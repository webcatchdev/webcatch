#!/usr/bin/env python3
"""
Webcatch 🔍 — Self-hosted webhook capture, replay, and analysis.

Run:
    uvicorn main:app --host 0.0.0.0 --port 9120 --reload

Environment:
    LOCAL_LLM_URL     → local model endpoint (default: http://127.0.0.1:8081/v1/chat/completions)
    LOCAL_LLM_MODEL   → model name (default: qwen-local)
    INSPECTOR_PORT    → port (default: 9120)
    WEBCATCH_PASSWORD → optional dashboard password
    STRIPE_SECRET_KEY → Stripe secret key for $12 license checkout
"""

import time
import csv
import io
import re
import ipaddress
import socket
import shlex
import aiohttp
import asyncio
import json
import os
import concurrent.futures
import hashlib
import hmac
import secrets as _secrets
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, parse_qs

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

import storage
import inspector
import schema_engine
import auth
import signature as sig_module
import license as lic_module

# Stripe config
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
if STRIPE_SECRET_KEY:
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
else:
    stripe = None

SUCCESS_URL = os.getenv("SUCCESS_URL", "https://webcatch.dev/success?session_id={CHECKOUT_SESSION_ID}")
CANCEL_URL = os.getenv("CANCEL_URL", "https://webcatch.dev/")

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.getenv("INSPECTOR_PORT", "9120"))
HOST = os.getenv("INSPECTOR_HOST", "0.0.0.0")
ENV = os.getenv("WEBCATCH_ENV", "development")

# Trial / licensing
TRIAL_WEBHOOK_LIMIT = int(os.getenv("TRIAL_WEBHOOK_LIMIT", "10"))

# Security constants
MAX_BODY_SIZE = int(os.getenv("MAX_BODY_SIZE", "1048576"))  # 1MB
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "30"))  # requests per window per IP
_ENDPOINT_ID_RE = re.compile(r"^[a-f0-9]{12}$")

# LLM analysis (disabled by default so high webhook volume doesn't overwhelm small local models)
ANALYZE_ON_CAPTURE = os.getenv("WEBCATCH_ANALYZE_ON_CAPTURE", "false").lower() in {"1", "true", "yes", "on"}
LLM_ANALYSIS_CONCURRENCY = int(os.getenv("WEBCATCH_LLM_CONCURRENCY", "1"))

# Transforms gated by default — exec() sandbox is not secure without RestrictedPython
ENABLE_TRANSFORMS = os.getenv("WEBCATCH_ENABLE_TRANSFORMS", "false").lower() in {"1", "true", "yes", "on"}

# In-memory rate limiter: {ip: [(timestamp, count), ...]}
_rate_limiter: dict[str, list] = defaultdict(list)
_rate_limiter_lock = asyncio.Lock()

# Login rate limiter: {ip: [(timestamp), ...]}
_login_rate_limiter: dict[str, list] = defaultdict(list)
_LOGIN_RATE_LIMIT_MAX = 5
_LOGIN_RATE_LIMIT_WINDOW = 900  # 15 minutes


def _clean_rate_limiter():
    """Remove expired rate limit entries."""
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW
    for ip in list(_rate_limiter.keys()):
        _rate_limiter[ip] = [t for t in _rate_limiter[ip] if t > cutoff]
        if not _rate_limiter[ip]:
            del _rate_limiter[ip]


async def _check_rate_limit(client_ip: str) -> bool:
    """Return True if request is allowed, False if rate limited."""
    async with _rate_limiter_lock:
        _clean_rate_limiter()
        now = time.time()
        entries = _rate_limiter[client_ip]
        if len(entries) >= RATE_LIMIT_MAX:
            return False
        entries.append(now)
        return True


def _validate_endpoint_id(endpoint_id: str) -> bool:
    return bool(_ENDPOINT_ID_RE.match(endpoint_id))


# SSRF protection — block private / loopback / link-local IPs
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("0.0.0.0/32"),
]
_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _is_safe_url(url: str) -> bool:
    """Return True if URL is safe for server-side requests (no SSRF)."""
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    # Block bare IPs and resolve hostnames
    try:
        ip = ipaddress.ip_address(hostname)
        if any(ip in net for net in _BLOCKED_NETWORKS):
            return False
    except ValueError:
        # It's a hostname — resolve and check
        try:
            resolved = socket.getaddrinfo(hostname, None)
            for _, _, _, _, addr in resolved:
                ip = ipaddress.ip_address(addr[0])
                if any(ip in net for net in _BLOCKED_NETWORKS):
                    return False
        except socket.gaierror:
            return False
    return True


def _check_login_rate_limit(client_ip: str) -> bool:
    """Return True if login attempt is allowed."""
    now = time.time()
    cutoff = now - _LOGIN_RATE_LIMIT_WINDOW
    entries = _login_rate_limiter[client_ip]
    entries[:] = [t for t in entries if t > cutoff]
    if len(entries) >= _LOGIN_RATE_LIMIT_MAX:
        return False
    entries.append(now)
    return True


# Auth fail-closed: refuse to start in production without a password
if ENV == "production" and not auth.AUTH_ENABLED:
    raise RuntimeError("CRITICAL: WEBCATCH_PASSWORD must be set in production")


# Track active endpoints in memory (endpoint_id → created_at)
active_endpoints: dict[str, str] = {}


class ConnectionManager:
    """WebSocket connection manager for real-time dashboard updates."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        # Snapshot list to avoid mutation during iteration
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()
analysis_semaphore = asyncio.Semaphore(LLM_ANALYSIS_CONCURRENCY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage.init_db()
    storage.init_endpoint_config()
    lic_module.init_db()
    for eid in storage.get_all_endpoint_ids():
        active_endpoints[eid] = {"created": True}
    yield


app = FastAPI(title="Webcatch", version="0.6.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")

# CORS — only allow same-origin in production; permissive in dev
origins = ["*"] if ENV == "development" else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self';"
    )
    return response


# ---------------------------------------------------------------------------
# Auth & license middleware
# ---------------------------------------------------------------------------

_AUTH_WHITELIST = {
    "/api/health",
    "/api/login",
    "/api/logout",
    "/api/checkout",
    "/api/license/validate",
    "/success",
    "/stripe/webhook",
    "/ws",
}

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — Webcatch</title>
<style>
body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 2.5rem; width: 100%; max-width: 360px; text-align: center; }
h1 { color: #58a6ff; margin-bottom: 0.5rem; font-size: 1.5rem; }
p { color: #8b949e; font-size: 0.9rem; margin-bottom: 1.5rem; }
input { width: 100%; background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 0.7rem; border-radius: 8px; font-size: 0.95rem; margin-bottom: 1rem; box-sizing: border-box; }
input:focus { outline: none; border-color: #58a6ff; }
button { width: 100%; background: #58a6ff; color: #000; border: none; padding: 0.7rem; border-radius: 8px; font-weight: 600; font-size: 0.95rem; cursor: pointer; }
button:hover { background: #79c0ff; }
#error { color: #f85149; font-size: 0.85rem; margin-top: 0.75rem; display: none; }
</style>
</head>
<body>
<div class="card">
<h1>🔒 Webcatch</h1>
<p>Enter your admin password to continue.</p>
<input type="password" id="pw" placeholder="Password" autofocus onkeydown="if(event.key==='Enter')doLogin()">
<button onclick="doLogin()">Sign In</button>
<div id="error"></div>
</div>
<script>
async function doLogin() {
    const pw = document.getElementById('pw').value;
    const err = document.getElementById('error');
    try {
        const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({password: pw}) });
        const data = await res.json();
        if (data.authenticated) { window.location.href = '/dashboard'; }
        else { err.textContent = data.message || 'Invalid password'; err.style.display = 'block'; }
    } catch (e) { err.textContent = 'Network error'; err.style.display = 'block'; }
}
</script>
</body>
</html>"""


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Always allow webhook capture endpoints
    if path.startswith("/wh/"):
        return await call_next(request)
    # Allow static files
    if path.startswith("/static/"):
        return await call_next(request)
    # Allow whitelisted routes
    if path in _AUTH_WHITELIST:
        return await call_next(request)
    # Check auth
    if not auth.is_authenticated(request):
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return HTMLResponse(LOGIN_HTML, status_code=401)
        return JSONResponse({"error": "Authentication required"}, status_code=401)
    # CSRF check for state-changing methods (POST/PUT/DELETE/PATCH)
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        try:
            auth.require_csrf(request)
        except HTTPException:
            return JSONResponse({"error": "CSRF token invalid"}, status_code=403)
    return await call_next(request)


# ---------------------------------------------------------------------------
# License helpers
# ---------------------------------------------------------------------------

def _is_licensed() -> bool:
    """Check if app has a valid license (caches briefly in memory)."""
    return lic_module.has_valid_license()


def _require_license():
    """Raise 402 if not licensed and trial exhausted."""
    if _is_licensed():
        return
    count = storage.get_capture_event_count()
    if count < TRIAL_WEBHOOK_LIMIT:
        return
    raise HTTPException(
        status_code=402,
        detail=f"Trial expired ({TRIAL_WEBHOOK_LIMIT} webhooks). Purchase a license at /api/checkout",
    )


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard_root():
    html_path = os.path.join(APP_DIR, "static", "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Webcatch</h1><p>Dashboard HTML not found.</p>"


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    html_path = os.path.join(APP_DIR, "static", "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Webcatch</h1><p>Dashboard HTML not found.</p>"


# ---------------------------------------------------------------------------
# API: Endpoints management
# ---------------------------------------------------------------------------

@app.post("/api/endpoints")
async def create_endpoint():
    _require_license()
    endpoint_id = storage.create_endpoint()
    active_endpoints[endpoint_id] = {"created": True}
    return {
        "endpoint_id": endpoint_id,
        "webhook_url": f"http://{HOST}:{PORT}/wh/{endpoint_id}",
        "dashboard_url": f"http://{HOST}:{PORT}/#/endpoint/{endpoint_id}",
    }


@app.get("/api/endpoints")
async def list_endpoints():
    endpoints = []
    for eid in list(active_endpoints.keys()):
        ep = storage.get_endpoint(eid)
        endpoints.append({
            "endpoint_id": eid,
            "enabled": ep.get("enabled", True),
            "webhook_url": f"http://{HOST}:{PORT}/wh/{eid}",
        })
    return {"endpoints": endpoints}


@app.post("/api/endpoints/{endpoint_id}/toggle")
async def toggle_endpoint(endpoint_id: str):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    ep = storage.get_endpoint(endpoint_id)
    new_state = not ep.get("enabled", True)
    storage.set_endpoint_enabled(endpoint_id, new_state)
    return {"endpoint_id": endpoint_id, "enabled": new_state}


# ---------------------------------------------------------------------------
# API: Stats
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def get_stats():
    stats = storage.get_stats()
    stats["licensed"] = _is_licensed()
    stats["trial_limit"] = TRIAL_WEBHOOK_LIMIT
    stats["trial_used"] = storage.get_capture_event_count()
    return stats


# ---------------------------------------------------------------------------
# API: Webhook capture (the core magic)
# ---------------------------------------------------------------------------

@app.api_route("/wh/{endpoint_id}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def capture_webhook(endpoint_id: str, request: Request):
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")

    ep = storage.get_endpoint(endpoint_id)
    if not ep.get("enabled", True):
        return JSONResponse(
            content={"status": "disabled", "message": "This endpoint is currently disabled."},
            status_code=503,
        )

    if endpoint_id not in active_endpoints:
        active_endpoints[endpoint_id] = {"created": True}

    # Rate limit check
    client_ip = request.client.host if request.client else "unknown"
    if not await _check_rate_limit(client_ip):
        return JSONResponse(
            content={"status": "rate_limited", "message": "Too many requests. Try again later."},
            status_code=429,
        )

    # Body size check
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        return JSONResponse(
            content={"status": "payload_too_large", "message": f"Max body size is {MAX_BODY_SIZE} bytes"},
            status_code=413,
        )

    start_time = time.time()

    # Read body
    body: Optional[bytes] = None
    try:
        body = await request.body()
        if len(body) > MAX_BODY_SIZE:
            return JSONResponse(
                content={"status": "payload_too_large", "message": f"Max body size is {MAX_BODY_SIZE} bytes"},
                status_code=413,
            )
        if len(body) == 0:
            body = None
    except Exception:
        body = None

    # Extract headers
    headers = dict(request.headers)

    # Query params
    query_params = dict(request.query_params)

    # Filter rules check
    config = storage.get_endpoint_config(endpoint_id)
    if config:
        rules = config.get("filter_rules") or {}
        if rules:
            allowed_methods = rules.get("allowed_methods")
            if allowed_methods and request.method not in allowed_methods:
                return JSONResponse(
                    content={"status": "filtered", "reason": "method_not_allowed"},
                    status_code=202,
                )
            required_header = rules.get("required_header")
            if required_header:
                key, val = required_header.split(":", 1) if ":" in required_header else (required_header, None)
                if key not in headers:
                    return JSONResponse(content={"status": "filtered", "reason": "missing_header"}, status_code=202)
                if val and headers.get(key) != val:
                    return JSONResponse(content={"status": "filtered", "reason": "header_mismatch"}, status_code=202)
            body_contains = rules.get("body_contains")
            if body_contains:
                body_text = body.decode("utf-8", errors="replace") if body else ""
                if body_contains not in body_text:
                    return JSONResponse(content={"status": "filtered", "reason": "body_no_match"}, status_code=202)

    # Trial check for capture
    if not _is_licensed():
        count = storage.get_capture_event_count()
        if count >= TRIAL_WEBHOOK_LIMIT:
            return JSONResponse(
                content={
                    "status": "trial_expired",
                    "message": f"Trial limit reached ({TRIAL_WEBHOOK_LIMIT} webhooks). Purchase at /api/checkout",
                    "checkout_url": "/api/checkout",
                },
                status_code=402,
            )

    # Store it
    latency_ms = (time.time() - start_time) * 1000
    webhook_id = storage.store_webhook(
        endpoint_id=endpoint_id,
        method=request.method,
        url=str(request.url),
        headers=headers,
        body=body,
        query_params=query_params,
        client_ip=client_ip,
        latency_ms=round(latency_ms, 2),
    )

    # Retention cleanup
    if config and config.get("retention_count"):
        storage.apply_retention(endpoint_id, config["retention_count"])

    # Optional fire-and-forget LLM analysis with timing. Disabled by default so
    # high webhook volume does not overwhelm a small local model.
    body_text = body.decode("utf-8", errors="replace") if body else None
    if ANALYZE_ON_CAPTURE:
        asyncio.create_task(
            _analyze_and_store(webhook_id, request.method, str(request.url), headers, body_text, query_params)
        )

    # Fire-and-forget schema inference + validation
    if body_text:
        asyncio.create_task(
            _infer_and_validate_schema(endpoint_id, webhook_id, body_text)
        )

    # Fire-and-forget forwarding if configured
    if config and config.get("forward_url"):
        asyncio.create_task(
            _forward_webhook(webhook_id, request.method, config["forward_url"], headers, body, query_params, transform_script=config.get("transform_script"))
        )

    # Broadcast to all connected WebSocket clients
    webhook_data = {
        "type": "new_webhook",
        "webhook": {
            "id": webhook_id,
            "endpoint_id": endpoint_id,
            "method": request.method,
            "url": str(request.url),
            "headers": headers,
            "body": body_text,
            "query_params": query_params,
            "client_ip": client_ip,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "analyzed": 0,
            "analysis": None,
            "latency_ms": round(latency_ms, 2),
            "validation_errors": None,
        },
    }
    asyncio.create_task(manager.broadcast(webhook_data))

    # Check for custom response config
    if config:
        resp_headers = config.get("response_headers") or {}
        resp_body = config.get("response_body")
        status_code = config.get("status_code", 200)
        return JSONResponse(
            content=resp_body if resp_body else {"status": "captured", "webhook_id": webhook_id},
            status_code=status_code,
            headers=resp_headers,
        )

    return JSONResponse(
        content={"status": "captured", "webhook_id": webhook_id},
        status_code=200,
    )


async def _analyze_and_store(
    webhook_id: str,
    method: str,
    url: str,
    headers: dict,
    body: Optional[str],
    query_params: dict,
) -> None:
    """Background task: run local LLM analysis and store result."""
    start = time.time()
    try:
        async with analysis_semaphore:
            analysis = await inspector.analyze_webhook(method, url, headers, body, query_params)
        elapsed_ms = (time.time() - start) * 1000
        storage.update_analysis(webhook_id, analysis, analysis_time_ms=round(elapsed_ms, 2))
        await manager.broadcast({
            "type": "analysis_update",
            "webhook_id": webhook_id,
            "analysis": analysis,
            "analysis_time_ms": round(elapsed_ms, 2),
        })
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000
        storage.update_analysis(webhook_id, f"Analysis failed: {e}", analysis_time_ms=round(elapsed_ms, 2))
        await manager.broadcast({
            "type": "analysis_update",
            "webhook_id": webhook_id,
            "analysis": f"Analysis failed: {e}",
            "analysis_time_ms": round(elapsed_ms, 2),
        })


async def _infer_and_validate_schema(endpoint_id: str, webhook_id: str, body_text: str) -> None:
    """Background task: infer schema from all webhooks for endpoint, validate this webhook."""
    try:
        existing = storage.get_schema(endpoint_id)
        schema = None
        if existing:
            schema = json.loads(existing["schema_json"])

        validation_errors = []
        if schema:
            validation_errors = schema_engine.validate_body(body_text, schema)
            if validation_errors:
                storage.update_validation_errors(webhook_id, validation_errors)
                await manager.broadcast({
                    "type": "validation_update",
                    "webhook_id": webhook_id,
                    "validation_errors": validation_errors,
                })

        recent = storage.get_webhooks(endpoint_id, limit=200)
        bodies = [wh["body"] for wh in recent if wh.get("body")]
        new_schema = schema_engine.infer_schema(bodies)
        if new_schema:
            storage.set_schema(endpoint_id, new_schema, len(bodies))
    except Exception:
        pass


# Thread pool for running user transform scripts (gated by ENABLE_TRANSFORMS)
_transform_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="transform") if ENABLE_TRANSFORMS else None


def _run_transform_sync(script: str, method: str, url: str, headers: dict, body: Optional[str], query: dict) -> tuple:
    """Run a user transform script in a restricted sandbox. Returns (method, url, headers, body, query, error)."""
    if not ENABLE_TRANSFORMS:
        return method, url, headers, body, query, "Transforms are disabled"
    if not script or not script.strip():
        return method, url, headers, body, query, None

    # Restricted builtins — NO type, isinstance, hasattr, getattr to prevent sandbox escape
    safe_globals = {
        "__builtins__": {
            "len": len, "str": str, "int": int, "float": float,
            "bool": bool, "dict": dict, "list": list, "tuple": tuple, "set": set,
            "json": __import__("json"),
            "re": __import__("re"),
            "datetime": __import__("datetime"),
            "print": lambda *a, **k: None,
            "enumerate": enumerate, "range": range, "zip": zip, "map": map, "filter": filter,
            "sum": sum, "min": min, "max": max, "abs": abs, "round": round,
        }
    }

    locals_dict = {
        "method": method,
        "url": url,
        "headers": dict(headers),
        "body": body,
        "query": dict(query),
    }

    try:
        exec(script, safe_globals, locals_dict)
        return (
            locals_dict.get("method", method),
            locals_dict.get("url", url),
            locals_dict.get("headers", headers),
            locals_dict.get("body", body),
            locals_dict.get("query", query),
            None,
        )
    except Exception as e:
        return method, url, headers, body, query, str(e)


async def _forward_webhook(
    webhook_id: str,
    method: str,
    forward_url: str,
    headers: dict,
    body: Optional[bytes],
    query_params: dict,
    transform_script: Optional[str] = None,
) -> None:
    """Forward captured webhook to another URL with retry and optional transform."""
    max_retries = 3
    base_delay = 1.0
    fwd_timeout = aiohttp.ClientTimeout(total=30)

    body_text = body.decode("utf-8", errors="replace") if body else None

    if transform_script and transform_script.strip():
        if not ENABLE_TRANSFORMS:
            storage.update_forward_status(webhook_id, 0, "Transforms are disabled")
            await manager.broadcast({
                "type": "forward_update",
                "webhook_id": webhook_id,
                "forward_status": 0,
            })
            return
        loop = asyncio.get_event_loop()
        try:
            t_method, t_url, t_headers, t_body, t_query, t_error = await asyncio.wait_for(
                loop.run_in_executor(
                    _transform_executor,
                    _run_transform_sync,
                    transform_script,
                    method,
                    forward_url,
                    dict(headers),
                    body_text,
                    dict(query_params),
                ),
                timeout=5.0,
            )
            if t_error:
                storage.update_forward_status(webhook_id, 0, f"Transform error: {t_error}")
                await manager.broadcast({
                    "type": "forward_update",
                    "webhook_id": webhook_id,
                    "forward_status": 0,
                })
                return
            method = t_method
            forward_url = t_url
            headers = t_headers
            body_text = t_body
            query_params = t_query
            body = t_body.encode("utf-8") if t_body else None
        except asyncio.TimeoutError:
            storage.update_forward_status(webhook_id, 0, "Transform error: script timed out after 5s")
            await manager.broadcast({
                "type": "forward_update",
                "webhook_id": webhook_id,
                "forward_status": 0,
            })
            return
        except Exception as e:
            storage.update_forward_status(webhook_id, 0, f"Transform error: {e}")
            await manager.broadcast({
                "type": "forward_update",
                "webhook_id": webhook_id,
                "forward_status": 0,
            })
            return

    for attempt in range(1, max_retries + 1):
        try:
            target = forward_url
            if not _is_safe_url(target):
                storage.update_forward_status(webhook_id, 0, "Forward URL blocked for security")
                await manager.broadcast({
                    "type": "forward_update",
                    "webhook_id": webhook_id,
                    "forward_status": 0,
                })
                return
            if query_params:
                separator = "&" if "?" in forward_url else "?"
                target += separator + "&".join(f"{k}={v}" for k, v in query_params.items())
            fwd_headers = {k: v for k, v in headers.items() if k.lower() not in ["host", "content-length", "transfer-encoding", "connection"]}
            fwd_body = body
            async with aiohttp.ClientSession(timeout=fwd_timeout) as session:
                async with session.request(method, target, headers=fwd_headers, data=fwd_body) as resp:
                    resp_text = await resp.text()
                    storage.update_forward_status(webhook_id, resp.status, resp_text[:2000])
                    await manager.broadcast({
                        "type": "forward_update",
                        "webhook_id": webhook_id,
                        "forward_status": resp.status,
                    })
                    return
        except Exception as e:
            if attempt < max_retries:
                await asyncio.sleep(base_delay * (2 ** (attempt - 1)))
                continue
            storage.update_forward_status(webhook_id, 0, str(e)[:500])
            await manager.broadcast({
                "type": "forward_update",
                "webhook_id": webhook_id,
                "forward_status": 0,
            })


# ---------------------------------------------------------------------------
# API: Export webhooks
# ---------------------------------------------------------------------------

def _webhook_to_postman_item(wh: dict) -> dict:
    """Convert a single webhook to a Postman Collection v2.1 item."""
    headers = wh.get("headers") or {}
    query_params = wh.get("query_params") or {}
    body = wh.get("body")
    method = wh.get("method", "GET")
    url = wh.get("url", "")

    url_obj = {"raw": url, "host": [url]}
    try:
        parsed = urlparse(url)
        url_obj = {
            "raw": url,
            "protocol": parsed.scheme,
            "host": [parsed.hostname] if parsed.hostname else [""],
            "port": parsed.port,
            "path": [p for p in parsed.path.split("/") if p],
            "query": [{"key": k, "value": v} for k, v in query_params.items()],
        }
    except Exception:
        pass

    header_list = []
    for k, v in headers.items():
        if k.lower() in ["host", "content-length", "transfer-encoding", "connection"]:
            continue
        header_list.append({"key": k, "value": str(v)})

    body_obj = None
    if body:
        content_type = headers.get("content-type", headers.get("Content-Type", ""))
        if "json" in content_type.lower():
            try:
                body_obj = {"mode": "raw", "raw": body, "options": {"raw": {"language": "json"}}}
            except Exception:
                body_obj = {"mode": "raw", "raw": body}
        else:
            body_obj = {"mode": "raw", "raw": body}

    item = {
        "name": f"{method} {url[:80]}",
        "request": {
            "method": method,
            "header": header_list,
            "url": url_obj,
            "description": f"Captured at {wh.get('received_at', '')} from {wh.get('client_ip', 'unknown')}",
        },
        "response": [],
    }
    if body_obj:
        item["request"]["body"] = body_obj
    return item


def _webhook_to_curl(wh: dict) -> str:
    """Convert a single webhook to a cURL command."""
    headers = wh.get("headers") or {}
    body = wh.get("body")
    method = wh.get("method", "GET")
    url = wh.get("url", "")

    cmd = f'curl -X {shlex.quote(method)} {shlex.quote(url)}'
    for k, v in headers.items():
        if k.lower() in ["host", "content-length", "transfer-encoding", "connection"]:
            continue
        cmd += f' \\n  -H {shlex.quote(f"{k}: {v}")}'
    if body:
        cmd += f" \\n  -d {shlex.quote(body)}"
    return cmd


@app.get("/api/webhooks/export")
async def export_webhooks(format: str = "json", endpoint_id: Optional[str] = None):
    _require_license()
    if endpoint_id and not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")

    webhooks = storage.get_webhooks(endpoint_id=endpoint_id, limit=1000)
    for wh in webhooks:
        wh["headers"] = json.loads(wh["headers"]) if wh["headers"] else {}
        wh["query_params"] = json.loads(wh["query_params"]) if wh["query_params"] else {}

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "endpoint_id", "method", "url", "received_at", "client_ip", "latency_ms", "analysis_time_ms", "body"])
        for wh in webhooks:
            writer.writerow([
                wh["id"], wh["endpoint_id"], wh["method"], wh["url"],
                wh["received_at"], wh.get("client_ip", ""),
                wh.get("latency_ms", ""), wh.get("analysis_time_ms", ""),
                wh["body"] or "",
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=webcatch-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"},
        )

    if format == "postman":
        collection = {
            "info": {
                "_postman_id": f"webcatch-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "name": f"Webcatch Export — {endpoint_id or 'All Endpoints'}",
                "description": f"Exported from Webcatch on {datetime.now(timezone.utc).isoformat()}",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [_webhook_to_postman_item(wh) for wh in webhooks],
        }
        return StreamingResponse(
            io.BytesIO(json.dumps(collection, indent=2).encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=webcatch-{endpoint_id or 'all'}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.postman_collection.json"},
        )

    if format == "curl":
        commands = [_webhook_to_curl(wh) for wh in webhooks]
        output = "\n\n# ----\n\n".join(commands)
        return StreamingResponse(
            io.BytesIO(output.encode("utf-8")),
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=webcatch-{endpoint_id or 'all'}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.sh"},
        )

    return JSONResponse(content={"webhooks": webhooks})


# ---------------------------------------------------------------------------
# API: Webhook retrieval
# ---------------------------------------------------------------------------

@app.get("/api/webhooks")
async def list_webhooks(endpoint_id: Optional[str] = None, limit: int = 100):
    if endpoint_id and not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    limit = min(max(limit, 1), 1000)

    webhooks = storage.get_webhooks(endpoint_id=endpoint_id, limit=limit)
    for wh in webhooks:
        wh["headers"] = json.loads(wh["headers"]) if wh["headers"] else {}
        wh["query_params"] = json.loads(wh["query_params"]) if wh["query_params"] else {}
    return {"webhooks": webhooks}


@app.get("/api/webhooks/{webhook_id}")
async def get_webhook(webhook_id: str):
    wh = storage.get_webhook(webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    wh["headers"] = json.loads(wh["headers"]) if wh["headers"] else {}
    wh["query_params"] = json.loads(wh["query_params"]) if wh["query_params"] else {}
    return wh


@app.post("/api/webhooks/{webhook_id}/analyze")
async def analyze_webhook_now(webhook_id: str):
    wh = storage.get_webhook(webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    headers = json.loads(wh["headers"]) if wh["headers"] else {}
    query_params = json.loads(wh["query_params"]) if wh["query_params"] else {}
    await _analyze_and_store(webhook_id, wh["method"], wh["url"], headers, wh["body"], query_params)
    updated = storage.get_webhook(webhook_id)
    return {
        "webhook_id": webhook_id,
        "analysis": updated.get("analysis") if updated else None,
        "analysis_time_ms": updated.get("analysis_time_ms") if updated else None,
    }


@app.get("/api/webhooks/{webhook_id}/export")
async def export_single_webhook(webhook_id: str, format: str = "curl"):
    _require_license()
    wh = storage.get_webhook(webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    wh["headers"] = json.loads(wh["headers"]) if wh["headers"] else {}
    wh["query_params"] = json.loads(wh["query_params"]) if wh["query_params"] else {}

    if format == "postman":
        collection = {
            "info": {
                "_postman_id": f"webcatch-single-{webhook_id}",
                "name": f"Webcatch Single — {wh['method']} {wh['url'][:60]}",
                "description": f"Exported from Webcatch on {datetime.now(timezone.utc).isoformat()}",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [_webhook_to_postman_item(wh)],
        }
        return StreamingResponse(
            io.BytesIO(json.dumps(collection, indent=2).encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=webcatch-{webhook_id}.postman_collection.json"},
        )

    if format == "curl":
        cmd = _webhook_to_curl(wh)
        return StreamingResponse(
            io.BytesIO(cmd.encode("utf-8")),
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=webcatch-{webhook_id}.sh"},
        )

    raise HTTPException(status_code=400, detail="Format must be 'postman' or 'curl'")


@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    _require_license()
    storage.delete_webhook(webhook_id)
    return {"status": "deleted"}


@app.delete("/api/endpoints/{endpoint_id}/webhooks")
async def clear_endpoint(endpoint_id: str):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    storage.delete_all_for_endpoint(endpoint_id)
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# API: Endpoint response configuration
# ---------------------------------------------------------------------------

@app.get("/api/endpoints/{endpoint_id}/config")
async def get_endpoint_config(endpoint_id: str):
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    cfg = storage.get_endpoint_config(endpoint_id)
    if not cfg:
        return {"endpoint_id": endpoint_id, "status_code": 200, "response_headers": {}, "response_body": None, "forward_url": None, "retention_count": 0, "filter_rules": {}, "transform_script": None}
    return cfg


@app.put("/api/endpoints/{endpoint_id}/config")
async def set_endpoint_config(endpoint_id: str, request: Request):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    data = await request.json()
    storage.set_endpoint_config(
        endpoint_id=endpoint_id,
        status_code=data.get("status_code", 200),
        response_headers=data.get("response_headers", {}),
        response_body=data.get("response_body"),
        forward_url=data.get("forward_url"),
        retention_count=data.get("retention_count"),
        filter_rules=data.get("filter_rules"),
        transform_script=data.get("transform_script"),
    )
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# API: Schema inference
# ---------------------------------------------------------------------------

@app.get("/api/endpoints/{endpoint_id}/schema")
async def get_endpoint_schema(endpoint_id: str):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    row = storage.get_schema(endpoint_id)
    if not row:
        raise HTTPException(status_code=404, detail="No schema inferred yet. Capture some JSON webhooks first.")
    return {
        "endpoint_id": endpoint_id,
        "schema": json.loads(row["schema_json"]),
        "inferred_at": row["inferred_at"],
        "webhook_count": row["webhook_count"],
    }


@app.post("/api/endpoints/{endpoint_id}/schema/infer")
async def infer_endpoint_schema(endpoint_id: str):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    recent = storage.get_webhooks(endpoint_id, limit=500)
    bodies = [wh["body"] for wh in recent if wh.get("body")]
    schema = schema_engine.infer_schema(bodies)
    if not schema:
        raise HTTPException(status_code=400, detail="No valid JSON bodies found to infer schema from.")
    storage.set_schema(endpoint_id, schema, len(bodies))
    return {
        "endpoint_id": endpoint_id,
        "schema": schema,
        "webhook_count": len(bodies),
    }


@app.delete("/api/endpoints/{endpoint_id}/schema")
async def delete_endpoint_schema(endpoint_id: str):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    storage.delete_schema(endpoint_id)
    return {"status": "deleted"}


@app.get("/api/endpoints/{endpoint_id}/schema/openapi")
async def export_schema_openapi(endpoint_id: str):
    _require_license()
    if not _validate_endpoint_id(endpoint_id):
        raise HTTPException(status_code=400, detail="Invalid endpoint ID")
    row = storage.get_schema(endpoint_id)
    if not row:
        raise HTTPException(status_code=404, detail="No schema inferred yet.")
    schema = json.loads(row["schema_json"])
    return schema_engine.to_openapi(schema, title=f"Webhook {endpoint_id}")


# ---------------------------------------------------------------------------
# API: Replay webhook
# ---------------------------------------------------------------------------

@app.post("/api/webhooks/{webhook_id}/replay")
async def replay_webhook(webhook_id: str, request: Request):
    _require_license()
    wh = storage.get_webhook(webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    data = await request.json() if request.headers.get("content-length") else {}
    target_url = data.get("url") if data else None

    headers = json.loads(wh["headers"]) if wh["headers"] else {}
    body = wh["body"]
    method = wh["method"]
    url = target_url or wh["url"]

    if method not in _ALLOWED_METHODS:
        raise HTTPException(status_code=400, detail="Method not allowed for replay")
    if not _is_safe_url(url):
        raise HTTPException(status_code=400, detail="Target URL not allowed")

    for h in ["host", "content-length", "transfer-encoding", "connection"]:
        headers.pop(h, None)
        headers.pop(h.title(), None)

    try:
        replay_timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=replay_timeout) as session:
            async with session.request(method, url, headers=headers, data=body.encode("utf-8") if body else None, allow_redirects=False) as resp:
                resp_body = await resp.text()
                return {
                    "status": "replayed",
                    "original_webhook_id": webhook_id,
                    "target_url": url,
                    "response_status": resp.status,
                    "response_body": resp_body[:2000],
                }
    except Exception:
        raise HTTPException(status_code=502, detail="Replay failed")


@app.post("/api/bulk-replay")
async def bulk_replay(request: Request):
    _require_license()
    data = await request.json()
    webhook_ids = data.get("webhook_ids", [])
    target_url = data.get("url")
    if not webhook_ids:
        raise HTTPException(status_code=400, detail="No webhook_ids provided")

    results = []
    replay_timeout = aiohttp.ClientTimeout(total=30)
    for wh_id in webhook_ids:
        wh = storage.get_webhook(wh_id)
        if not wh:
            results.append({"webhook_id": wh_id, "status": "not_found"})
            continue
        headers = json.loads(wh["headers"]) if wh["headers"] else {}
        body = wh["body"]
        method = wh["method"]
        url = target_url or wh["url"]
        if method not in _ALLOWED_METHODS:
            results.append({"webhook_id": wh_id, "status": "error", "error": "Method not allowed"})
            continue
        if not _is_safe_url(url):
            results.append({"webhook_id": wh_id, "status": "error", "error": "Target URL not allowed"})
            continue
        for h in ["host", "content-length", "transfer-encoding", "connection"]:
            headers.pop(h, None)
            headers.pop(h.title(), None)
        try:
            async with aiohttp.ClientSession(timeout=replay_timeout) as session:
                async with session.request(method, url, headers=headers, data=body.encode("utf-8") if body else None, allow_redirects=False) as resp:
                    resp_body = await resp.text()
                    results.append({
                        "webhook_id": wh_id,
                        "status": "replayed",
                        "target_url": url,
                        "response_status": resp.status,
                    })
        except Exception:
            results.append({"webhook_id": wh_id, "status": "error", "error": "Replay failed"})

    return {"replayed": len([r for r in results if r["status"] == "replayed"]), "results": results}


# ---------------------------------------------------------------------------
# API: Test webhook generator
# ---------------------------------------------------------------------------

@app.post("/api/test-webhook")
async def test_webhook(request: Request):
    _require_license()
    data = await request.json()
    target_url = data.get("url")
    method = data.get("method", "POST")
    headers = data.get("headers", {})
    body = data.get("body", "")

    if not target_url:
        raise HTTPException(status_code=400, detail="url is required")
    if method not in _ALLOWED_METHODS:
        raise HTTPException(status_code=400, detail="Method not allowed")
    if not _is_safe_url(target_url):
        raise HTTPException(status_code=400, detail="Target URL not allowed")

    try:
        req_body = None
        if body:
            if isinstance(body, dict):
                req_body = json.dumps(body).encode('utf-8')
                if not headers.get('Content-Type'):
                    headers['Content-Type'] = 'application/json'
            else:
                req_body = body.encode('utf-8')
        test_timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=test_timeout) as session:
            async with session.request(method, target_url, headers=headers, data=req_body, allow_redirects=False) as resp:
                resp_text = await resp.text()
                return {
                    "status": "sent",
                    "target_url": target_url,
                    "response_status": resp.status,
                    "response_body": resp_text[:2000],
                }
    except Exception:
        raise HTTPException(status_code=502, detail="Request failed")


# ---------------------------------------------------------------------------
# API: Diff two webhooks
# ---------------------------------------------------------------------------

@app.get("/api/webhooks/{webhook_a}/diff/{webhook_b}")
async def diff_webhooks(webhook_a: str, webhook_b: str):
    _require_license()
    a = storage.get_webhook(webhook_a)
    b = storage.get_webhook(webhook_b)
    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both webhooks not found")

    def normalize(wh):
        return {
            "method": wh["method"],
            "url": wh["url"],
            "headers": json.loads(wh["headers"]) if wh["headers"] else {},
            "body": wh["body"],
            "query_params": json.loads(wh["query_params"]) if wh["query_params"] else {},
        }

    na = normalize(a)
    nb = normalize(b)

    diff = {}
    all_keys = set(na.keys()) | set(nb.keys())
    for key in all_keys:
        if na.get(key) != nb.get(key):
            diff[key] = {"a": na.get(key), "b": nb.get(key)}

    return {
        "webhook_a": webhook_a,
        "webhook_b": webhook_b,
        "diff": diff,
        "identical": len(diff) == 0,
    }


# ---------------------------------------------------------------------------
# API: Signature verification
# ---------------------------------------------------------------------------

@app.post("/api/webhooks/{webhook_id}/verify")
async def verify_webhook_sig(webhook_id: str, request: Request):
    wh = storage.get_webhook(webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    data = await request.json()
    secrets = data.get("secrets", {})
    body = (wh["body"] or "").encode("utf-8")
    headers = json.loads(wh["headers"]) if wh["headers"] else {}

    result = sig_module.verify_webhook(headers, body, secrets)
    return result


# ---------------------------------------------------------------------------
# WebSocket: Real-time updates
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if auth.AUTH_ENABLED:
        cookie = websocket.cookies.get(auth._COOKIE_NAME, "")
        if not cookie or not auth._verify_cookie_value(cookie):
            await websocket.close(code=1008, reason="Authentication required")
            return
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Health / Info
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    db_ok = True
    try:
        db_ok = storage.health_check()
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "db_error",
        "version": "0.6.0",
        "licensed": _is_licensed(),
        "trial_limit": TRIAL_WEBHOOK_LIMIT,
        "trial_used": storage.get_capture_event_count(),
    }


@app.post("/api/login")
async def api_login(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_login_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    data = await request.json()
    password = data.get("password", "")
    return auth.login_response(password)


@app.post("/api/logout")
async def api_logout():
    return auth.logout_response()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=True)

# ---------------------------------------------------------------------------
# Stripe Checkout & License (single $12 tier)
# ---------------------------------------------------------------------------

@app.post("/api/checkout")
async def create_checkout():
    if not stripe or not STRIPE_SECRET_KEY:
        return JSONResponse({"error": "Stripe not configured"}, status_code=500)
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": "Webcatch License", "description": "Lifetime self-hosted license"},
                    "unit_amount": 1200,
                },
                "quantity": 1,
            }],
            mode="payment",
            success_url=SUCCESS_URL,
            cancel_url=CANCEL_URL,
        )
        return {"url": session.url}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/success", response_class=HTMLResponse)
async def checkout_success(session_id: str = None):
    if not session_id or not stripe:
        return "<h1>Missing session</h1><p>Please contact support.</p>"
    try:
        sess = stripe.checkout.Session.retrieve(session_id)
        if sess.payment_status != "paid":
            return "<h1>Payment not completed</h1><p>If you believe this is an error, contact support.</p>"

        lic_key = lic_module.create_license(
            email=sess.customer_details.email if sess.customer_details else None,
            stripe_session_id=session_id
        )

        return f"""<!DOCTYPE html>
<html><head><title>Webcatch — Success</title>
<style>
body {{ background: #0d1117; color: #c9d1d9; font-family: sans-serif; text-align: center; padding: 80px 20px; }}
h1 {{ color: #58a6ff; }} .key {{ background: #161b22; border: 1px solid #30363d; padding: 16px 24px; border-radius: 8px;
font-family: monospace; font-size: 1.1rem; color: #3fb950; margin: 20px auto; display: inline-block; }}
.btn {{ background: #58a6ff; color: #0d1117; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block; margin-top: 20px; }}
</style></head><body>
<h1>🎉 Welcome to Webcatch!</h1>
<p>Your payment was successful. Here is your license key:</p>
<div class="key">{lic_key}</div>
<p>Copy this key and paste it into your self-hosted Webcatch app under Settings → License.</p>
<a href="/dashboard" class="btn">Open Webcatch</a>
</body></html>"""
    except Exception as e:
        return f"<h1>Error</h1><p>{str(e)}</p>"


@app.post("/api/license/validate")
async def validate_license(request: Request):
    data = await request.json()
    key = data.get("key", "").strip()
    if not key:
        return {"valid": False, "error": "No key provided"}
    result = lic_module.validate_and_activate(key, request.client.host if request.client else "unknown")
    return result


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not stripe or not STRIPE_WEBHOOK_SECRET:
        return JSONResponse({"error": "Webhook secret not configured"}, status_code=500)
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return JSONResponse({"error": "Invalid payload"}, status_code=400)
    except stripe.error.SignatureVerificationError:
        return JSONResponse({"error": "Invalid signature"}, status_code=400)

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        if session.payment_status == "paid":
            lic_module.create_license(
                email=session.customer_details.email if session.customer_details else None,
                stripe_session_id=session.id
            )
    return {"status": "ok"}
