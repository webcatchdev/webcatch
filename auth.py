"""
Simple cookie-based auth for Webcatch.
Set WEBCATCH_PASSWORD env var to enable. If not set, everything is open.
"""

import os
import hmac
import hashlib
import secrets
import time
from typing import Optional
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

AUTH_PASSWORD = os.getenv("WEBCATCH_PASSWORD", "").strip()
AUTH_ENABLED = bool(AUTH_PASSWORD)
_COOKIE_NAME = "webcatch_session"
_COOKIE_MAX_AGE = 86400 * 30  # 30 days
_CSRF_COOKIE = "webcatch_csrf"


def _sign(value: str) -> str:
    return hmac.new(AUTH_PASSWORD.encode(), value.encode(), hashlib.sha256).hexdigest()


def _make_cookie_value() -> str:
    ts = str(int(time.time()))
    sig = _sign(ts)
    return f"{ts}:{sig}"


def _verify_cookie_value(cookie: str) -> bool:
    try:
        ts, sig = cookie.split(":", 1)
        expected = _sign(ts)
        if not hmac.compare_digest(sig, expected):
            return False
        age = int(time.time()) - int(ts)
        return age <= _COOKIE_MAX_AGE
    except Exception:
        return False


def generate_csrf_token() -> str:
    """Generate a random CSRF token."""
    return secrets.token_urlsafe(32)


def _verify_csrf(request: Request) -> bool:
    """Verify CSRF token from header against cookie."""
    cookie = request.cookies.get(_CSRF_COOKIE, "")
    header = request.headers.get("x-csrf-token", "")
    if not cookie or not header:
        return False
    return hmac.compare_digest(cookie, header)


def require_auth(request: Request):
    if not AUTH_ENABLED:
        return True
    cookie = request.cookies.get(_COOKIE_NAME, "")
    if cookie and _verify_cookie_value(cookie):
        return True
    raise HTTPException(status_code=401, detail="Authentication required")


def is_authenticated(request: Request) -> bool:
    if not AUTH_ENABLED:
        return True
    cookie = request.cookies.get(_COOKIE_NAME, "")
    return bool(cookie and _verify_cookie_value(cookie))


def require_csrf(request: Request):
    """Raise 403 if CSRF token is missing or mismatched."""
    if not AUTH_ENABLED:
        return True
    if _verify_csrf(request):
        return True
    raise HTTPException(status_code=403, detail="CSRF token invalid")


def _is_secure() -> bool:
    """Return True if we should set secure cookie flags."""
    return os.getenv("WEBCATCH_ENV", "development").lower() in ("production", "staging")


def login_response(password: str) -> Optional[JSONResponse]:
    if not AUTH_ENABLED:
        return JSONResponse({"status": "ok", "message": "Auth not configured"})
    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(password.encode(), AUTH_PASSWORD.encode()):
        return JSONResponse({"status": "error", "message": "Invalid password"}, status_code=403)
    
    # Generate ONE CSRF token, use it for both JSON body and cookie
    csrf = generate_csrf_token()
    resp = JSONResponse({"status": "ok", "authenticated": True, "csrf_token": csrf})
    secure = _is_secure()
    resp.set_cookie(
        _COOKIE_NAME,
        _make_cookie_value(),
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="strict" if secure else "lax",
        secure=secure,
    )
    resp.set_cookie(
        _CSRF_COOKIE,
        csrf,
        max_age=_COOKIE_MAX_AGE,
        httponly=False,
        samesite="strict" if secure else "lax",
        secure=secure,
    )
    return resp


def logout_response() -> JSONResponse:
    resp = JSONResponse({"status": "ok", "authenticated": False})
    resp.delete_cookie(_COOKIE_NAME)
    resp.delete_cookie(_CSRF_COOKIE)
    return resp
