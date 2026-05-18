"""
Webhook storage layer — SQLite-backed, zero-config.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "webhooks.db"


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_conn()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.OperationalError:
        pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY,
            endpoint_id TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            headers TEXT NOT NULL,
            body TEXT,
            query_params TEXT,
            client_ip TEXT,
            received_at TEXT NOT NULL,
            analyzed INTEGER DEFAULT 0,
            analysis TEXT,
            forward_status INTEGER,
            forward_response TEXT,
            forwarded_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_endpoint ON webhooks(endpoint_id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_received ON webhooks(received_at DESC)
        """
    )
    # Capture counter for trial tracking — never decrements on delete
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS capture_events (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            count INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO capture_events (id, count) VALUES (1, 0)
        """
    )
    # Real endpoints table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS endpoints (
            endpoint_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    # Ensure endpoint_configs exists before migrating from it
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS endpoint_configs (
            endpoint_id TEXT PRIMARY KEY,
            forward_url TEXT,
            transform_script TEXT,
            response_body TEXT,
            response_headers TEXT,
            status_code INTEGER DEFAULT 200,
            filter_rules TEXT,
            retention_count INTEGER,
            updated_at TEXT
        )
        """
    )
    # Migrate existing endpoints from configs/webhooks
    conn.execute(
        """
        INSERT OR IGNORE INTO endpoints (endpoint_id, enabled, created_at, updated_at)
        SELECT endpoint_id, 1, datetime('now'), datetime('now')
        FROM endpoint_configs
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO endpoints (endpoint_id, enabled, created_at, updated_at)
        SELECT DISTINCT endpoint_id, 1, datetime('now'), datetime('now')
        FROM webhooks
        WHERE endpoint_id NOT IN (SELECT endpoint_id FROM endpoints)
        """
    )
    # Migration: add forward columns if missing (old dbs)
    for col in ["forward_status", "forward_response", "forwarded_at"]:
        try:
            conn.execute(f"ALTER TABLE webhooks ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass
    # Migration: add latency columns
    for col in ["latency_ms", "analysis_time_ms"]:
        try:
            conn.execute(f"ALTER TABLE webhooks ADD COLUMN {col} REAL")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()


def init_endpoint_config() -> None:
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS endpoint_configs (
            endpoint_id TEXT PRIMARY KEY,
            status_code INTEGER DEFAULT 200,
            response_headers TEXT,
            response_body TEXT,
            forward_url TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    # Migration: add forward_url if missing (old dbs)
    try:
        conn.execute("ALTER TABLE endpoint_configs ADD COLUMN forward_url TEXT")
    except sqlite3.OperationalError:
        pass  # already exists
    # Migration: add enabled if missing (old dbs)
    try:
        conn.execute("ALTER TABLE endpoint_configs ADD COLUMN enabled INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    # Migration: add retention_count if missing
    try:
        conn.execute("ALTER TABLE endpoint_configs ADD COLUMN retention_count INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    # Migration: add filter_rules if missing
    try:
        conn.execute("ALTER TABLE endpoint_configs ADD COLUMN filter_rules TEXT")
    except sqlite3.OperationalError:
        pass
    # Migration: add transform_script if missing
    try:
        conn.execute("ALTER TABLE endpoint_configs ADD COLUMN transform_script TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    # Schema inference table
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS endpoint_schemas (
            endpoint_id TEXT PRIMARY KEY,
            schema_json TEXT NOT NULL,
            inferred_at TEXT NOT NULL,
            webhook_count INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    # Migration: add validation_errors to webhooks
    try:
        conn.execute("ALTER TABLE webhooks ADD COLUMN validation_errors TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


def init_security_tables() -> None:
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            attempted_at REAL NOT NULL,
            success INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempted_at)"
    )
    conn.commit()
    conn.close()


def check_login_rate_limit_persistent(client_ip: str, max_attempts: int = 5, window: int = 900) -> bool:
    import time
    now = time.time()
    cutoff = now - window
    conn = _get_conn()
    conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
    row = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM login_attempts
        WHERE ip_address = ? AND attempted_at >= ? AND success = 0
        """,
        (client_ip, cutoff),
    ).fetchone()
    allowed = row["c"] < max_attempts
    if allowed:
        conn.execute(
            "INSERT INTO login_attempts (ip_address, attempted_at, success) VALUES (?, ?, 0)",
            (client_ip, now),
        )
    conn.commit()
    conn.close()
    return allowed


def set_endpoint_config(
    endpoint_id: str,
    status_code: int = 200,
    response_headers: Optional[dict] = None,
    response_body: Optional[str] = None,
    forward_url: Optional[str] = None,
    retention_count: Optional[int] = None,
    filter_rules: Optional[dict] = None,
    transform_script: Optional[str] = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    headers_json = json.dumps(response_headers or {}, default=str)
    rules_json = json.dumps(filter_rules or {}, default=str)
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO endpoint_configs (endpoint_id, status_code, response_headers, response_body, forward_url, retention_count, filter_rules, transform_script, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(endpoint_id) DO UPDATE SET
            status_code = excluded.status_code,
            response_headers = excluded.response_headers,
            response_body = excluded.response_body,
            forward_url = excluded.forward_url,
            retention_count = excluded.retention_count,
            filter_rules = excluded.filter_rules,
            transform_script = excluded.transform_script,
            updated_at = excluded.updated_at
        """,
        (endpoint_id, status_code, headers_json, response_body, forward_url, retention_count, rules_json, transform_script, now, now),
    )
    conn.commit()
    conn.close()


def get_endpoint_config(endpoint_id: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM endpoint_configs WHERE endpoint_id = ?", (endpoint_id,)).fetchone()
    conn.close()
    if not row:
        return None
    cfg = dict(row)
    cfg["response_headers"] = json.loads(cfg["response_headers"]) if cfg["response_headers"] else {}
    cfg["filter_rules"] = json.loads(cfg["filter_rules"]) if cfg.get("filter_rules") else {}
    return cfg


def create_endpoint() -> str:
    endpoint_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc).isoformat()
    conn = _get_conn()
    conn.execute(
        "INSERT INTO endpoints (endpoint_id, enabled, created_at, updated_at) VALUES (?, 1, ?, ?)",
        (endpoint_id, now, now),
    )
    conn.commit()
    conn.close()
    return endpoint_id


def set_endpoint_enabled(endpoint_id: str, enabled: bool) -> bool:
    conn = _get_conn()
    cur = conn.execute(
        """
        UPDATE endpoints
        SET enabled = ?, updated_at = ?
        WHERE endpoint_id = ?
        """,
        (1 if enabled else 0, datetime.now(timezone.utc).isoformat(), endpoint_id),
    )
    conn.commit()
    changed = cur.rowcount > 0
    conn.close()
    return changed


def get_all_endpoint_ids() -> list:
    conn = _get_conn()
    rows = conn.execute("SELECT endpoint_id FROM endpoints ORDER BY created_at DESC").fetchall()
    conn.close()
    return [r["endpoint_id"] for r in rows]


def get_endpoint(endpoint_id: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute(
        """
        SELECT e.endpoint_id, e.enabled, e.created_at, e.updated_at,
               c.status_code, c.response_headers, c.response_body,
               c.forward_url, c.retention_count, c.filter_rules, c.transform_script
        FROM endpoints e
        LEFT JOIN endpoint_configs c ON c.endpoint_id = e.endpoint_id
        WHERE e.endpoint_id = ?
        """,
        (endpoint_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    cfg = dict(row)
    cfg["enabled"] = bool(cfg.get("enabled", 1))
    cfg["response_headers"] = json.loads(cfg["response_headers"]) if cfg.get("response_headers") else {}
    cfg["filter_rules"] = json.loads(cfg["filter_rules"]) if cfg.get("filter_rules") else {}
    return cfg


def get_stats() -> dict:
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) as c FROM webhooks").fetchone()["c"]
    today = conn.execute(
        "SELECT COUNT(*) as c FROM webhooks WHERE received_at >= date('now')"
    ).fetchone()["c"]
    hourly = conn.execute(
        """
        SELECT strftime('%Y-%m-%d %H:00', received_at) as hour, COUNT(*) as c
        FROM webhooks WHERE received_at >= datetime('now', '-24 hours')
        GROUP BY hour ORDER BY hour
        """
    ).fetchall()
    conn.close()
    return {
        "total": total,
        "today": today,
        "hourly": [dict(r) for r in hourly],
    }


def store_webhook(
    endpoint_id: str,
    method: str,
    url: str,
    headers: dict,
    body: Optional[bytes],
    query_params: dict,
    client_ip: Optional[str],
    latency_ms: Optional[float] = None,
    trial_limit: Optional[int] = None,
) -> str | None:
    """Store a webhook. If trial_limit is provided, atomically checks against capture_events
    and returns None if the trial is already exhausted (does NOT increment in that case)."""
    webhook_id = uuid.uuid4().hex[:16]
    headers_json = json.dumps(headers, default=str)
    body_text = body.decode("utf-8", errors="replace") if body else None
    query_json = json.dumps(query_params, default=str)
    received_at = datetime.now(timezone.utc).isoformat()

    conn = _get_conn()
    try:
        conn.execute("BEGIN IMMEDIATE")

        # Atomic trial check + increment
        if trial_limit is not None:
            row = conn.execute("SELECT count FROM capture_events WHERE id = 1").fetchone()
            current = row["count"] if row else 0
            if current >= trial_limit:
                conn.execute("ROLLBACK")
                conn.close()
                return None  # trial exhausted

        conn.execute(
            """
            INSERT INTO webhooks (id, endpoint_id, method, url, headers, body, query_params, client_ip, received_at, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (webhook_id, endpoint_id, method, url, headers_json, body_text, query_json, client_ip, received_at, latency_ms),
        )
        # Increment capture counter for trial tracking
        conn.execute("UPDATE capture_events SET count = count + 1 WHERE id = 1")
        conn.commit()
        return webhook_id
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def apply_retention(endpoint_id: str, retention_count: int) -> None:
    if retention_count <= 0:
        return
    conn = _get_conn()
    conn.execute(
        """
        DELETE FROM webhooks WHERE id IN (
            SELECT id FROM webhooks WHERE endpoint_id = ? ORDER BY received_at DESC LIMIT -1 OFFSET ?
        )
        """,
        (endpoint_id, retention_count),
    )
    conn.commit()
    conn.close()


def get_webhooks(endpoint_id: Optional[str] = None, limit: int = 100) -> list:
    conn = _get_conn()
    if endpoint_id:
        rows = conn.execute(
            "SELECT * FROM webhooks WHERE endpoint_id = ? ORDER BY received_at DESC LIMIT ?",
            (endpoint_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM webhooks ORDER BY received_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("validation_errors"):
            try:
                d["validation_errors"] = json.loads(d["validation_errors"])
            except (json.JSONDecodeError, ValueError):
                d["validation_errors"] = None
        result.append(d)
    return result


def get_webhook(webhook_id: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_analysis(webhook_id: str, analysis: str, analysis_time_ms: Optional[float] = None) -> None:
    conn = _get_conn()
    if analysis_time_ms is not None:
        conn.execute(
            "UPDATE webhooks SET analysis = ?, analyzed = 1, analysis_time_ms = ? WHERE id = ?",
            (analysis, analysis_time_ms, webhook_id),
        )
    else:
        conn.execute(
            "UPDATE webhooks SET analysis = ?, analyzed = 1 WHERE id = ?",
            (analysis, webhook_id),
        )
    conn.commit()
    conn.close()


def delete_webhook(webhook_id: str) -> None:
    conn = _get_conn()
    conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
    conn.commit()
    conn.close()


def delete_all_for_endpoint(endpoint_id: str) -> None:
    conn = _get_conn()
    conn.execute("DELETE FROM webhooks WHERE endpoint_id = ?", (endpoint_id,))
    conn.commit()
    conn.close()


def get_schema(endpoint_id: str) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM endpoint_schemas WHERE endpoint_id = ?", (endpoint_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)


def set_schema(endpoint_id: str, schema: dict, webhook_count: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    schema_json = json.dumps(schema, default=str)
    conn = _get_conn()
    conn.execute(
        """
        INSERT INTO endpoint_schemas (endpoint_id, schema_json, inferred_at, webhook_count, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(endpoint_id) DO UPDATE SET
            schema_json = excluded.schema_json,
            inferred_at = excluded.inferred_at,
            webhook_count = excluded.webhook_count,
            updated_at = excluded.updated_at
        """,
        (endpoint_id, schema_json, now, webhook_count, now),
    )
    conn.commit()
    conn.close()


def delete_schema(endpoint_id: str) -> None:
    conn = _get_conn()
    conn.execute("DELETE FROM endpoint_schemas WHERE endpoint_id = ?", (endpoint_id,))
    conn.commit()
    conn.close()


def update_validation_errors(webhook_id: str, errors: list) -> None:
    conn = _get_conn()
    conn.execute(
        "UPDATE webhooks SET validation_errors = ? WHERE id = ?",
        (json.dumps(errors, default=str) if errors else None, webhook_id),
    )
    conn.commit()
    conn.close()


def update_forward_status(webhook_id: str, status: int, response: str) -> None:
    conn = _get_conn()
    conn.execute(
        "UPDATE webhooks SET forward_status = ?, forward_response = ?, forwarded_at = ? WHERE id = ?",
        (status, response, datetime.now(timezone.utc).isoformat(), webhook_id),
    )
    conn.commit()
    conn.close()


def get_total_webhook_count() -> int:
    """Return total number of captured webhooks across all endpoints."""
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) as c FROM webhooks").fetchone()
    conn.close()
    return row["c"] if row else 0


def get_capture_event_count() -> int:
    """Return total number of capture events ever recorded (never decrements on delete)."""
    conn = _get_conn()
    row = conn.execute("SELECT count FROM capture_events WHERE id = 1").fetchone()
    conn.close()
    return row["count"] if row else 0


def health_check() -> bool:
    """Quick DB connectivity check."""
    try:
        conn = _get_conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return True
    except Exception:
        return False
