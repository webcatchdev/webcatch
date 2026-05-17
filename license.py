"""Supporter license key management for Webcatch."""
import os
import sqlite3
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "licenses.db")
_MAX_ACTIVATIONS = int(os.getenv("LICENSE_MAX_ACTIVATIONS", "2"))


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            email TEXT,
            stripe_session_id TEXT,
            created_at TEXT,
            validated_at TEXT,
            is_valid INTEGER DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_stripe_session
        ON licenses(stripe_session_id)
        WHERE stripe_session_id IS NOT NULL
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS license_activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            ip_address TEXT,
            activated_at TEXT NOT NULL,
            FOREIGN KEY (license_key) REFERENCES licenses(key)
        )
    """)
    conn.commit()
    conn.close()


def create_license(email: str = None, stripe_session_id: str = None) -> str:
    init_db()
    conn = _get_conn()
    if stripe_session_id:
        existing = conn.execute(
            "SELECT key FROM licenses WHERE stripe_session_id = ?",
            (stripe_session_id,),
        ).fetchone()
        if existing:
            conn.close()
            return existing["key"]

    key = "wc-" + uuid.uuid4().hex[:24]
    try:
        conn.execute(
            "INSERT INTO licenses (key, email, stripe_session_id, created_at) VALUES (?, ?, ?, ?)",
            (key, email, stripe_session_id, datetime.now(timezone.utc).isoformat())
        )
    except sqlite3.IntegrityError:
        existing = conn.execute(
            "SELECT key FROM licenses WHERE stripe_session_id = ?",
            (stripe_session_id,),
        ).fetchone()
        conn.close()
        if existing:
            return existing["key"]
        raise
    conn.commit()
    conn.close()
    return key


def get_license(key: str) -> dict:
    init_db()
    conn = _get_conn()
    row = conn.execute("SELECT * FROM licenses WHERE key = ?", (key,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def _get_activation_count(key: str) -> int:
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) as c FROM license_activations WHERE license_key = ?", (key,)).fetchone()
    conn.close()
    return row["c"] if row else 0


def has_valid_license() -> bool:
    """Return True if any valid license exists in the database."""
    init_db()
    conn = _get_conn()
    row = conn.execute("SELECT COUNT(*) as c FROM licenses WHERE is_valid = 1").fetchone()
    conn.close()
    return row["c"] > 0 if row else False


def validate_and_activate(key: str, client_ip: str) -> dict:
    """Validate a license key and track activation. Returns {valid: bool, activations: int, error: str|None}."""
    init_db()
    lic = get_license(key)
    if not lic:
        return {"valid": False, "activations": 0, "error": "Invalid license key"}
    if lic.get("is_valid", 0) != 1:
        return {"valid": False, "activations": 0, "error": "License revoked"}

    current_activations = _get_activation_count(key)

    # Check if this IP already activated (re-activation from same machine is fine)
    conn = _get_conn()
    existing = conn.execute(
        "SELECT id FROM license_activations WHERE license_key = ? AND ip_address = ?",
        (key, client_ip)
    ).fetchone()

    if not existing:
        if current_activations >= _MAX_ACTIVATIONS:
            conn.close()
            return {
                "valid": False,
                "activations": current_activations,
                "error": f"Activation limit reached ({_MAX_ACTIVATIONS} devices). Contact support to reset.",
            }
        conn.execute(
            "INSERT INTO license_activations (license_key, ip_address, activated_at) VALUES (?, ?, ?)",
            (key, client_ip, datetime.now(timezone.utc).isoformat())
        )
        current_activations += 1

    conn.execute(
        "UPDATE licenses SET validated_at = ? WHERE key = ?",
        (datetime.now(timezone.utc).isoformat(), key)
    )
    conn.commit()
    conn.close()
    return {"valid": True, "activations": current_activations, "error": None}
