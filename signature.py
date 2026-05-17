"""
Webhook signature verification for common providers.
Supports: Stripe, GitHub, Shopify, generic HMAC-SHA256.
"""

import hashlib
import hmac
import json
import time
from typing import Optional


def verify_stripe(payload: bytes, signature: str, secret: str) -> bool:
    """Verify Stripe webhook signature with timestamp tolerance."""
    try:
        elements = signature.split(",")
        sig_dict = {}
        for elem in elements:
            if "=" in elem:
                k, v = elem.split("=", 1)
                sig_dict.setdefault(k, []).append(v)

        timestamp = sig_dict.get("t", [""])[0]
        if not timestamp:
            return False
        # Reject signatures older than 5 minutes (replay protection)
        if abs(int(time.time()) - int(timestamp)) > 300:
            return False

        expected = hmac.new(
            secret.encode("utf-8"),
            f"{timestamp}.".encode("utf-8") + payload,
            hashlib.sha256,
        ).hexdigest()

        return expected in sig_dict.get("v1", [])
    except Exception:
        return False


def verify_github(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature (sha256)."""
    try:
        if not signature.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def verify_shopify(payload: bytes, signature: str, secret: str) -> bool:
    """Verify Shopify webhook HMAC-SHA256 signature (base64 encoded)."""
    try:
        import base64
        expected = base64.b64encode(
            hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
        ).decode("utf-8")
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


def verify_generic(payload: bytes, signature: str, secret: str, algorithm: str = "sha256") -> bool:
    """Verify generic HMAC signature. Signature can be hex or with prefix like sha256=."""
    try:
        sig = signature
        if "=" in sig:
            _, sig = sig.split("=", 1)

        hasher = getattr(hashlib, algorithm, hashlib.sha256)
        expected = hmac.new(secret.encode("utf-8"), payload, hasher).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


def detect_provider(headers: dict) -> Optional[str]:
    """Detect webhook provider from headers."""
    h = {k.lower(): v for k, v in headers.items()}
    if "stripe-signature" in h:
        return "stripe"
    if "x-hub-signature-256" in h:
        return "github"
    if "x-shopify-hmac-sha256" in h:
        return "shopify"
    if "x-hub-signature" in h:
        return "github_legacy"
    return None


def verify_webhook(headers: dict, body: bytes, secrets: dict) -> dict:
    """
    Verify a webhook signature given headers and body.
    secrets: {"stripe": "sk_...", "github": "ghp_...", ...}
    Returns: {"provider": str|None, "verified": bool, "error": str|None}
    """
    provider = detect_provider(headers)
    if not provider:
        return {"provider": None, "verified": False, "error": "No recognized signature header"}

    secret = secrets.get(provider)
    if not secret:
        return {"provider": provider, "verified": False, "error": f"No secret configured for {provider}"}

    h = {k.lower(): v for k, v in headers.items()}

    if provider == "stripe":
        sig = h.get("stripe-signature", "")
        ok = verify_stripe(body, sig, secret)
    elif provider == "github":
        sig = h.get("x-hub-signature-256", "")
        ok = verify_github(body, sig, secret)
    elif provider == "github_legacy":
        sig = h.get("x-hub-signature", "")
        ok = verify_generic(body, sig, secret, "sha1")
    elif provider == "shopify":
        sig = h.get("x-shopify-hmac-sha256", "")
        ok = verify_shopify(body, sig, secret)
    else:
        return {"provider": provider, "verified": False, "error": "Unknown provider"}

    return {"provider": provider, "verified": ok, "error": None if ok else "Signature mismatch"}
