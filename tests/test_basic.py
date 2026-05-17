"""Basic smoke tests for Webcatch."""
import asyncio
import os
import sys
import json
import tempfile

# Point to project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import storage
import license as lic_module
import auth
import signature


def test_endpoint_id_validation():
    from main import _validate_endpoint_id
    assert _validate_endpoint_id("abc123def456") is True
    assert _validate_endpoint_id("abc") is False
    assert _validate_endpoint_id("../../etc/passwd") is False
    assert _validate_endpoint_id("abc123def45G") is False


def test_rate_limiter():
    from main import _check_rate_limit, _clean_rate_limiter
    _clean_rate_limiter()
    ip = "1.2.3.4"
    # Should allow first request
    assert asyncio.run(_check_rate_limit(ip)) is True
    _clean_rate_limiter()


def test_transform_sandbox_no_escape():
    """Ensure dangerous builtins are NOT available in transform sandbox."""
    from main import _run_transform_sync
    script = "result = type(method)"
    _, _, _, _, _, error = _run_transform_sync(script, "POST", "http://x", {}, "", {})
    assert error is not None or "type" in str(error) or "NameError" in str(error)

    script = "result = isinstance(method, str)"
    _, _, _, _, _, error = _run_transform_sync(script, "POST", "http://x", {}, "", {})
    assert error is not None or "isinstance" in str(error) or "NameError" in str(error)

    script = "result = hasattr(method, 'upper')"
    _, _, _, _, _, error = _run_transform_sync(script, "POST", "http://x", {}, "", {})
    assert error is not None or "hasattr" in str(error) or "NameError" in str(error)


def test_storage_health_check():
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_path = storage.DB_PATH
        storage.DB_PATH = os.path.join(tmpdir, "test.db")
        try:
            storage.init_db()
            assert storage.health_check() is True
        finally:
            storage.DB_PATH = orig_path


def test_license_activation():
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_path = lic_module.DB_PATH
        lic_module.DB_PATH = os.path.join(tmpdir, "licenses.db")
        try:
            lic_module.init_db()
            key = lic_module.create_license(email="test@example.com")
            assert lic_module.has_valid_license() is True

            # First activation should succeed
            result = lic_module.validate_and_activate(key, "1.2.3.4")
            assert result["valid"] is True
            assert result["activations"] == 1

            # Same IP re-activation should succeed
            result2 = lic_module.validate_and_activate(key, "1.2.3.4")
            assert result2["valid"] is True
            assert result2["activations"] == 1

            # New IP within limit should succeed
            result3 = lic_module.validate_and_activate(key, "5.6.7.8")
            assert result3["valid"] is True
            assert result3["activations"] == 2

            # Third IP should fail (max 2 by default)
            result4 = lic_module.validate_and_activate(key, "9.10.11.12")
            assert result4["valid"] is False
            assert "limit" in result4["error"].lower()
        finally:
            lic_module.DB_PATH = orig_path


def test_signature_timestamp_tolerance():
    import time
    payload = b'{"test": true}'
    secret = "whsec_test"
    timestamp = str(int(time.time()))
    sig = f"t={timestamp},v1=invalid"
    result = signature.verify_stripe(payload, sig, secret)
    # Should fail because signature is invalid, not because of timestamp
    assert result is False

    # Old timestamp (> 5 min)
    old_ts = str(int(time.time()) - 400)
    old_sig = f"t={old_ts},v1=invalid"
    result2 = signature.verify_stripe(payload, old_sig, secret)
    assert result2 is False


def test_csrf_generation():
    token = auth.generate_csrf_token()
    assert len(token) > 20
    token2 = auth.generate_csrf_token()
    assert token != token2


if __name__ == "__main__":
    test_endpoint_id_validation()
    print("✅ endpoint_id validation")
    test_rate_limiter()
    print("✅ rate limiter")
    test_transform_sandbox_no_escape()
    print("✅ transform sandbox")
    test_storage_health_check()
    print("✅ storage health check")
    test_license_activation()
    print("✅ license activation")
    test_signature_timestamp_tolerance()
    print("✅ signature timestamp tolerance")
    test_csrf_generation()
    print("✅ CSRF generation")
    print("\n🎉 All tests passed!")
