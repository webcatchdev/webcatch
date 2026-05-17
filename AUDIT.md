# Webcatch Audit Report

**Project:** webcatchdev/webcatch (Webhook Inspector)  
**Version:** 0.5.0  
**Date:** 2026-05-17  
**Auditor:** Herm-E  

---

## Executive Summary

The project is feature-rich and functional, but **NOT ready for public launch** in its current state. Critical security vulnerabilities exist, there is zero feature gating for the pricing tiers, and the payment flow is incomplete. The good news: most issues are fixable in 1–2 focused sessions.

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Security | 2 | 3 | 5 | 2 |
| Code Quality | 1 | 2 | 4 | 3 |
| Business/Logic | 3 | 2 | 1 | 1 |
| **Total** | **6** | **7** | **10** | **6** |

---

## Critical Issues

### C1. No License / Tier Enforcement ⚠️ BUSINESS KILLER

**Severity:** Critical  
**Location:** Entire app  

The README advertises Free vs Pro tiers, but the app does **not enforce anything**. All features work regardless of whether the user has a license key.

- Custom responses, bulk replay, unlimited history, team sharing — all available without payment.
- The `license.validate_license()` function exists but is never checked before serving Pro features.
- A user can simply skip the checkout and use everything.

**Fix:** Implement a `require_tier()` dependency that gates Pro endpoints.

---

### C2. Transform Script Sandbox Escape ⚠️ SECURITY KILLER

**Severity:** Critical  
**Location:** `main.py` lines 440–478  

The "safe" sandbox allows `type`, `isinstance`, `hasattr`, and `getattr`. These can be chained to escape the sandbox:

```python
# In a transform script:
().__class__.__bases__[0].__subclasses__()  # access object subclasses
# From there, can reach warnings.catch_warnings → builtins → os.system
```

An attacker who controls `transform_script` (via endpoint config) can execute arbitrary code on the server.

**Fix:** Remove `type`, `isinstance`, `hasattr`, `getattr`. Use ` RestrictedPython` or `ast.literal_eval` for simple transforms, or move to a subprocess sandbox.

---

### C3. No Rate Limiting on Webhook Capture

**Severity:** Critical  
**Location:** `/wh/{endpoint_id}`  

Anyone can POST massive payloads to `/wh/{id}` without limits. This enables:
- Disk-filling attacks (unbounded body sizes)
- DoS (no request rate limits)
- Cost attacks if forwarding is enabled

**Fix:** Add body size limit (e.g., 1MB) and per-IP rate limiting.

---

### C4. Duplicate Function Definition

**Severity:** Critical (code smell, maintenance hazard)  
**Location:** `main.py` lines 372–401 and 576–605  

`_analyze_and_store` is defined **twice** with identical bodies. Python silently overwrites the first definition. If someone edits one copy but not the other, behavior diverges unpredictably.

**Fix:** Delete the second copy (lines 576–605).

---

### C5. Hardcoded $39 Lifetime Price — Does Not Match Business Plan

**Severity:** Critical (business)  
**Location:** `main.py` lines 1120–1136  

The Stripe checkout is hardcoded to `$39` for a single "lifetime" license. User wants:
- **Basic tier:** $12 (one-time, replaces "free")
- **Pro tier:** significantly more expensive (suggested $79–$129 one-time)

There is no concept of Basic vs Pro in the checkout code.

**Fix:** Create two Stripe checkout endpoints (or a unified one with `price_id` param) and gate features based on tier.

---

### C6. No Request Body Size Limit

**Severity:** Critical  
**Location:** `/wh/{endpoint_id}`  

`await request.body()` can read unlimited data into memory. A 10GB POST will crash the process or fill the disk.

**Fix:** Add FastAPI `Request` size limit middleware or Uvicorn `--limit-max-body-size`.

---

## High Issues

### H1. No CSRF Protection on State-Changing Endpoints

POST/PUT/DELETE endpoints (replay, delete, config update, bulk replay) accept requests without CSRF tokens. If a user is logged in, a malicious site can trigger actions.

**Fix:** Add `SameSite=Strict` cookies and/or CSRF token validation for non-GET requests.

---

### H2. Cookie Security Flags Missing

**Location:** `auth.py` lines 69–76  

Session cookies are `httponly=True` and `samesite="lax"`, but missing:
- `secure=True` (required for HTTPS deployments)
- `max_age` is 30 days but no rotation/revocation mechanism

**Fix:** Add `secure=True` when `ENV=production`. Add session revocation list.

---

### H3. Inline Imports in Route Handlers

**Location:** `main.py`  

`urllib.parse` and `signature` are imported inside route functions. This is:
- Slower (re-imported on every request)
- Harder to catch missing dependencies at startup

**Fix:** Move all imports to the top of the file.

---

### H4. No Input Validation on `endpoint_id`

`endpoint_id` is used as a URL path segment and DB key, but never validated. Could contain path traversal (`../`) or SQL injection attempts.

**Fix:** Validate with regex `^[a-f0-9]{12}$` (matches UUID hex output).

---

### H5. License Keys Not Bound to Anything

A single `$39` license key can be used on infinite servers. There is no device/instance binding, no activation limit, no revocation.

**Fix:** Add `max_activations` column, track IP + hostname on first `validate_license`, enforce limit.

---

### H6. No Stripe Timestamp Tolerance

**Location:** `signature.py` lines 12–32  

Stripe signature verification does not check timestamp tolerance. A replayed signature from hours ago would pass.

**Fix:** Reject if `|now - timestamp| > 300 seconds`.

---

## Medium Issues

### M1. No CORS Configuration

The API may reject requests from the dashboard if served from a different origin. FastAPI defaults to no CORS.

**Fix:** Add `CORSMiddleware` with explicit allowlist.

---

### M2. No Security Headers

Missing: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`.

**Fix:** Add security headers middleware.

---

### M3. Webhook Capture Returns 200 on Filtered Requests

When a webhook is filtered out, the app returns `200 OK` with `{"status": "filtered"}`. The sender thinks the webhook was accepted.

**Fix:** Return `202 Accepted` for filtered requests, or make it configurable.

---

### M4. No Request Timeout on Forwarding

`aiohttp.ClientSession()` has no explicit timeout for forwarded webhooks. A slow target can hold connections open indefinitely.

**Fix:** Add `aiohttp.ClientTimeout(total=30)` to forwarding sessions.

---

### M5. No Logging Configuration

The app uses no structured logging. Errors go to stderr only. No request IDs, no access logs.

**Fix:** Configure `logging` with rotation. Add request ID middleware.

---

### M6. Missing `__init__.py`

The project has no package structure. Tests cannot import modules cleanly.

**Fix:** Add `__init__.py` and/or switch to `src/` layout.

---

### M7. `jinja2` in requirements but unused

**Fix:** Remove from `requirements.txt`.

---

### M8. No Tests

Zero unit tests, zero integration tests.

**Fix:** Add `pytest` suite for at least auth, storage, signature, and schema engine.

---

### M9. Docker Runs as Root

The Dockerfile does not create a non-root user.

**Fix:** Add `RUN useradd -m appuser && USER appuser`.

---

## Low Issues

### L1. `data/` directory not in `.gitignore`

SQLite DBs and license DBs could be accidentally committed.

**Fix:** Add `data/` to `.gitignore`.

### L2. `requirements.txt` has no version pins

Could break on dependency updates.

**Fix:** Pin versions or add `requirements-dev.txt` with hashes.

### L3. No health check that verifies DB connectivity

`/api/health` only returns a static dict.

**Fix:** Query `SELECT 1` from both DBs in health check.

### L4. Marketing comparison matrix is misleading

README says "Free" tier has AI analysis and transform scripts, but these are compute-intensive. A free tier with no limits is unsustainable.

**Fix:** Align matrix with actual gated features.

---

## Recommendations

### Must Fix Before Launch
1. **C1** — Implement tier enforcement (`basic` vs `pro`)
2. **C2** — Fix sandbox escape (remove dangerous builtins)
3. **C3** — Add rate limiting + body size cap
4. **C4** — Remove duplicate `_analyze_and_store`
5. **C5** — Implement $12 Basic + $79–$129 Pro checkout
6. **C6** — Add body size limit

### Should Fix Before Launch
7. **H1** — CSRF protection
8. **H4** — Input validation on `endpoint_id`
9. **H5** — License activation limits
10. **M8** — At least smoke tests
11. **M9** — Docker non-root user

### Can Fix Post-Launch
12. Structured logging
13. Security headers middleware
14. Admin panel for license management
15. Subscription model (if desired)

---

## Pricing Model Proposal

| Tier | Price | Features |
|------|-------|----------|
| **Basic** | **$12** one-time | 3 endpoints, 50 webhook history, basic replay, signature verify, no AI analysis, no transforms, no forwarding |
| **Pro** | **$79** one-time | Unlimited endpoints, unlimited history, AI analysis, transform scripts, forwarding, schema inference, bulk replay, team sharing (5 users) |
| **Team** | **$149** one-time | Everything in Pro + unlimited team members, priority support |

**Note:** The user specified "much more expensive Pro tier." $79 is a 6x jump from $12, which creates clear value separation without being absurd. Team tier at $149 captures enterprise value.

---

## Files to Change

| File | Changes |
|------|---------|
| `main.py` | Fix duplicate function, add tier enforcement, fix imports, add rate limiting, add body size limit, fix checkout for two tiers |
| `auth.py` | Add `secure` cookie flag, session revocation |
| `license.py` | Add tier column, activation tracking, max activations |
| `storage.py` | Add webhook count per endpoint, enforce history limits per tier |
| `requirements.txt` | Pin versions, remove `jinja2` |
| `Dockerfile` | Add non-root user |
| `README.md` | Update pricing matrix |
| `static/dashboard.html` | Gate Pro UI features based on tier |
| `.gitignore` | Add `data/` |
| **new** `tests/` | Smoke tests for critical paths |
