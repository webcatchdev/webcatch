# Webcatch Security & Code Quality Audit

**Project:** [webcatchdev/webcatch](https://github.com/webcatchdev/webcatch)  
**Version:** 0.6.1  
**Date:** 2026-05-17  
**Auditor:** Multi-model panel (Kimi K2.6, Qwen 3.6+, GLM 5.1, Qwen 3.5+, DeepSeek V4 Pro)

---

## Security Posture: v0.6.1

This version fixes all Critical and High issues found in the v0.5.0 audit. Remaining issues are Medium or Low. The app is **ready for controlled public use** (Basic tier), but the Pro tier features should be reviewed by additional models before wide deployment.

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| Security | 0 | 0 | 3 | 2 |
| Code Quality | 0 | 0 | 2 | 2 |
| Business/Logic | 0 | 0 | 2 | 1 |
| **Total** | **0** | **0** | **7** | **5** |

---

## Fixed in v0.6.1 (Do Not Report)

The following were identified in v0.5.0 or by the multi-model panel and are **already fixed**. Please do not re-report them.

| Issue | Fix |
|-------|-----|
| **RCE via `exec()` sandbox** | Transforms gated behind `WEBCATCH_ENABLE_TRANSFORMS` (default `false`). |
| **SSRF on replay/test/forward** | `_is_safe_url()` blocks private IPs, metadata endpoints, non-HTTP schemes. |
| **Broken CSRF** | Single token generated, used for both JSON body and `Set-Cookie`. |
| **Timing attack on password** | `hmac.compare_digest()` replaces `==`. |
| **Rate limiter race condition** | `asyncio.Lock` protects `_rate_limiter`. |
| **Login rate limiting** | 5 attempts per 15 minutes per IP. |
| **License activation race** | `BEGIN IMMEDIATE` + `UNIQUE(license_key, ip_address)` constraint. |
| **Trial bypass via deletion** | `capture_events` counter never decrements. |
| **Auth fail-open** | Raises `RuntimeError` at startup if `WEBCATCH_PASSWORD` not set in production. |
| **Body size limit** | `MAX_BODY_SIZE = 1MB` enforced on capture. |
| **Endpoint ID validation** | Regex `^[a-f0-9]{12}$` enforced. |
| **CSP / security headers** | Strict CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. |
| **WebSocket list mutation** | `list()` snapshot during `broadcast()`. |
| **WebSocket auth** | `/ws` added to auth middleware whitelist. |
| **Info disclosure in replay** | Generic error messages, no `str(e)` in responses. |
| **Health check leak** | Removed `local_llm` URL from `/api/health`. |
| **Docker non-root** | Runs as `appuser` (UID 1000). |
| **Docker HEALTHCHECK** | Added `HEALTHCHECK` to Dockerfile. |

---

## Remaining Medium Issues

### M1. `exec()` Sandbox Still Present (Gated, Not Removed)

**Location:** `main.py`  
**Status:** Gated behind env var, but the `exec()` code path still exists.

If a user explicitly enables transforms, the RCE risk returns. The proper fix is replacing `exec()` with `RestrictedPython` or a subprocess sandbox. This is acceptable for now because the feature is opt-in and documented as unsafe.

**Open Question:** Should we remove `exec()` entirely and replace with AST-only transforms?

---

### M2. No Structured Logging

**Location:** Entire app  
**Status:** Errors go to `stderr` only. No request IDs, no rotation, no correlation.

**Impact:** Hard to debug production issues, no audit trail for license activations or security events.

---

### M3. No Feature Tier Enforcement in Backend

**Location:** `main.py`  
**Status:** License check (`_require_license()`) gates capture entirely, but does **not** gate individual features (AI analysis, transforms, forwarding, bulk replay, team sharing).

All licensed users get everything. The user wants:
- Basic: $12 one-time (limited features)
- Pro: $79–$129 one-time (all features)

**Current state:** Only "free vs paid" is enforced, not "basic vs pro."

---

### M4. Stripe Checkout is Single-Tier

**Location:** `main.py` checkout endpoint  
**Status:** One hardcoded price. No Basic/Pro selection.

---

### M5. Cookie `secure=True` Missing

**Location:** `auth.py`  
**Status:** `httponly=True`, `samesite="lax"`, but `secure=True` is not set even in production. Browsers may reject `SameSite=None` without `Secure` on HTTPS.

---

### M6. No Tests

**Location:** Entire project  
**Status:** Zero tests. Smoke tests passed manually on VPS but not automated.

---

### M7. `requirements.txt` Has No Version Pins

**Location:** `requirements.txt`  
**Status:** Could break on upstream updates.

---

## Remaining Low Issues

### L1. No Request ID Middleware

No correlation IDs for tracing requests across logs.

### L2. `jinja2` in `requirements.txt` but Unused

Leftover dependency.

### L3. No Admin Panel for License Management

Must query SQLite directly to revoke licenses or view activations.

### L4. No Subscription Model

All tiers are one-time. No recurring revenue path.

### L5. Marketing Copy References Free Tier

README still mentions "Free" tier in some places. The user wants "Basic" ($12) as the entry tier with no free option.

---

## Recommendations

### Before Wide Pro Deployment
1. Replace `exec()` with AST-only transforms or subprocess sandbox
2. Add structured logging (`structlog` or `python-json-logger`)
3. Implement Basic vs Pro feature gating in backend
4. Add Basic/Pro Stripe checkout endpoints
5. Pin `requirements.txt` versions

### Nice to Have
6. Add `pytest` smoke tests for auth, SSRF validator, license logic
7. Add request ID middleware
8. Add admin panel for license management

---

## Context for OpenRouter Reviewers

**What to focus on:**
- New vulnerabilities introduced in v0.6.1 changes (SSRF validator, rate limiter, auth logic)
- Business logic gaps (tier enforcement, pricing, license activation edge cases)
- Code quality issues in the new code paths
- Anything we missed in the multi-model review

**What NOT to report:**
- Any issue listed in "Fixed in v0.6.1" above — they are already resolved.
- The `exec()` sandbox itself — it is gated and known. Only report if you find a way to bypass the gating.
