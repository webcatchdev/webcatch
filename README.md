# Webcatch 🔍

> Self-hosted webhook capture, replay, and analysis. All data stays on your machine.

[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Why Webcatch?

Most webhook tools send your data to someone else's cloud. Webcatch doesn't. Everything runs locally — your data, your server, your rules.

- **🔒 Privacy-first** — SQLite storage. No telemetry. No cloud lock-in.
- **📡 Real-time dashboard** — WebSocket-powered live updates.
- **🔄 Replay & proxy** — Resend webhooks, forward to backends, transform payloads with Python scripts, verify HMAC signatures.
- **🧠 AI analysis** — Analyze webhooks with your local LLM (optional).
- **🧬 Auto schema inference** — Automatically infer JSON schemas from webhook history. Validate new webhooks against the inferred schema and export as OpenAPI.
- **🔍 Search & diff** — Full-text search. Side-by-side webhook comparison.

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/webcatchdev/webcatch.git
cd webcatch
docker compose up -d
```

Open http://localhost:9120

### Local Python

```bash
cd webcatch
pip install -r requirements.txt
python main.py
```

---

## Pricing

Webcatch is a **$12 one-time purchase**. No subscriptions. No recurring fees.

**Trial:** Capture up to 10 webhooks for free. After that, enter a license key to unlock unlimited usage.

[Purchase a license](https://webcatch.dev) → receive a license key → paste it into Settings → License.

Your license works on up to 2 devices (contact support to reset activations).

---

## Features

- Unlimited endpoints
- Real-time dashboard
- Webhook replay & bulk replay
- Forwarding / proxy with Python transform scripts
- Signature verification (Stripe, GitHub, Shopify, generic HMAC)
- Search & filter
- Webhook diff
- AI analysis via local LLM
- Postman / cURL export
- Schema inference & validation
- OpenAPI export
- Custom response codes & headers

---

## Configuration

Create a `.env` file:

```bash
# App
INSPECTOR_PORT=9120
INSPECTOR_HOST=0.0.0.0
WEBCATCH_ENV=production

# Auth (optional — protects dashboard & API, leaves webhook capture open)
WEBCATCH_PASSWORD=your-secure-password

# Stripe (for $12 license checkout)
STRIPE_SECRET_KEY=sk_...
STRIPE_PUBLISHABLE_KEY=pk_...
STRIPE_WEBHOOK_SECRET=whsec_...
SUCCESS_URL=https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}
CANCEL_URL=https://yourdomain.com/

# Local LLM (optional, for AI analysis)
LOCAL_LLM_URL=http://127.0.0.1:8081/v1/chat/completions
LOCAL_LLM_MODEL=qwen-local
```

---

## Authentication

Set `WEBCATCH_PASSWORD` to password-protect the dashboard and all API routes. Webhook capture URLs (`/wh/{id}`) remain **publicly accessible** so external services can still deliver webhooks.

- If `WEBCATCH_PASSWORD` is **not set**, everything is open (backward compatible).
- If set, visiting `/` or `/dashboard` presents a login page.
- Session cookies expire after 30 days.
- The logout button is in the top-right of the dashboard.

---

## Architecture

- **FastAPI** backend + SQLite storage
- **Vanilla JS** dashboard (no build step)
- **WebSocket** real-time updates
- **Docker** single-container deploy
- Optional **local LLM** via OpenAI-compatible API (llama.cpp, Ollama, etc.)

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/endpoints` | POST | Create endpoint |
| `/api/endpoints` | GET | List endpoints |
| `/api/webhooks` | GET | List captured webhooks |
| `/api/webhooks/export?format=postman` | GET | Export as Postman collection |
| `/api/webhooks/export?format=curl` | GET | Export as cURL script |
| `/api/webhooks/export?format=csv` | GET | Export as CSV |
| `/api/endpoints/{id}/config` | GET/PUT | Get/set endpoint config |
| `/api/endpoints/{id}/schema` | GET | Get inferred JSON schema |
| `/api/endpoints/{id}/schema/infer` | POST | Force re-inference |
| `/api/endpoints/{id}/schema/openapi` | GET | Export as OpenAPI document |
| `/wh/{id}` | ANY | Capture webhooks |
| `/api/webhooks/{id}/replay` | POST | Replay webhook |
| `/api/webhooks/{id}/export` | GET | Export single webhook |
| `/api/webhooks/{a}/diff/{b}` | GET | Compare webhooks |
| `/api/checkout` | POST | Create Stripe checkout session ($12) |
| `/api/license/validate` | POST | Validate license key |
| `/ws` | WebSocket | Live updates |

Full API docs at `/docs` when running.

---

## Transform Scripts

Before forwarding a webhook, you can mutate it with a Python script. Available variables:

- `method` — HTTP method (str)
- `url` — Target URL (str)
- `headers` — Dict of headers
- `body` — Request body (str or None)
- `query` — Dict of query params

Example — strip PII before forwarding:

```python
import json
data = json.loads(body)
data.pop("email", None)
data.pop("ssn", None)
body = json.dumps(data)
```

Scripts run in a restricted sandbox with a 5-second timeout. If a script fails, the original webhook is forwarded unchanged and the error is logged.

---

## Schema Inference

Webcatch automatically analyzes JSON webhook bodies for each endpoint and infers a JSON Schema. New webhooks are validated against this schema in real-time — anomalies show a red ⚠️ badge on the webhook card.

What gets inferred:
- **Types** — `string`, `integer`, `number`, `boolean`, `array`, `object`, `null`
- **Required fields** — fields that appear in every observed webhook
- **Enums** — string values with ≤10 distinct observed values
- **Min/max** — numeric ranges

Inferred schemas are updated continuously as new webhooks arrive. You can also force re-inference or clear the schema from the dashboard.

Export the inferred schema as an **OpenAPI 3.0 document** for documentation or code generation.

---

## License

MIT — see [LICENSE](LICENSE)

---

Built for developers who care about privacy.
