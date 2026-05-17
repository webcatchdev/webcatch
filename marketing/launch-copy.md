# Launch Copy

## Hacker News (Show HN)

**Title:** Show HN: Webcatch – Self-hosted webhook inspector with AI analysis

**Body:**

I built Webcatch because I was tired of sending my webhook payloads to someone else's cloud. Every time I debugged a Stripe or GitHub webhook, I had to trust a third party with potentially sensitive data.

Webcatch is a single Docker container that captures, replays, and analyzes webhooks — entirely on your machine.

**What it does:**
- Creates webhook URLs instantly (`/wh/{id}`)
- Captures every request with headers, body, query params
- **Replays** any webhook with one click (or bulk replay)
- **Forwards** to your backend with optional Python transform scripts
- **Analyzes** payloads with your local LLM (Ollama, llama.cpp, etc.) — no API keys
- **Infers JSON schemas** from your webhook history and validates new ones
- **Verifies** HMAC signatures (Stripe, GitHub, Shopify)
- **Exports** to Postman collections, cURL scripts, or CSV
- **Diffs** two webhooks side-by-side

**Tech stack:** FastAPI, SQLite, vanilla JS, WebSocket. No build step. One container.

**Pricing:** Free (100 recent webhooks) or $39 lifetime Pro (unlimited history, bulk replay, team sharing up to 5).

MIT licensed. GitHub: https://github.com/webcatchdev/webcatch

I'd love feedback on the schema inference and local LLM integration. What would make this your default webhook tool?

---

## Indie Hackers

**Title:** I built a self-hosted webhook inspector because I was tired of SaaS lock-in

**Body:**

Hey IH 👋

I’m a solo developer who works with a lot of webhooks (Stripe, GitHub, Shopify). Every existing tool sends my payload data to their cloud. I don’t love that.

So I built **Webcatch** — a webhook inspector that runs entirely on your machine. One Docker command, zero data leaves your server.

**Why it might matter to you:**
- **Privacy-first:** All data in SQLite. No telemetry. No accounts.
- **AI analysis:** Works with your local LLM (I use Ollama with Qwen). No OpenAI bills.
- **Schema inference:** Automatically figures out the JSON schema of your webhooks and validates new ones. Great for catching breaking changes.
- **Replay & proxy:** Resend any webhook, forward to your backend, transform payloads with a Python script before forwarding.
- **One container:** FastAPI + vanilla JS. No build step. No dependencies beyond Docker.

**Monetization:** $39 lifetime Pro license. No recurring revenue — I know, I know 😅 — but I wanted something I’d actually buy. If it grows I might add team/enterprise tiers.

**Stack:** Python, FastAPI, SQLite, vanilla JS, WebSocket.

Repo: https://github.com/webcatchdev/webcatch

Questions, feedback, or roasting welcome. What would make you switch from Hookdeck / Svix / Webhook.site?

---

## Reddit (r/selfhosted or r/webdev)

**Title (r/selfhosted):** Webcatch — Self-hosted webhook inspector with local LLM analysis and schema inference

**Body:**

I built a webhook capture tool that runs in a single Docker container. Everything stays local — SQLite storage, optional local LLM analysis, no accounts, no telemetry.

**Features:**
- Instant webhook URLs
- Live dashboard (WebSocket)
- Replay any webhook or bulk replay
- Forward to backends with Python transform scripts
- AI analysis via local LLM (Ollama, llama.cpp, vLLM)
- Auto schema inference + validation + OpenAPI export
- HMAC signature verification (Stripe, GitHub, Shopify)
- Export to Postman, cURL, CSV
- Webhook diff
- Custom responses, filter rules, retention limits

Free / $39 lifetime Pro.

GitHub: https://github.com/webcatchdev/webcatch

Curious if the selfhosted crowd finds the local LLM integration useful, or if that's just me being nerdy.

---

## Twitter / X Thread

**Tweet 1 (hook):**
Every webhook tool sends your data to the cloud. 

I built one that doesn't. 

Introducing Webcatch — self-hosted webhook capture, replay, and AI analysis. One Docker container. Zero data leaves your machine.

👇

**Tweet 2 (features):**
What it does:
🔒 Capture any webhook instantly
🔄 Replay with one click
🧠 AI analysis (local LLM, no API keys)
🧬 Auto schema inference + validation
📄 Export Postman / cURL / CSV
⚖️ Verify Stripe/GitHub/Shopify signatures

**Tweet 3 (tech):**
Stack: FastAPI + SQLite + vanilla JS. 

No build step. No dependencies. One container.

MIT licensed. Free or $39 lifetime Pro.

**Tweet 4 (CTA):**
If you debug webhooks and care about privacy, this is for you.

🐛 github.com/webcatchdev/webcatch

Star ⭐ if you dig it. Issues and PRs welcome.

---

## Product Hunt (Upcoming)

**Tagline:** Self-hosted webhook inspector with AI analysis — your data never leaves your machine

**Description:**
Webcatch is a privacy-first webhook capture and analysis tool that runs entirely on your own infrastructure. Create webhook URLs instantly, capture payloads in real-time, replay requests, analyze them with your local LLM, and export to Postman or cURL — all without sending a single byte to the cloud.

**Key features:**
- 🔒 100% self-hosted — SQLite, no telemetry, no accounts
- 🔄 Replay & bulk replay any captured webhook
- 🧠 Local LLM analysis (Ollama, llama.cpp compatible)
- 🧬 Auto schema inference + OpenAPI export
- 📄 Export to Postman collections, cURL scripts, CSV
- ⚖️ Signature verification for Stripe, GitHub, Shopify
- 🔧 Python transform scripts before forwarding
- 📊 Real-time WebSocket dashboard

**Maker comment:**
I built this because I was debugging Stripe webhooks and didn't want to paste potentially sensitive payment data into a cloud service. If you care about data privacy or work in regulated industries, Webcatch is designed for you.

---

## Email to newsletter / personal list

**Subject:** I built a webhook tool that doesn't spy on you

Hey,

Quick one: I built a tool for debugging webhooks that runs entirely on your machine. No cloud. No accounts. No "we may collect usage data."

It's called Webcatch. One Docker command and you have:
- Instant webhook URLs
- A live dashboard
- One-click replay
- AI analysis via your local LLM (I use Ollama)
- Auto schema inference
- Postman / cURL export

I use it for Stripe, GitHub, and Shopify webhooks. If you work with webhooks and care about privacy, check it out:

https://github.com/webcatchdev/webcatch

It's MIT licensed. Free forever, or $39 for Pro (unlimited history, bulk replay, team sharing).

Let me know what you think.

— webcatchdev
