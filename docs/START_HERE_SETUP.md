# Paari v3.7.1 — Two-Workspace Portal: Set Up & Use

Everything you need to run the backend + the two-workspace Product Portal
(Organization Portal **and** Paari Platform Console) on your own machine.

**What this is:** a FastAPI + SQLAlchemy + Pydantic governance layer between
AI agents and payment infrastructure. This package is a **local sandbox demo**
— no real money moves. Python 3.11.

---

## 0. Prerequisites
- **Python 3.11** (`python --version`)
- A terminal. On Windows use PowerShell or CMD.
- No Postgres needed — the demo runs on SQLite out of the box.

## 1. Install
```bash
# make a virtual environment
python -m venv .venv
# activate it
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

# runtime + portal dependencies
pip install -r requirements.txt
pip install -r requirements-portal.txt   # QR + SVG for the agent-card QR feature
```

## 2. Create your secrets (.env)
Copy the template and give each secret a strong, independent value
(each 32+ chars). Do NOT reuse one value across several keys.
```bash
copy .env.example .env            # Windows
# cp .env.example .env            # macOS / Linux
```
Then edit `.env` and replace every `replace-with-...` placeholder.
Minimal fields you must set for a working sandbox:

| Variable | Requirement |
|---|---|
| `PAARI_ENV` | `sandbox` |
| `PAARI_MODE` | `autonomous` |
| `PAARI_ADMIN_API_KEY` | independent random, 32+ chars — **this is the Platform Console key** |
| `PAARI_V36_KEY_ENCRYPTION_SECRET` | 32+ chars |
| `PAARI_V36_PII_HMAC_SECRET` | 32+ chars |
| `PAARI_V36_AUTH_SECRET` | **32+ chars (v3.6 sign-in fails closed if shorter)** |
| `PAARI_V37_DATA_ENCRYPTION_SECRET` | 32+ chars |

A fresh signing key is auto-generated on first boot at
`./paari_signing_key.pem` (sandbox) — no action needed.

## 3. Create the database schema
Tables are **never** created at import — you must migrate first:
```bash
python -m alembic upgrade head
```

## 4. Start the server
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Keep this running in one terminal.

## 5. Open the portal
```
http://127.0.0.1:8000/portal
```
Health check: `http://127.0.0.1:8000/portal/v1/health` → `{"status":"ok"}`

### Two workspaces
- **Organization Portal** (top nav): onboarding → parent sign-in → agent
  registry → **Payment tracker** → treasury → profile.
- **Paari Platform Console** (top nav): enter the `PAARI_ADMIN_API_KEY` to
  review onboarding, manage tenants, watch the agent fleet and run the
  cross-tenant payment tracker.

### Quick onboarding test
Use the **⚡ Autofill example data** buttons on the onboarding and agent forms
to fill everything, then submit. Approve the parent in the Platform Console,
sign in as the parent, register an agent, then run the agent payment-intent
step to see activity appear in the Payment tracker.

## 6. Run one agent payment request (optional simulation)
From a second terminal, with the server running, you can drive an agent
end-to-end. The reference SDK is in `sdk/paari_agent` (installed with the
package). A minimal flow:
1. Register an agent in the Organization Portal and download the **agent
   bootstrap** (private key + credential).
2. Use that bootstrap to call `PaariAgentClient.payment_intent(...)` — the
   request is governed, recorded, and appears in the tracker.

For a deterministic full E2E without a real LLM, run:
```bash
python scripts/autonomous_payment_e2e.py
```

---

## Notes & guardrails
- A `deny` on the Payment tracker is a **correct** governance outcome (e.g. a
  v3.6-enrolled agent with no approved provider). It is still recorded and
  visible.
- `PAID` is only ever set from a provider-confirmed capture, never from a
  client claim.
- This is a **partially verified local development release**, not a
  production-certified deployment. Keep the sandbox posture.

## File map
| Path | What it is |
|---|---|
| `app/` | FastAPI backend (routers, models, security, v3.6/v3.7) |
| `app/portal_extension.py` | Additive portal + Platform Console API |
| `paari_product_portal.html` | Two-workspace portal UI (served at `/portal`) |
| `docs/` | Integration guides + technical blueprint |
| `sdk/paari_agent/` | Reference external-agent SDK |
| `llm_agent/` | Client-side LLM harness |
| `scripts/` | E2E / demo / sandbox harnesses |
| `alembic/` | Migrations |
| `tests/` | Test suite |
