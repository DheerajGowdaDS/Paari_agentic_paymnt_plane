# Paari v3.7.1 — Live Demonstration Report

**Date:** 2026-11-03
**Goal (from the demo guide):** prove each of the recommended demonstration
scenarios live against the local sandbox, using Docker Desktop for services, and
report what worked, what failed, and what was fixed.

**Headline:** All twelve guide scenarios were exercised for real on the strict
local stack (stateful PostgreSQL + Provider simulator + SAFR + receiver &
federation enforcement). Automated verification is green. The sandbox remains a
**partially verified local development release — not a production-certified
financial service.** No real money moved at any point; every `PAID` result is
simulated settlement evidence.

---

## 1. What is running

| Component | Where | Notes |
|---|---|---|
| Paari backend (FastAPI + SQLAlchemy) | Docker `app` container, port 8000 | DB = named volume `postgres_data` |
| PostgreSQL 16 | Docker `db` service | app + demo data |
| Local PostgreSQL for tests | Docker `local-postgres`, port 5439 | `paari_demo` / `paari_demo_test` |
| Provider simulator (`stub_razorpay.py`) | host, dynamic port | Local stand-in only |
| Strict local stack (strict SAFR) | host uvicorn (fresh each run) | Used for the 12-scenario rehearsal |
| Organization Portal / Paari Console / Docs | served at `/organization`, `/console`, `/docs` | 200 on both, same back-end |

---

## 2. Defects found and fixed (this session)

Code/deploy fixes made in this session (all covered by tests or live runs):

| # | Defect | File(s) changed |
|---|---|---|
| 1 | `docker-compose.yml` never forwarded the v3.6/v3.7 secrets; onboarding 503'd | `docker-compose.yml` |
| 2 | Docker image lacked `qrcode`; Agent-Card QR 503'd | `Dockerfile` (installs `requirements-portal.txt`) |
| 3 | Agent Card signed non-serialized bytes (`+00:00` vs `Z`); public verification always failed | `app/routers/agents.py` (+ regression test) |
| 4 | `/v1/payments/intent` crashed HTTP 500 for v3.6 agents (`provider_id` absent on v1 model) | `app/schemas.py`, `app/v36/provider_policy.py` |
| 5 | Delegation record bootstrapped without the tenant's `org_id` (`default` fallback) → SAFR ingress found nothing | `app/routers/agents.py` |
| 6 | Review-release opt-in existed in checks but **no org could ever set it** (unreachable path) | `app/control_plane/schemas.py`, `app/control_plane/router.py` (`allow_signed_review_release`, default off) |
| 7 | Windows-scratch-file unlink crashed the strict harness | `scripts/llm_agent_e2e.py` |
| 8 | Stale test asserted `/console` must not exist (contradicted shipped portal) | `tests/test_backend_only_api.py` |
| 9 | Pre-existing Postgres volume held an old password | rotated in-place (non-destructive) |
| 10 | v3.7.1 two-workspace portal + Docker deployment verified; no external rails changed | — |

Two regression tests were added in `tests/test_v371_portal_regressions.py`
(card signature over serialized bytes; `/v1` provider gate denies instead of 500,
asserting Governed DENY + NULL authorization).

---

## 3. Twelve demo scenarios — live results

Run on the strict stack against PostgreSQL + provider simulator
(`scripts/ceo_demo_run.py`), plus the Docker walk-through
(`scripts/portal_walkthrough_check.py`) on the public HTTP surfaces.

| # | Scenario | Result |
|---|---|---|
| 1 | Parent onboarding → pending | PASS (record created, console queue lists it) |
| 2 | Administrator approves → tenant provisioned → parent login | PASS (Overview shows org) |
| 3 | Agent registration → Agent Card | PASS (signature_valid=True on public verify) |
| 4 | Valid payment, AUTO_EXECUTE | PASS (AUTO_EXECUTE → envelope → consume → order → webhook → reconcile → **PAID**) |
| 5 | OBSERVE at 75 % of delegated limit | PASS (allow; `OBSERVE` persisted in decisions for the intent) |
| 6 | SAFR ESCALATE → **parent rejects** | PASS (REVIEW queue → deny; `authorization_issued=false`; agent retrieve → 409) |
| 7 | SAFR ESCALATE → **parent approves** | PASS (REVIEW → allow, bounded authorization issued; agent retrieves it; consumed; order created) |
| 8 | Over-limit (₹60,000 on ₹50,000 limit) | PASS (DENY before any provider submission) |
| 9 | Replay defence | PASS (first consume 200; second 409) |
| 10 | Agent revocation | PASS (revoked agent → HTTP 401 / cannot pay) |
| 11 | 100-agent treasury fleet | PASS (100 agents registered; portfolio inventory + signals readable) |
| 12 | Receiver restrictions + provider recovery | PASS (unregistered/blocked receiver DENY pre-authorization; kill/restart recovery run → PAID, one order, audit intact) |

**Live rehearsal checks: 31 / 31 PASS.**

---

## 4. Automated verification

| Check | Result |
|---|---|
| Full SQLite suite (after fixes) | **506 passed, 22 skipped, 0 failed** |
| PostgreSQL migration suite | **2 passed** |
| PostgreSQL resilience + hardening | **13 passed** |
| Focused policy/governance modules | **56 passed** |
| `scripts/verify_local_demo.py --full` | PASS (13 scenarios + 3 lifecycle demos; both providers E2Es) |
| `scripts/safr_disposition_coverage.py` | PASS (AUTO_EXECUTE / OBSERVE / ESCALATE / DENY; PAID baseline) |
| `scripts/recovery_e2e.py` (Postgres) | PASS (kill/restart mid-flight; PAID; exactly one order; audit chain verified) |
| `scripts/llm_agent_e2e.py --strict-control-plane --execute-stub` | PASS (exit 0) |
| `scripts/v37_treasury_100_agents_demo.py --count 100` | PASS (100/100 registered; keys discarded) |
| Docker portal walk-through | PASS 20/20 |
| `alembic check` | `No new upgrade operations detected` on SQLite **and** Postgres |
| `compileall` | PASS |

Expected skips (environment-dependent): 13 PQC tests (`liboqs-python` absent),
8 Postgres-only (covered by the Postgres CI job), 1 Windows POSIX, 2 Postgres
migration checks.

---

## 5. CEO-ready 20-minute flow

Use this order to show value fast (all verified live on this machine):

1. `/organization` — submit sandbox org; show **pending** in `/console` (Test 1).
2. `/console` — approve; provision tenant; `/organization` sign-in (Test 2).
3. `/organization` — register procurement agent; open public card verification (Test 3).
4. `AUTO_EXECUTE` payment → audit shows ALLOW → envelope → consume → **PAID (simulated)** (Test 4).
5. `OBSERVE` payment (≈75 % of limit) → tracker shows monitor disposition (Test 5).
6. `ESCALATE` payment → parent **rejects** in `/organization` → DENY, no authorization (Test 6).
7. Another `ESCALATE` → parent **approves** (org has opted in to signed review release) → agent retrieves the bounded authorization itself (Test 7).
8. ₹60,000-on-₹50,000 → DENY before provider; replay blocked (Tests 8–9).
9. 100-agent treasury → fleet exposure + risk signals (Test 11).
10. Audit chain + proof bundle open at the end (accountability).

---

## 6. Honest limits

- `PAID`/capture here witness the **local provider simulator**, not real settlement.
- Review release of a held ESCALATE is **opt-in per organization**
  (now configurable via `POST /control/v1/policies` with
  `allow_signed_review_release: true`; default off, fail-closed).
- The v3.6 parent mandate is created/updated through the parent's session;
  USER federation agreements must be signed by a distinct payer keypair
  (as implemented by the payer/bootstrap path), never the browser's
  authorization token.
- No KYC/KYB, managed keys, MFA, QRNG budgets, bank adapters, or live provider
  quotas are exercised; production gates remain enforced (`/health/ready`=503
  is the correct, expected state).
- Enterprise ceilings count **reserved non-denied intents**, not cleared balances.
