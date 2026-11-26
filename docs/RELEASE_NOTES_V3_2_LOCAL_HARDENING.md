# Paari v3.2 — Local Hardening & Full Workflow Acceptance

**Status:** Local completion milestone. Not a production certification.
**Baseline:** v3.1 (363 passed / 3 skipped / 0 failed, SQLite target).
**Scope:** Close the two High-priority local gaps called out in the v3.1 report,
complete the dashboard-driven SAFR acceptance, and make the local release
reproducible. Every change is pattern-adherent to the existing architecture and
weakens no production gate. No real money moves anywhere in this increment.

## What changed, by recommendation

The v3.1 hand-off named five improvements for "the next milestone, dedicated to
PostgreSQL concurrency, genuine restart/recovery experiments, and complete
dashboard-driven acceptance." v3.2 implements all five.

### 1. Postgres-first E2E (High gap: "PostgreSQL concurrency not fully validated")

`scripts/pg_e2e_workflow.py` boots the **real server** and the **local provider
stub** against a **disposable PostgreSQL database** (name ending `_test`, gated by
`app.database.assert_disposable_database_url`) and drives the full critical path:

    onboard -> signed user mandate -> governance ALLOW -> bounded single-use
    authorization -> consume (PROVIDER_SUBMITTED) -> stub capture -> signed
    capture webhook -> corroborated PAID -> reconciliation -> audited proof

Then, over the same real HTTP boundary, it proves the two Postgres-specific
invariants that SQLite could not: **8 real HTTP workers racing a single-use
authorization yield exactly one 200 and the rest 409**, and **duplicate webhook
delivery is `duplicate_ignored`** (no double settlement). 10 checks, all PASS.

### 2. Actual recovery testing (High gap: "lifecycle demos use stand-in
transactions, not complete persistent recovery through real service failures")

`scripts/recovery_e2e.py` drives the real app on a persistent Postgres DB and the
real durable-state provider stub, then **terminates both the server and the
provider while the row sits at `PROVIDER_SUBMITTED`** — a genuine service
failure, not a state-machine preview. It re-boots both on the same Postgres DB +
the same durable provider-state file, and proves the reconciler **resumes to PAID
from the persisted, corroborated record** with:

- exactly **one** `provider_transactions` row for the authorization,
- the **same** provider order id (no second submission),
- exactly **one** `order_submitted` audit event, and
- a hash-chained audit trail that still verifies across the restart.

The provider stub gained an opt-in durable state (`STUB_STATE_FILE`) so a
re-spawned simulator "remembers" its orders/payments, mirroring a real PSP's
server-side persistence. Default in-memory behaviour is unchanged.

### 3. Complete SAFR workflow demonstration (recommendation 3)

The portal now exposes two **guided, dashboard-driven** workflows that compose
the deterministic engine + the real transition table into one reproducible map,
each appending a verifiable audit event:

- `POST /api/full_workflow` — onboarding (signed envelope) → delegated mandate
  decision → governance across **all four SAFR outcomes** (AUTO_EXECUTE / OBSERVE
  / ESCALATE / DENY) → expiry/revocation fail-closed → authorized-execution +
  simulated-settlement lifecycle → tamper-evident audit proof. 5 stages.
- `POST /api/escalation/simulate` — the **human-escalation lifecycle**: missing
  authority refused, a review resolves exactly once, approve vs deny, and
  unanswered/missing-authority reviews fail closed. Approval **never confers
  payment authority** (documented in the response and the UI).

`local_demo/static/index.html` gained a "Complete SAFR workflow & human
escalation" section with two buttons; the new endpoints are advertised in
`/api/catalog`. `tests/test_v32_local_workflows.py` locks both.

### 4. Human escalation integration (recommendation 4)

Covered by the same escalation surface: reviewer **approve** and **deny**,
**expired** reviews (fail closed), **missing authority** (wrong code refused),
and the **mandatory fresh re-check** (a resolve re-evaluates the scenario and
downgrades an approval if it no longer escalates). The existing
`tests/test_local_demo_v3.py` already covered the direct `ReviewQueue` edges;
v3.2 adds the composed HTTP-driven proof.

### 5. Reproducible release (recommendation 5)

- **Version-controlled source:** the tree is a clean git baseline
  (`4f78d1a`, 273 tracked files, working tree clean). `.gitignore` was extended
  for the v3.2 scratch artifacts; the real `.env`, `data/`, `*.pem`, `*.db`, and
  `.agnes/` are all confirmed untracked — no key material or state is committed.
- **Automated CI:** `.github/workflows/ci.yml` now runs the Postgres-gated
  resilience + hardening tests against the Postgres service (they are skipped,
  not failed, on a plain SQLite run).
- **Clean-install checks + reliable Windows teardown:** the v3.1
  `PermissionError ... being used by another process` after the verifier's checks
  was fixed at the root — `EvidenceStore` and `ReviewQueue` now close their
  SQLite handles per call (a `sqlite3.Connection` used as a context manager only
  commits/rolls back; it never releases the OS handle, which is what blocked
  `TemporaryDirectory` cleanup on Windows). The verifier and the new guided-workflow
  checks now exit cleanly with no teardown traceback.
- **One-command local acceptance:** `scripts/accept_v32.py` runs compileall →
  offline SAFR verifier (policy + lifecycle + guided workflows) → Postgres-gated
  hardening tests (with `TEST_DATABASE_URL` pointed at Postgres and a skip
  sentinel so a SQLite run can't false-green) → Postgres-first E2E → recovery E2E.
  A step that can't run (no Docker) is SKIPPED, not failed; a step that runs
  must print its GREEN/PASS marker.

## New / changed files

| File | Type | Purpose |
|---|---|---|
| `scripts/pg_e2e_workflow.py` | NEW | Postgres-first full-workflow + concurrency + duplicate-webhook E2E. |
| `scripts/recovery_e2e.py` | NEW | Actual-recovery E2E: service kill at `PROVIDER_SUBMITTED`, re-boot, no-dup PAID. |
| `scripts/accept_v32.py` | NEW | One-command local acceptance gate (SQLite + optional Postgres). |
| `tests/test_v32_pg_hardening.py` | NEW | Postgres-gated: single-use, 16-worker concurrency, duplicate webhook, persist-across-rebuild, idempotent migrate. |
| `tests/test_v32_local_workflows.py` | NEW | Locks the two guided dashboard workflows + escalation lifecycle. |
| `scripts/stub_razorpay.py` | MOD | Opt-in durable state (`STUB_STATE_FILE`); default behaviour unchanged. |
| `local_demo/core.py` | MOD | `EvidenceStore` closes SQLite handles per call (Windows teardown fix). |
| `local_demo/reviews.py` | MOD | `ReviewQueue` closes SQLite handles per call (Windows teardown fix). |
| `local_demo/portal.py` | MOD | `POST /api/full_workflow` + `POST /api/escalation/simulate`; `workflows` in catalog; v3.2 branding. |
| `local_demo/static/index.html` | MOD | New guided-workflow/escalation section + JS; v3.2 rebrand. |
| `scripts/verify_local_demo.py` | MOD | Runs the two guided-workflow checks (separate store); clean exit. |
| `.github/workflows/ci.yml` | MOD | Postgres-gated hardening tests in CI. |
| `.gitignore` | MOD | v3.2 scratch-file block. |

## Verified results (this increment)

- **Postgres-gated hardening tests** (against `paari_demo_test`): **12 passed**
  (5 new `test_v32_pg_hardening` + 7 v3.1 `test_v31_resilience`).
- **Postgres-first E2E** (`scripts/pg_e2e_workflow.py`): **10/10 PASS**,
  8-worker concurrency → exactly one win; duplicate webhook → `duplicate_ignored`.
- **Recovery E2E** (`scripts/recovery_e2e.py`): **GREEN** — one provider txn,
  order id unchanged, one submit event, audit chain intact, recovered to PAID.
- **Offline verifier** (`scripts/verify_local_demo.py`): 10 dispositions + 3
  lifecycle + 13-entry chain **plus** the two guided-workflow checks, all PASS,
  clean exit (no `PermissionError`).
- **Full suite (SQLite target):** **366 passed, 8 skipped, 0 failed**
  (363 v3.1 baseline + 3 new local-workflow tests; 5 Postgres-gated tests skip on
  SQLite by design).
- **One-command gate** (`scripts/accept_v32.py`): **PAARI v3.2 ACCEPTANCE GREEN**
  (Postgres steps genuinely executed).

## Honest scope (unchanged and extended)

- Local/demo environment only. **No real money, no live Razorpay settlement.**
  Every settlement in this increment is the local provider simulator
  (`settlement_source == "simulator"`); a `PROVIDER_SUBMITTED`/`CAPTURED`/`PAID`
  row from a sim is not provider-side proof.
- The recovery experiment is a **two-process kill on a single node**, which
  proves persistence + no-duplicate-execution across a service restart; it does
  **not** claim multi-node crash tolerance, WAL/RPO guarantees, or provider-side
  crash recovery.
- **No real KYC/KYB**, **no managed KMS/HSM**, and **no SAFR certification**.
  The agentic settlement seam remains wired-by-default-refusing; nothing here
  claims a live autonomous settlement.
- Postgres concurrency here is a targeted multi-worker race on a single
  disposable DB — it closes the "not validated under multi-worker load" gap but
  is **not a soak or saturation test**.
- The guided dashboard workflows are **deterministic previews** of the engine +
  transition table; they are distinct from the two real-HTTP provider E2Es,
  which remain the only path that touches the wire. Preview/approval ≠ spend
  authority, and approval in the escalation flow never authorizes a payment.

**Canonical wording:** the agent *proposed* a payment and Paari *validated its
authority*; settlement reached a `PAID` row only through a corroborated,
simulated capture on a disposable Postgres database. Keep new prose consistent
with `docs/RELEASE_NOTES_V3_1_LOCAL_COMPLETION.md` and this file.
