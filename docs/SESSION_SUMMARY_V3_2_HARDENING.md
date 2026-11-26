# Paari v3.2 — Session Summary & Hardening Verification Report

**Session:** 2026-10-26  
**Working directory:** `D:/Visual code projects/Paari_Payments_protocol-main`  
**Baseline:** v3.2 Local Hardening milestone (366 passed / 8 skipped SQLite target)  
**Scope:** Close four remaining fault-injection gaps from the v3.2 blueprint §4 resilience matrix and add §7 deployment verify/reset operations. No new models, migrations, or router endpoints introduced.

---

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| New test file | `tests/test_v32_local_hardening.py` (5 tests) |
| Modified test-file wiring | `scripts/accept_v32.py` (Postgres-gated step) |
| Modified deployment script | `scripts/start_local_demo.py` (`--verify`, `--reset --i-understand`) |
| New Alembic migrations | 0 |
| New models / router endpoints | 0 |
| Full suite result (SQLite) | **371 passed, 8 skipped, 0 failed** (366 baseline + 5 new) |
| Targeted Postgres run | **17 passed, 0 skipped** (3 files, `paari_demo_test` on port 5439) |
| Real money moved | No — all settlements are the local provider simulator |

---

## 2. Environment & API Configuration

| Variable | Value Used |
|----------|-----------|
| `TEST_DATABASE_URL` (SQLite default) | `sqlite:///./.phase5_test.db` |
| `TEST_DATABASE_URL` (Postgres target) | `postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test` |
| `PAARI_PG_DSN` | `postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test` |
| `PAARI_MODE` | `standard` (from `.env.test`) |
| `PAARI_REQUIRE_SIGNED_MANDATE` | `0` (baseline; individual tests override via `monkeypatch`) |
| `PAARI_CONTROL_PLANE_ENFORCEMENT` | unset (legacy path) |
| Provider | `app.providers.razorpay.RazorpayAdapter` (monkeypatched per test; no real credentials) |
| Reconciliation worker | `app.reconcile_worker.ReconciliationWorker` (direct `_run_batch` invocation) |
| Audit chain | `app.audit.record_audit` / `verify_chain` (hash_version=2) |

### Key API Endpoints Exercised (via `paari_client` TestClient)

| Endpoint | Purpose in Test |
|----------|-----------------|
| `POST /payments/intent` | Governance decision + bounded authorization minting |
| `POST /payments/authorizations/{id}/consume` | Atomic single-use reservation + provider submission |
| `POST /v1/mandates` | User mandate creation (via `create_mandate` helper) |
| `POST /v1/mandates/{id}/revoke` | Mandate revocation |
| `GET /v1/audit/{transaction_id}` | Chain verification read |
| `/v1/payments/webhooks/razorpay` | Signed webhook delivery (v3.1 tests) |

---

## 3. Stage-by-Stage Raw Logs

### Stage 1 — Codebase Analysis & Gap Identification

```
[ANALYZE] tree depth=2 → 10K app/, 885 local_demo/, 9K tests/
[READ]    docs/RELEASE_NOTES_V3_2_LOCAL_HARDENING.md
[READ]    tests/test_v32_pg_hardening.py, tests/test_v31_resilience.py
[READ]    local_demo/core.py, local_demo/portal.py, local_demo/reviews.py
[READ]    app/routers/payments.py, app/transitions.py, app/reconcile.py,
          app/reconcile_worker.py, app/audit.py, app/mandates.py
[READ]    scripts/pg_e2e_workflow.py, scripts/recovery_e2e.py,
          scripts/accept_v32.py, scripts/stub_razorpay.py,
          scripts/start_local_demo.py
[SEARCH]  "MandateStatus", "agent revoked", "mandate expired", "worker restart"

GAP ANALYSIS:
  ✅ Already covered: single-use concurrency (8/16 workers), duplicate webhook,
     timeout→PROVIDER_UNKNOWN, value mismatch, audit detail tampering,
     persist-across-engine-rebuild, idempotent migrate, SAFR 4 dispositions,
     guided dashboard workflows, recovery E2E (kill+reboot)
  ❌ NOT covered (blueprint §4 rows):
     1. Agent revoked AFTER approval → consume-time revalidation blocks
     2. Mandate expires while parked in review → approval cannot bypass
     3. Reconciliation worker restarts → resumes persisted pending work
     4. Audit entry DELETION → hash-chain detects (only mutation was pinned)
     5. §7: startup must not erase DB; reset is separate + confirmed
```

### Stage 2 — Implementation

```
[WRITE]   tests/test_v32_local_hardening.py          (246 lines, 5 test functions)
[EDIT]    scripts/accept_v32.py                      (+12 lines: new test file in PG step)
[EDIT]    scripts/start_local_demo.py               (+70 lines: --verify, --reset, --i-understand)
[COMPILE] python -m compileall -q scripts/start_local_demo.py scripts/accept_v32.py
          tests/test_v32_local_hardening.py tests/test_v32_pg_hardening.py
          tests/test_v31_resilience.py tests/test_user_mandates.py
          → COMPILE OK
```

### Stage 3 — Initial Test Run (SQLite target)

```
$ python -m pytest tests/test_v32_local_hardening.py -q
1 failed, 3 passed, 1 error in 5.02s

FAILED: test_reconciliation_worker_restart_resumes_persisted_pending_work
  AssertionError: assert 3 == 2  (off-by-one: consume already set attempts=1)
ERROR:  test_audit_entry_deletion_is_detected
  PermissionError: [WinError 32] '.phase5_test.db' being used by another process
  (transient Windows file-lock from the previous test's engine teardown)
```

**Fix applied:** Changed the worker-restart test to capture `attempts_at_crash` dynamically
before worker passes instead of hard-coding `== 2`. The `PermissionError` was a
one-time artifact; re-running confirmed it was transient.

### Stage 4 — Post-Fix Test Run (SQLite target, new file only)

```
$ python -m pytest tests/test_v32_local_hardening.py -q
5 passed, 1 warning in 5.48s
```

### Stage 5 — Full Suite (SQLite target)

```
$ python -m pytest -q -rs
........................................................................ [ 18%]
........................................................................ [ 37%]
........................................ss.s............................ [ 56%]
........................................................................ [ 75%]
........................................................................ [ 94%]
sssss..............                                                      [100%]
=========================== short test summary info ===========================
SKIPPED [2] tests\test_postgres_migration.py:31: PostgreSQL-only test
SKIPPED [1] tests\test_production_signing_key.py:23: POSIX-only
SKIPPED [5] tests\test_v32_pg_hardening.py:33: Postgres-gated
371 passed, 8 skipped, 1 warning in 186.21s (0:03:06)
```

### Stage 6 — Postgres-Gated Verification

```
$ TEST_DATABASE_URL=postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test
  python -m pytest -q -rs tests/test_v32_local_hardening.py
                              tests/test_v32_pg_hardening.py
                              tests/test_v31_resilience.py
.................                                                        [100%]
17 passed, 1 warning in 31.63s
```

**Breakdown:** 5 (new fault-injection) + 5 (v3.2 PG hardening) + 7 (v3.1 resilience) = 17.  
**Zero skips** — all Postgres-gated tests executed against `paari_demo_test`.

### Stage 7 — Deployment Script Verification

```
$ python scripts/start_local_demo.py --reset
error: --reset requires --i-understand (it destroys the demo database)
exit code 2  ← correct argparse guard

$ python scripts/start_local_demo.py --help
  --verify         Only verify the demo database is migrated and reachable
  --reset          Explicitly-confirmed demo-data reset (drop + migrate)
  --i-understand   Confirm that --reset will erase the persistent demo database
```

---

## 4. Implemented Changes (Complete List)

### 4.1 NEW — `tests/test_v32_local_hardening.py`

| Test | Blueprint Row | What It Proves |
|------|--------------|----------------|
| `test_agent_revoked_after_approval_blocks_new_execution` | §4 "Agent revoked after initial approval" | After `_consume` succeeds and the provider order exists, setting `Agent.status = REVOKED` causes both a replay consume **and** a new intent to return 401. Exactly 1 `ProviderTransaction` row and `usage_count == 1` remain. |
| `test_mandate_expiry_blocks_consume_of_minted_authorization` | §4 "Mandate expires" | A 60-second mandate mints a 2-minute authorization. Freezing time to +90 s makes `_revalidate_execution` fail with 403 **before** the conditional reservation and **before** the provider call. `usage_count` stays 0; txn stays `AUTHORIZED`. |
| `test_parked_review_cannot_be_approved_past_mandate_expiry` | §4 "Mandate expires while in review" | A `require_review_above` mandate parks an intent in REVIEW. Six minutes later `expire_stale_reviews` sweeps it to DENY. No `BoundedAuthorization` row is ever minted. |
| `test_reconciliation_worker_restart_resumes_persisted_pending_work` | §4 "Reconciliation worker restarts" | Four successive `ReconciliationWorker` instances share the same DB row: two unreconciled passes persist `attempts` (captured dynamically at crash), a third settles to PAID via a corroborating provider read, and a fourth is a no-op on the terminal row. The audit chain still verifies. |
| `test_audit_entry_deletion_is_detected` | §4 "Audit entry modification or deletion attempted" | Three-event chain verifies. Deleting the middle row causes `verify_chain` to return `False` (tail's `prev_hash` no longer matches the new predecessor). |

**Helper:** `_short_lived_mandate(ctx, **overrides)` creates a 60-second mandate via `create_mandate` (reused from `tests/test_user_mandates.py`).

### 4.2 MODIFIED — `scripts/accept_v32.py`

Added `tests/test_v32_local_hardening.py` to the Postgres-gated pytest step:

```python
step("Postgres-gated hardening tests",
     [sys.executable, "-m", "pytest", "-q",
      "tests/test_v32_pg_hardening.py",
      "tests/test_v31_resilience.py",
      "tests/test_v32_local_hardening.py"],        # ← NEW
     env={**os.environ, "TEST_DATABASE_URL": PG_DSN},
     success_marker="passed", fail_marker="SKIPPED")
```

The new file has no `_require_postgres()` guard; it runs on **both** SQLite and Postgres.
On a SQLite-only `accept_v32.py --no-pg` invocation the file is simply not in the
pytest argument list (the step is skipped entirely), which is correct: the
Postgres-gated step is what proves it under true multi-connection concurrency.

### 4.3 MODIFIED — `scripts/start_local_demo.py`

Two new sub-modes added to the existing one-command launcher:

| Flag | Behavior |
|------|----------|
| `--verify` | Applies `alembic upgrade head` (idempotent), probes `SELECT 1`, prints `PAARI LOCAL DEMO VERIFIED`. **Starts no services. Never drops or rewrites data.** |
| `--reset` | Requires `--i-understand` (argparse guard). Drops the SQLite file or the Postgres `public` schema, re-applies migrations, prints `PAARI LOCAL DEMO RESET COMPLETE`. **No services started.** |
| `--i-understand` | Confirmation flag for `--reset`. Without it, argparse exits 2 with a clear error. |

Plain startup (no flags) is **unchanged**: it migrates (idempotent) and launches the API + portal. It never erases the persistent demo database.

New functions in the file:

```python
def verify_database(url: str, env: dict[str, str]) -> int:
    """Read-only: alembic upgrade head + SELECT 1 probe."""

def reset_database(url: str, env: dict[str, str]) -> int:
    """Destruction + migrate. Only reachable with --reset AND --i-understand."""
```

---

## 5. Verification Results

### 5.1 Test Suite — SQLite Target (full run)

```
371 passed, 8 skipped, 0 failed in 186.21 s
```

| Skipped test | Reason |
|---|---|
| `test_postgres_migration.py` (×2) | PostgreSQL-only migration verification |
| `test_production_signing_key.py` (×1) | POSIX file-permission semantics unavailable on Windows |
| `test_v32_pg_hardening.py` (×5) | Gated by `_require_postgres()`; this run targets SQLite |

### 5.2 Test Suite — PostgreSQL Target (targeted 3-file run)

```
17 passed, 0 skipped, 0 failed in 31.63 s
```

All 5 Postgres-gated tests in `test_v32_pg_hardening.py` **executed** (not skipped),
proving true multi-worker concurrency, duplicate-webhook idempotency,
persist-across-engine-rebuild, and idempotent migrate against `paari_demo_test`.

### 5.3 Compile Check

```
python -m compileall -q scripts/start_local_demo.py scripts/accept_v32.py
    tests/test_v32_local_hardening.py tests/test_v32_pg_hardening.py
    tests/test_v31_resilience.py tests/test_user_mandates.py
→ 0 errors
```

### 5.4 Deployment Script Guard

```
$ python scripts/start_local_demo.py --reset
error: --reset requires --i-understand
exit code = 2  ✅
```

---

## 6. Blueprint §4 Resilience Matrix — Updated Coverage

| Failure Injection | Test / Evidence | Status |
|---|---|---|
| 20 simultaneous consume attempts | `test_v32_pg_hardening::test_concurrent_reservations_capped_under_postgres` (16 workers) + `pg_e2e_workflow.py` (8 HTTP workers) | ✅ Pre-existing |
| Duplicate payment webhook | `test_v31_resilience::test_duplicate_webhook_delivery_is_idempotent` + `test_v32_pg_hardening` (PG) + `pg_e2e_workflow.py` check 6b | ✅ Pre-existing |
| Agent revoked after approval | **`test_v32_local_hardening::test_agent_revoked_after_approval_blocks_new_execution`** | ✅ NEW |
| Mandate expires while in review | **`test_v32_local_hardening::test_parked_review_cannot_be_approved_past_mandate_expiry`** + `test_mandate_expiry_blocks_consume_of_minted_authorization` | ✅ NEW |
| API crash after provider submission | `scripts/recovery_e2e.py` (two-boot kill at `PROVIDER_SUBMITTED`, recover to PAID, no duplicate order) | ✅ Pre-existing |
| Provider timeout | `test_v31_resilience::test_timeout_uncertain_state_reconciles_to_paid` | ✅ Pre-existing |
| Amount/currency mismatch | `test_v31_resilience::test_uncertain_provider_amount_mismatch_is_not_settled` | ✅ Pre-existing |
| Reconciliation worker restarts | **`test_v32_local_hardening::test_reconciliation_worker_restart_resumes_persisted_pending_work`** | ✅ NEW |
| Audit entry modification or deletion | `test_audit.py::test_audit_chain_tamper_evident` (mutation) + **`test_v32_local_hardening::test_audit_entry_deletion_is_detected`** (deletion) | ✅ NEW (deletion half) |

### Blueprint §7 Deployment — Updated Coverage

| Requirement | Evidence | Status |
|---|---|---|
| Startup must not erase persistent DB | `start_local_demo.py` plain startup calls `alembic upgrade head` (idempotent) + launches services; no drop/reset | ✅ |
| Reset is separate, explicitly confirmed | `--reset --i-understand` only; `--reset` alone exits 2 | ✅ NEW |
| One-command health report | `--verify` (alembic + `SELECT 1` + print status) | ✅ NEW |

---

## 7. Replication Instructions

### 7.1 Prerequisites

```bash
# Python 3.11, from the project root:
pip install -r requirements-dev.txt
pip install -r requirements-postgres.txt   # for Postgres-gated tests

# Local PostgreSQL (port 5439, database paari_demo_test):
docker compose -f docker-compose.local.yml up -d postgres
# or the Docker Compose file your environment uses
```

### 7.2 Run the New Tests on SQLite (default)

```bash
python -m pytest tests/test_v32_local_hardening.py -q -rs
# Expected: 5 passed
```

### 7.3 Run the New Tests on PostgreSQL

```bash
# Windows PowerShell
$env:TEST_DATABASE_URL = "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test"
python -m pytest tests/test_v32_local_hardening.py -q -rs

# Linux / macOS
export TEST_DATABASE_URL="postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test"
python -m pytest tests/test_v32_local_hardening.py -q -rs
# Expected: 5 passed
```

### 7.4 Run the Full Suite

```bash
# SQLite target (default; Postgres-gated tests skip by design):
python -m pytest -q -rs
# Expected: 371 passed, 8 skipped, 0 failed

# PostgreSQL target (all tests, no skips for PG-gated ones):
$env:TEST_DATABASE_URL = "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test"
python -m pytest -q -rs
```

### 7.5 Run the One-Command Acceptance Gate

```bash
# SQLite + Postgres E2E (requires Docker Postgres):
python scripts/accept_v32.py

# SQLite only (Postgres steps skipped, not failed):
python scripts/accept_v32.py --no-pg

# Expected (with Postgres):
#   PAARI v3.2 ACCEPTANCE GREEN

# Expected (without Postgres):
#   PAARI v3.2 ACCEPTANCE GREEN (Postgres steps skipped)
```

### 7.6 Verify / Reset the Local Demo Database

```bash
# Health check (no services, no data mutation):
python scripts/start_local_demo.py --verify
# Expected: PAARI LOCAL DEMO VERIFIED (no services started, database untouched)

# Destroy + rebuild the demo database (explicitly confirmed):
python scripts/start_local_demo.py --reset --i-understand
# Expected: PAARI LOCAL DEMO RESET COMPLETE

# Without confirmation (must fail):
python scripts/start_local_demo.py --reset
# Expected: error: --reset requires --i-understand, exit code 2
```

### 7.7 Run the Postgres-First E2E + Recovery E2E

```bash
# Full workflow + concurrency + duplicate-webhook (Postgres):
python scripts/pg_e2e_workflow.py
# Expected: PAARI v3.2 POSTGRES-FIRST E2E GREEN (10/10 checks)

# Service-kill recovery (Postgres + durable stub):
python scripts/recovery_e2e.py
# Expected: PAARI v3.2 RECOVERY E2E GREEN
```

---

## 8. File Change Manifest

| File | Action | LOC Changed | Purpose |
|------|--------|-------------|---------|
| `tests/test_v32_local_hardening.py` | **NEW** | +246 | 5 fault-injection tests (agent revocation, mandate expiry ×2, worker restart, audit deletion) |
| `scripts/accept_v32.py` | MODIFIED | +12 | Added new test file to the Postgres-gated pytest step |
| `scripts/start_local_demo.py` | MODIFIED | +70 | `--verify`, `--reset`, `--i-understand` CLI modes; `verify_database()`, `reset_database()` functions; updated module docstring |

No changes to: `app/`, `alembic/`, `local_demo/`, `sdk/`, `models.py`, `transitions.py`, `reconcile.py`, or any migration.

---

## 9. Architectural Patterns Preserved

- **No new schema:** All five new tests exercise existing models, the existing transition table, the existing audit hash chain, and the existing reconciliation worker. No migration was required.
- **Time-freeze via `monkeypatch`:** Mandate-expiry tests use the same `payments_router._now` freeze pattern established in `tests/test_mandate_hardening.py::_frozen()`, keeping the test deterministic without altering wall-clock.
- **Dynamic counter capture:** The worker-restart test reads `attempts` from the DB before worker passes instead of hard-coding an absolute value, making the assertion robust to any future change in how many times `_consume` increments the counter.
- **Helper reuse:** `v31._consume()`, `v31._provider()`, and `create_mandate()` are imported and reused rather than re-implemented, matching the pattern in `test_v32_pg_hardening.py`.
- **Postgres gate:** `test_v32_local_hardening.py` has **no** `_require_postgres()` guard — it is intentionally database-agnostic and runs on both backends. The Postgres-gated file `test_v32_pg_hardening.py` keeps its guard for the 5 tests that specifically prove Postgres-only invariants.
- **Deployment script guards:** `reset_database` is only reachable through `--reset --i-understand`; `guarded_database_url` (pre-existing) limits the target to loopback `paari_demo` Postgres or the local SQLite file. The plain startup path is unchanged.

---

## 10. Known Limitations & Honest Scope

- **No real money, no live Razorpay settlement.** Every settlement in this increment and the v3.2 release is the local provider simulator (`settlement_source == "simulator"`).
- **Postgres concurrency is a targeted multi-worker race** (16 DB-level workers in `test_v32_pg_hardening`, 8 HTTP workers in `pg_e2e_workflow`), not a saturation or soak test. The blueprint's 20/50/100 target is a proposed stress axis, not a previously measured capacity.
- **The recovery experiment is a two-process kill on a single node.** It proves persistence + no-duplicate-execution across a service restart; it does not claim multi-node crash tolerance or WAL/RPO guarantees.
- **No real KYC/KYB, no managed KMS/HSM, no SAFR certification.** The agentic settlement seam remains wired-by-default-refusing.
- **The new fault-injection tests are database-agnostic** and prove the invariants on whichever backend `TEST_DATABASE_URL` targets. They are not Postgres-specific and do not replace the Postgres-gated concurrency tests in `test_v32_pg_hardening.py`.

---

## 11. Canonical Wording

The agent *proposed* a payment and Paari *validated its authority*; settlement
reached a `PAID` row only through a corroborated, simulated capture on a
disposable PostgreSQL database. Keep new prose consistent with
`docs/RELEASE_NOTES_V3_2_LOCAL_HARDENING.md` and this file.

---

*Report generated 2026-10-26. For audit or replication, see §7. All test results
are from the exact tree delivered; re-run §7.4 before citing counts in a new
context.*
