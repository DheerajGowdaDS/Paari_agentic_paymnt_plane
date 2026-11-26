# Paari v3.2 — Local Test Report (raw outputs)

Reproducible from source. Raw captures live in `.agnes/work/v32_*.txt`.
Targets: Docker loopback Postgres `127.0.0.1:5439` (user `paari` /
`paari-local-only`, databases `paari_demo` + `paari_demo_test`). The E2E harnesses
point at the disposable `paari_demo_test`; the demo UI runs on `:8000` (API) +
`:8765` (portal).

---

## 1. Compile (whole source tree)

`python -m compileall -q app sdk scripts tests alembic llm_agent local_demo` →
clean, exit 0 (no output). Confirmed in `scripts/accept_v32.py` step 1.

## 2. Offline SAFR verifier (incl. v3.2 guided workflows)

`python scripts/verify_local_demo.py` → **clean exit, no teardown traceback**
(the v3.1 `PermissionError ... being used by another process` is gone).
Verbatim tail:
```
[PASS] auto_execute: AUTO_EXECUTE ALL_MANDATORY_CONTROLS_PASSED
[PASS] observe: OBSERVE RISK_OBSERVATION_THRESHOLD
[PASS] escalate: ESCALATE RISK_ESCALATION_THRESHOLD
[PASS] deny_limit: DENY FINANCIAL_LIMIT_EXCEEDED
[PASS] deny_identity: DENY AGENT_NOT_ACTIVE
[PASS] deny_grant: DENY AGENT_RESOURCE_ACCESS_MISSING
[PASS] deny_signature: DENY ENVELOPE_ORIGIN_OR_INTEGRITY_INVALID
[PASS] escalate_evidence: ESCALATE EVIDENCE_QUALITY_BELOW_THRESHOLD
[PASS] deny_mandate_expired: DENY MANDATE_NOT_ACTIVE
[PASS] deny_mandate_revoked: DENY MANDATE_NOT_ACTIVE
[PASS] duplicate_authorization: lifecycle demo REJECTED (PASS)
[PASS] provider_timeout: lifecycle demo RECONCILED (PASS)
[PASS] service_restart: lifecycle demo RECOVERED (PASS)
[PASS] SAFR audit chain: 13 verified entries
[PASS] full_workflow: guided SAFR workflow PASS (5/5 stages)
[PASS] escalation_simulate: human-escalation lifecycle PASS (4/4 cases)
[PASS] guided-workflow audit chain: 6 verified entries
PAARI v3.2 LOCAL DEMONSTRATION CHECKS PASSED — NOT A PRODUCTION CERTIFICATION
```

## 3. Postgres-gated hardening tests

`TEST_DATABASE_URL=postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test
python -m pytest -q tests/test_v32_pg_hardening.py tests/test_v31_resilience.py` →
**12 passed** (5 new + 7 v3.1). On a SQLite target all 5 `test_v32_pg_hardening`
tests **skip** with the Postgres-first sentinel (that is the by-design behaviour,
and `accept_v32.py` rejects a skipped run when it expects Postgres).

## 4. Postgres-first E2E (verbatim, `.agnes/work/v32_pg_e2e.txt`)

```
[PASS] 0. server healthy on Postgres: {... "database": "up", "mandate_mode": "standard" ...}
[PASS] 1. agent delegated + authenticated over /v1
[PASS] 2. signed user mandate accepted on Postgres
[PASS] 2b. forged/tampered mandate signature rejected: {"http": 400}
[PASS] 3. agent reads active user authority
[PASS] 4. governance ALLOW under signed mandate
[PASS] 5. bounded authorization consumed -> PROVIDER_SUBMITTED: {"state": "PROVIDER_SUBMITTED", "order_id": "order_SIM00001"}
[PASS] 6. signed capture webhook applied -> PAID (corroborated): {"http": 200, "body": {"status": "applied", "state": "PAID"}}
[PASS] 6b. duplicate webhook delivery is idempotent (no double settle): {"http": 200, "body": {"status": "duplicate_ignored"}}
[PASS] 6c. forged webhook signature rejected: {"http": 401}
[PASS] 7. reconciliation confirms terminal PAID: {"reconcile": {"status": "terminal", "state": "PAID"}}
[PASS] 8. audit chain verified through PAID on Postgres
[PASS] 9. settlement provenance is the local simulator (never a real provider): {"final_state": "PAID", "settlement_source": "simulator"}
[PASS] 10. concurrent authorization attempts: exactly one reservation wins on Postgres: {"codes": [200, 409, 409, 409, 409, 409, 409, 409], "winners": 1}
PAARI v3.2 POSTGRES-FIRST E2E GREEN
```

## 5. Actual-recovery E2E (verbatem, `.agnes/work/v32_recovery.txt`)

```
[PASS] B1. consume -> PROVIDER_SUBMITTED before the failure: {"state": "PROVIDER_SUBMITTED"}
[KILL] terminating the Paari server and the provider stub at PROVIDER_SUBMITTED (the service failure)
[PASS] B2. reconcile after service failure reaches terminal PAID: {"reconcile": {"status": "terminal", "state": "PAID"}}
[PASS] B2b. no duplicate provider execution (exactly one txn, order id unchanged, one submit): {"provider_txn_rows": 1, "order_id": "order_SIM00001", "expected_order": "order_SIM00001", "order_submit_events": 1}
[PASS] B2b. no duplicate provider execution (order id unchanged, settled once): {"final_state": "PAID", "settlement_source": "simulator"}
[PASS] B2c. audit chain intact across the restart
PAARI v3.2 RECOVERY E2E GREEN
```
(Note the `[KILL]` line names the failure point. The "FAILURE" word in the
summary banner is the label for *the simulated service failure*, not a test
failure.)

## 6. New local-workflow tests

`python -m pytest -q tests/test_v32_local_workflows.py` → **3 passed**
(catalog advertises both guided workflows; `full_workflow` walks all 5 stages
and appends a verifiable audit event; `escalation_simulate` covers missing
authority / single resolve / approve / deny, `provider_executed` always False).

## 7. Full suite (SQLite target) — verbatim summary (`.agnes/work/v32_full.txt`)

```
SKIPPED [2] tests\test_postgres_migration.py:31: this run targets 'sqlite'; PostgreSQL-only test.
SKIPPED [1] tests\test_production_signing_key.py:23: POSIX file permission semantics are not available on Windows
SKIPPED [5] tests\test_v32_pg_hardening.py:33: Postgres-first hardening test; this run targets 'sqlite'.
366 passed, 8 skipped, 1 warning in 180.77s (0:03:00)
```
Delta vs v3.1 baseline (363/3): **+3** = the 3 new local-workflow tests; the
5 new Postgres-gated tests skip on SQLite by design and execute under Postgres
(§3, §gate). **0 failures.**

## 8. One-command acceptance gate

`python scripts/accept_v32.py` → **PAARI v3.2 ACCEPTANCE GREEN** (Postgres steps
genuinely executed; `.agnes/work/v32_accept.txt`). Step order: compileall →
offline verifier (with guided workflows) → Postgres-gated tests
(`TEST_DATABASE_URL` set, `SKIPPED` sentinel rejects a false green) →
`pg_e2e_workflow.py` → `recovery_e2e.py`. `--no-pg` skips the PG steps and
reports them SKIPPED, not failed.

## 9. Known limitations / honest scope

- **Windows teardown (Medium gap) — now closed.** The v3.1 post-check
  `PermissionError [WinError 32] ... checks.sqlite3 ... being used by another
  process` was a real artifact: `sqlite3.Connection` as a context manager does
  **not** close the OS handle, so `TemporaryDirectory` cleanup failed after every
  check had already passed. Fixed at the root in `EvidenceStore` and `ReviewQueue`
  (explicit connect/commit/close per call). The verifier now exits cleanly.
- **Recovery experiment scope.** Two-process kill on one node; proves
  persistence + no-duplicate-execution across a service restart. It does **not**
  claim multi-node crash tolerance or provider-side crash recovery.
- **Postgres concurrency** is a targeted multi-worker race on one disposable DB
  (16 connections in the test, 8 HTTP workers in the E2E); not a soak/saturation
  test.
- **External integrations remain outstanding** (Later gap): real KYC/KYB,
  managed KMS/HSM, live autonomous rails, regulatory review. No SAFR
  certification is claimed; the envelope endpoint stays validation-only.
- Every settlement in this increment is the local simulator
  (`settlement_source == "simulator"`); no real money moved.

## 10. Replication

```
docker compose up -d local-postgres            # or the :5439 loopback you already run
python -m pytest -q -rs                        # SQLite target: 366/8
SET TEST_DATABASE_URL=postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test
python -m pytest -q tests/test_v32_pg_hardening.py tests/test_v31_resilience.py -rs
python scripts/accept_v32.py                   # one-command gate (PG steps run when PG is up)
```
Never run two pytest processes at once in this repo (shared
`./.phase5_test.db` → Windows lock `PermissionError` that masquerades as a
regression).
