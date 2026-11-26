# Paari v3.1 — SAFR Local Completion & Validation Increment (development)

**Release type:** local development milestone, built from v3.0. No production
certification, real provider license, real KYC/KYB, managed KMS/HSM, or official
SAFR conformance claim. The original payment-governance and security checks remain
fail-closed. This increment completes the local SAFR demonstration, wires PostgreSQL
into the local acceptance path, and adds the missing acceptance-matrix scenarios and
their resilience tests.

## What was added / changed

### Phase 1 — PostgreSQL integration (P0)
- Documented + verified the loopback Docker PostgreSQL path
  (`docker-compose.local.yml`, DB `paari_demo` / test DB `paari_demo_test` on `:5439`).
- The two previously-skipped PostgreSQL tests (`tests/test_postgres_migration.py`)
  are now runnable against `paari_demo_test` via `TEST_DATABASE_URL`.
- Persistent-Postgres restart-persistence verified: a write on one API boot is still
  present on the next boot (data survives restart). No real provider credentials used.

### Phase 2 + 4 — Complete SAFR-governed workflows & dashboard
- **`local_demo/core.py`:** two new disposition scenarios — `deny_mandate_expired`
  and `deny_mandate_revoked` (→ DENY `MANDATE_NOT_ACTIVE`) — completing the "expired or
  revoked mandate" acceptance item.
- **`local_demo/core.py`:** three new **lifecycle demonstrations** driven by the
  *real* `app.transitions` state machine (no provider call, no money):
  - `duplicate_authorization` — single-use reservation admits exactly one consume; a
    replayed attempt is rejected before any second provider call (`REJECTED`).
  - `provider_timeout` — a timed-out submission leaves a non-terminal
    `PROVIDER_UNKNOWN`; reconciliation resumes and settles to `PAID` (`RECONCILED`).
  - `service_restart` — the persisted row + hash-chained audit are the recovery source;
    the reconciler resumes and settles idempotently without re-submitting (`RECOVERED`).
- **`local_demo/portal.py`:** new `POST /api/lifecycle/{key}` endpoint (CSRF-gated,
  audit-chained) and a `lifecycle` entry in `/api/catalog`; the critical design rule
  (preview/approval ≠ spend authority) is unchanged — every demo reports
  `provider_executed: False`.
- **`local_demo/static/index.html`:** a new "Payment lifecycle & resilience" section
  renders the three demos; the dashboard now covers agent/policy/review/audit plus the
  lifecycle outcomes.

### Phase 3 — Security & resilience tests (new `tests/test_v31_resilience.py`)
- `test_single_use_reservation_admits_exactly_one` — deterministic proof the atomic
  conditional update admits exactly one reservation of a `max_usage=1` authorization.
- `test_concurrent_reservations_cannot_exceed_limit` — 8 workers race the real update;
  at most one may win; the DB stays capped at 1 (safe under SQLite lock, invariant on
  PostgreSQL).
- `test_double_consume_http_second_is_rejected` — sequential double-consume is 409, one
  provider-transaction row.
- `test_duplicate_webhook_delivery_is_idempotent` — a repeated signed webhook is
  `duplicate_ignored`, settlement is not doubled.
- `test_timeout_uncertain_state_reconciles_to_paid` — timed-out submission →
  `PROVIDER_UNKNOWN` → reconciles to `PAID` with a corroborating provider read.
- `test_uncertain_provider_amount_mismatch_is_not_settled` — a value mismatch in the
  reconciling read is held in `PROVIDER_UNKNOWN`, never settled.
- `test_audit_chain_intact_after_consume_and_reconcile` — the audit hash chain links
  across consume + reconciliation.

### Phase 5 — Validation & packaging
- `scripts/verify_local_demo.py` now exercises the two new disposition scenarios and the
  three lifecycle demos (13-entry local audit chain) before running the two real-HTTP E2Es.
- `docs/SAFR_REQUIREMENT_TRACEABILITY_V3_1.md` — requirement-to-test mapping for all four
  SAFR components and all eight acceptance scenarios (marking what v3.1 added).

## Verified on this machine (local, SQLite + loopback PostgreSQL)
- `python -m compileall -q app sdk scripts tests alembic llm_agent local_demo` — clean.
- `python -m pytest -q -rs` — **363 passed, 3 skipped, 0 failed**
  (the 3 skips: 2 Postgres-only on a SQLite target, 1 POSIX-permission test on Windows).
- With `TEST_DATABASE_URL` pointed at loopback PostgreSQL: `tests/test_postgres_migration.py`
  — **2 passed**.
- `python scripts/verify_local_demo.py` — all 10 dispositions + 3 lifecycle demos + audit
  chain **PASS**.
- `python scripts/verify_local_demo.py --full` — both real-HTTP E2E demonstrations reach
  simulated `PAID` with controls (no real money).
- PostgreSQL restart-persistence check — PASSED.

See `docs/LOCAL_TEST_REPORT_V3_1.md` for raw output captures.

## Still out of scope for this local milestone
Real-money movement; real KYC/KYB identity providers; managed KMS/HSM signing;
independent security certification; production PostgreSQL multi-process concurrency
and fleet soak; WORM/immutable audit storage and retention; full SAFR conformance;
UAE legal/regulatory review; and partner sign-off. The bundled fake identity adapter and
local signing key remain development fixtures.
