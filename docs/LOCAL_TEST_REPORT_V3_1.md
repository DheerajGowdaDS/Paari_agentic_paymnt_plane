# Paari v3.1 — Local Test Report (raw evidence)

Captured on this machine, 2026-10-26 (IST). Python 3.11.8, system interpreter.
All runs are local; no real provider, no money, no trusted identity, no managed KMS.

## 1. Compile
```
python -m compileall -q app sdk scripts tests alembic llm_agent local_demo
→ clean (no output)
```

## 2. Full unit + integration suite (SQLite target, single process)
```
python -m pytest -q -rs
→ 363 passed, 3 skipped, 1 warning in 197.35s (0:03:17)
```
Skips (all platform/target-expected, not failures):
- `tests/test_postgres_migration.py` (2) — "this run targets 'sqlite'; PostgreSQL-only test."
- `tests/test_production_signing_key.py` (1) — "POSIX file permission semantics are not available on Windows."

Baseline was 354 passed / 3 skipped on v3.0; v3.1 adds 9 (2 new disposition
scenarios + 7 new resilience tests) → **363**.

## 3. PostgreSQL path (loopback Docker, `paari_demo_test`)
```
docker compose -f docker-compose.local.yml up -d
set TEST_DATABASE_URL=postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test
python -m pytest -q tests/test_postgres_migration.py
→ 2 passed
```
- `paari_demo` migrated to Alembic head `e6f7a8b9c0d1`; `alembic check` →
  "No new upgrade operations detected."
- Restart-persistence check (`.agnes/work/pg_restart_persistence.py`): a parent
  written on boot 1 is still present in PostgreSQL after the API restarts
  (`parent_authorities` status `ACTIVE`). No real credentials.

## 4. New v3.1 tests
```
python -m pytest tests/test_v31_resilience.py tests/test_local_demo_v3.py -q
→ 7 new resilience tests passed (concurrency-safe on SQLite; invariant pinned on PostgreSQL)
```
New: `test_single_use_reservation_admits_exactly_one`,
`test_concurrent_reservations_cannot_exceed_limit`, `test_double_consume_http_second_is_rejected`,
`test_duplicate_webhook_delivery_is_idempotent`, `test_timeout_uncertain_state_reconciles_to_paid`,
`test_uncertain_provider_amount_mismatch_is_not_settled`,
`test_audit_chain_intact_after_consume_and_reconcile`.

## 5. Offline SAFR verifier (fast)
```
python scripts/verify_local_demo.py
→ 10 dispositions PASS (incl. new deny_mandate_expired / deny_mandate_revoked → MANDATE_NOT_ACTIVE)
→ 3 lifecycle demos PASS (duplicate REJECTED, provider_timeout RECONCILED, service_restart RECOVERED)
→ "SAFR audit chain: 13 verified entries"
→ exit 0
```

## 6. Full verifier (two real-HTTP E2E demonstrations)
```
python scripts/verify_local_demo.py --full
→ [PASS] strict_payment: provider E2E reached simulated PAID with controls
→ [PASS] autonomous_payment: provider E2E reached simulated PAID with controls
→ exit 0 · "PAARI v3.1 LOCAL DEMONSTRATION CHECKS PASSED — NOT A PRODUCTION CERTIFICATION"
```

## 7. Portal live probes
- CSRF missing → 403; cross-origin → 403; valid → 200 (disposition + audit-chained).
- New `/api/lifecycle/{key}` → 200 for all three demos; unknown key → 404.
- Reviewer queue: wrong code → 403; correct code → `approved_preview` (not an authorization).

## Known limitations (not claimed as passing)
- Production PostgreSQL multi-process concurrency / fleet soak, WORM audit, real KYC/KYB,
  managed KMS/HSM, full SAFR conformance, and UAE legal/regulatory review remain open.
- A benign Windows teardown artifact appears in `--full` temp cleanup
  (`checks.sqlite3` briefly held); all 13 PASS lines and exit code 0 are recorded —
  it is not a check failure.
