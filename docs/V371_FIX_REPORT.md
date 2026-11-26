# Paari v3.7.1 — Stability Fixes and Verification Report

**Prepared:** 2026-10-29  
**Verification runtime:** Linux, Python 3.13.5, SQLite  
**Scope:** Source-level fixes based on the 2026-10-29 local setup handoff and Razorpay test-mode E2E reports.  
**Release status:** Improved local-development package; **not production-certified**.

## Summary of changes

1. **Migration test setup:** `test_migration_rewrites_pending_rows` now starts from the actual pre-migration revision (`b2c3d4e5f6a7`) and upgrades normally to head. It no longer stamps a head-schema SQLite database backward and then replays historical column-adding migrations.
2. **Denied-intent proof handling:** proof bundle assembly now supports denied intents that have no authorization record. An absent authorization serializes as `null` instead of causing an unexpected `AttributeError`/HTTP 500.
3. **PostgreSQL unique-constraint alignment:** added Alembic revision `e8f901234567`. On PostgreSQL it removes a targeted unique constraint only when an independent, non-partial unique index on the same single column remains, while preserving inbound FK names and actions when recreating those FKs. SQLite requires no DDL for this discrepancy. **The new migration was not executed against PostgreSQL in this environment; review and PG validation are still required before a release.**
4. **Health/readiness reporting:** `/health` reports the active mandate posture and receiver, federation, control-plane and SAFR enforcement flags. `/health/ready` is a separate strict readiness gate. Compose uses `/health` as its liveness check so an unconfigured provider can be live while readiness correctly remains blocked.
5. **HTTP hardening:** added `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer` response headers.
6. **Strict local E2E harness:** strict-mode setup creates synthetic receiver/beneficiary fixtures before the negative mandate probe, then creates scoped sender/user/receiver agreements and a transaction-bound SAFR envelope before the permitted test order. `--execute-stub` uses a local test stub and reports `PROVIDER_SUBMITTED`; it does not claim provider-native settlement or real payment. Replays are rejected and the over-cap proposal is denied.
7. **Test environment resilience:** post-quantum test modules skip cleanly when optional `liboqs-python` (`oqs`) is unavailable. The shared `paari_client` fixture explicitly closes `TestClient` objects; the independent-receiver acceptance test uses a one-request server and a bounded join.
8. **Docker/local configuration:** rewrote the Dockerfile as a multi-stage Python 3.11 image, with runtime dependencies only and a non-root `paari` user. The app is bound to host loopback in Compose; secrets are supplied by environment variables; strict control-plane, receiver, federation, signed-mandate and SAFR flags are enabled by default. `.env.example` contains placeholders, not credentials.
9. **Distribution hygiene:** the ZIP excludes `.env`, private signing keys, local databases, test logs, generated `evidence/` files, Python caches and `.pytest_cache`.

## Verification completed in this environment

| Check | Result | Notes |
|---|---|---|
| `python -m compileall -q app llm_agent scripts tests` | PASS | No syntax errors. |
| Focused migration/proof/webhook/security/health tests | PASS | 22 passed, including the formerly failing migration regression and denied-intent proof case. |
| `python -m pytest -q tests/test_e2e_mvp_acceptance.py` | PASS | 15 passed when run by itself. |
| `python -m pytest -q tests/test_v37_enterprise.py tests/test_v37_fleet_100.py` | PASS | 8 passed on the latest isolated run. |
| Strict LLM rehearsal with `--strict-control-plane --execute-stub` | PASS | Required control-plane, receiver, federation, signed-mandate and SAFR paths were exercised using synthetic local fixtures; one bounded order reached the local stub; replay returned HTTP 409; a 20×-over-cap proposal was denied. No real provider or money involved. |
| `python scripts/autonomous_payment_e2e.py` | PASS | Reference in-memory provider only; simulated settlement to `PAID`, replay rejected, audit chain verified. No real money moved. |
| Fresh SQLite Alembic `upgrade head` + `check` | PASS | `No new upgrade operations detected.` |
| `docker-compose.yml` and `docker-compose.local.yml` YAML parse | PASS | Parsed using PyYAML. Docker itself was not available, so Compose startup was not run here. |
| Post-quantum tests when `oqs` is absent | SKIPPED | `liboqs-python` is not installed in this environment; PQC operations are not validated by these skips. |

## Verification gaps / known limitations

- **The complete test suite is not certified green.** A combined multi-module run exceeded the execution window during the end-to-end acceptance sequence; the latest C14 phase log records its database/audit assertions as passed, but the combined pytest process did not finish cleanly. The acceptance module passes when run alone. Do not describe the entire suite as passing until this interaction/repeatability issue is resolved in CI.
- **PostgreSQL is unverified here.** This runtime has no Docker executable, PostgreSQL server/CLI or `psycopg` driver. The unique-constraint migration must be reviewed and run against a disposable PostgreSQL database, followed by `alembic check`, inbound-FK behavior tests and the PostgreSQL-specific migration/hardening suite.
- **Razorpay evidence is sandbox/test-mode only.** The supplied reports describe a test-mode order/payment and a signed webhook; they explicitly say identity/KYC, receiver, federation, SAFR and control-plane controls were bypassed in that run. The raw log also contains an initial attempt that remained `PROVIDER_SUBMITTED`; the later embedded report describes a successful test-mode attempt. These reports do not prove strict governance or live-money readiness.
- **Credentials in the supplied reports must be treated as exposed.** Rotate the Razorpay test API secret and webhook secret through the provider dashboard, update local configuration, and redact the credentials from logs or repository history where they were copied. The distributed ZIP deliberately contains no live `.env` or signing key.
- **Trusted identity and managed signing remain external requirements.** Synthetic test fixtures are not KYC/KYB evidence, and a local PEM signer is not a managed KMS/HSM signer. Strict production readiness must remain blocked until real trusted integrations are provisioned and verified.
- **Security scan scope is limited.** The supplied ZAP report noted missing security headers and timestamp disclosure. This update adds common response headers, but no complete security audit or fresh ZAP scan was performed as part of this package build.

## Suggested local verification commands

```powershell
python -m pytest -q tests/test_phase9_state_machine.py::test_migration_rewrites_pending_rows tests/test_proof_bundle.py tests/test_webhook_value_guard.py tests/test_security_headers.py tests/test_health.py
python -m pytest -q tests/test_e2e_mvp_acceptance.py
python -m pytest -q tests/test_v37_enterprise.py tests/test_v37_fleet_100.py
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
python scripts/autonomous_payment_e2e.py
```

For PostgreSQL, first create and select a disposable database whose name ends with `_test`; never point the migration test fixture at valuable or deployment data. Do not claim release readiness until PostgreSQL migration parity, combined-suite repeatability, strict external identity/payment integration and the production security review have passed.
