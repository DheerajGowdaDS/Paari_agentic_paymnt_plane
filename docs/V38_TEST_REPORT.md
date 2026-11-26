# v3.7.1 enterprise risk and portability extension — validation report

**Validation date:** 3 November 2026  
**Environment:** Python 3.13.5, pytest 9.0.2, SQLite disposable test databases; local Chromium executable is present but browser navigation is blocked by the execution policy (`ERR_BLOCKED_BY_ADMINISTRATOR`).

## Passed targeted test suites

The following targeted tests passed after the additive API, migration, portal and test updates:

| Test group | Result |
|---|---:|
| `tests/test_v37_enterprise.py tests/test_v37_fleet_100.py` | 11 passed |
| `tests/test_v34_receivers.py tests/test_v35_independent_receiver_sandbox.py tests/test_v35_receiver_http_process.py` | 8 passed |
| `tests/test_health.py tests/test_deployment_guards.py` | 11 passed |
| `tests/test_migrations.py` | 2 passed |
| `tests/test_multitenancy.py` | 8 passed |
| `tests/test_failure_recovery.py` | 2 passed |
| `tests/test_safr_portability_v27.py` | 13 passed |
| `tests/test_mandate_hardening.py` | 12 passed |
| `tests/test_control_plane_api.py` | 6 passed |
| `tests/test_consume_atomic.py tests/test_provider_transaction_model.py tests/test_webhook_org_isolation.py` | 9 passed |
| `tests/test_reconcile.py tests/test_reconcile_worker.py` | 10 passed |
| `tests/test_security_headers.py tests/test_production_signing_key.py tests/test_governance_attacks.py` | 7 passed |
| **Total targeted** | **99 passed** |

`python -m pytest --collect-only -q` collected 514 tests and reported three optional PQC tests skipped because `liboqs-python` was not installed.

## Additional checks

- `python -m alembic heads` reports one head: `f2a3b4c5d6e7`.
- `python -m alembic upgrade head` completed successfully against a newly created disposable SQLite database, including the new recipient-key columns and rail-simulation table.
- Inline portal JavaScript passes `node --check`.
- Portal HTML parses; all seven Organization Portal page IDs are present and there are no duplicate DOM IDs.
- Local Uvicorn startup completed; `GET /portal` returned HTTP 200 and `GET /health` returned `status=ok` with database `up`.
- An automated Playwright visual/browser interaction run could not complete because the environment blocked navigation to both local HTTP and file URLs. Browser-level visual verification must therefore be performed in the target Windows/browser environment.

## Not passed / not demonstrated

- The complete 514-test suite did not finish within the available execution window. Two full-suite attempts timed out; no full-suite pass is claimed.
- No PostgreSQL integration test was run. The shared-budget lock uses `SELECT ... FOR UPDATE`, but concurrent 100-agent authorization, lock timeout/deadlock handling and process-restart recovery remain unverified on PostgreSQL.
- No real open-banking provider, live stablecoin testnet or mainnet, bank consent, TPP/FAPI, wallet screening, custody, signing, broadcast or settlement integration was configured.
- No real external recipient delivery was performed for encrypted data exports.
- No production KMS/HSM, trusted KYC/KYB, MFA/RBAC staff identity, external penetration test or independent cryptographic audit was performed.

## Interpretation

The 99 passing targeted tests establish useful local regression coverage for treasury/fleet risk, receiver-side evidence, health/deployment gates, migrations, multi-tenancy, failure recovery, SAFR/mandate controls, bounded authorization, provider state, reconciliation and webhook isolation. They do **not** establish production readiness. Follow the release gates in `docs/V38_AGENTIC_RISK_AND_PORTABILITY.md` and require `/health/ready` to report ready in the actual production-like deployment before considering any live financial route.
