# Validation record — Paari v2.8 SAFR sandbox

Validation was run against the modified checkout in this package. This is a test record, not a security certification.

## Passed

- `python -m compileall -q app alembic/versions scripts` — passed.
- `python -m alembic heads` — one head: `d5e6f7a8b9c0`.
- `pytest -q tests/test_control_plane_engine.py tests/test_safr_portability_v27.py tests/test_deployment_guards.py tests/test_sandbox_separation.py tests/test_migrations.py tests/test_control_plane_api.py` — **33 passed**.
- `python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub --settle` — green: signed Governance Envelope processed before consume; AUTO_EXECUTE decision bound to the exact saved intent; one-time authorization consumed once; duplicate consume refused; local provider stub captured; signed webhook applied; duplicate webhook ignored; forged webhook refused; reconciliation reached `PAID`; proof bundle reported `chain_verified=true`, `webhook_verified=true`, and `settlement_source=simulator`; the 20x over-cap intent was denied without authorization.

All E2E identities are synthetic test fixtures and settlement uses a local simulator. No real money moved and no genuine production KYB evidence was presented.

## Full-suite limitation observed in this environment

The repository has 328 collected tests. A full `pytest -q` run did not complete: the run stalled at `tests/test_env_isolation.py::test_pollution_is_live_without_the_fixture`, which spawns a child Python process; no failure assertion was reported before the runner timeout. The same stall reproduced when that single test was run in isolation here, while the probe command run directly in a shell returned immediately. This test is therefore **not counted as passed**, and the full suite cannot be claimed green from this validation run. Re-run this environment-isolation canary and then the full suite in the target CI environment.

## Production gates remain closed

The verified local E2E health payload explicitly showed `signing_backend.managed=false` and `principal_identity_provider.trusted_evidence=false`. Do not deploy the live path until a genuine identity/KYB integration and managed KMS/HSM signing adapter pass their acceptance tests. Tenant isolation under concurrent Postgres workers, long-running escalation operations, WORM retention/signed audit checkpoints and production provider certification are additional release gates.
