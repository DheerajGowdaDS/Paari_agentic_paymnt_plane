# Paari v2.6 — Implementation verification

## Scope

This release addresses the discrepancy noted by the v2.5 live E2E hand-off between signed-mandate enforcement and strict institutional control-plane enforcement. It adds durable service launch/probe tooling and updates the live settlement driver so it requires an already-running service and never terminates the process that must receive provider webhooks.

## Code changes

- `scripts/run_strict_sandbox_server.py`: persistent strict sandbox launcher; refuses `prod`, `prod-live`, and `PAARI_LIVE=1`; forces autonomous mandate posture, signed mandates and strict institutional control plane.
- `scripts/strict_service_gate.py`: read-only live service verification; no payment side effects; optionally requires trusted principal identity integration.
- `scripts/live_e2e_test.py`: client-only driver; strict posture by default; explicit isolated limited mode for prior signed-mandate-only sandbox testing; no child server termination; waits for authoritative proof if requested; caps default/minor-unit amount; uses the independent canonical mandate encoder.
- `app/trust.py` and `/health`: expose that no trusted principal KYC/KYB identity adapter is configured. Parent admin approval does not imply principal identity proof.
- `docker-compose.yml`: strict autonomous mandate posture is default and no longer configurable to the weaker posture within the standard Compose service.
- `.env.example`, `.gitignore`: clarify strict configuration and exclude local live E2E state files.
- Tests cover strict-vs-limited posture validation, production refusal by the sandbox launcher, identity-provider gate behavior, and the guarantee that the live driver does not own/terminate the service or seed synthetic identity assurance.

## Verification protocol

Run in one process at a time; `tests/test_env_isolation.py` deliberately launches nested pytest processes and can stall if another suite is running against shared test files.

```powershell
python -m compileall -q app sdk scripts llm_agent tests alembic
python -m pytest -q tests/test_live_service_gate.py tests/test_health.py tests/test_provider_provenance.py tests/test_deployment_guards.py
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
```

On a Docker-enabled host with a disposable PostgreSQL database:

```powershell
docker compose config
docker compose build
TEST_DATABASE_URL="postgresql+psycopg://.../paari_test" python -m pytest -q tests/test_postgres_migration.py
python scripts/strict_service_gate.py
```

The present authoring environment did not have the user's live Razorpay account, webhook dashboard or Docker/PostgreSQL runtime attached; no fresh provider-side settlement was performed as part of v2.6. Results from the user's prior session remain historical evidence, not a new run of this package.

## Expected limitation

The strict local-stub E2E can use its explicitly synthetic identity fixture in a disposable database. The live persistent service must not use that fixture. Since there is no trusted principal identity-provider adapter in this release, the live driver refuses to create a positive strict-control-plane order. `PAARI_ENV=prod` remains blocked by design until the KMS/HSM and identity adapters, concurrency/soak tests and independent security review are complete.
