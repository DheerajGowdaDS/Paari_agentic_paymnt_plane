# v2.9 Validation Results — Strict Provider Governance Gate

**Validation date:** 26 October 2026 (UTC environment timestamps; project target remains UAE-first).  
**Scope:** this working tree and the v2.9 modifications only. This is test evidence, not an independent audit or production certification.

## Results

| Check | Result | Scope note |
|---|---|---|
| Python compile check | PASS | `python -m compileall -q app scripts tests` |
| Identity, control-plane API and SAFR/portability tests | PASS — 26 tests | Includes untrusted/absent provider fail-closed behavior, provider evidence binding, 100-agent functional fleet summary, portability and envelope tests. |
| Deployment guards, migrations, sandbox separation and health | PASS — 14 tests | Run as an isolated group. |
| Provider provenance, atomic authorization consume and mandate hardening | PASS — 29 tests | Run as an isolated group. |
| Total grouped targeted tests | PASS — 69 tests | All tests in the three groups passed when run separately. |
| Fresh SQLite migration to head + schema drift check | PASS | `alembic upgrade head`; `alembic check` returned `No new upgrade operations detected.` Migration head `e6f7a8b9c0d1`. |
| Strict-control-plane local-stub end-to-end rehearsal | PASS | Signed envelope, bounded authorization, local stub order/capture, signed simulator webhook, reconciliation to `PAID`, proof bundle, replay refusal (HTTP 409), 20x over-cap denial. No real payment provider or money involved. |
| Combined multi-module targeted pytest invocation | INCOMPLETE | The combined invocation printed the test progress but timed out during teardown without a final pytest summary. The same 69 targeted tests passed when split into the three groups above. |
| Full repository test suite | NOT CLAIMED | Must run to completion in clean CI; this validation does not assert a whole-repository pass. |
| Strict live-provider payment with real KYC/KYB + managed KMS/HSM | BLOCKED / NOT RUN | No actual vendor identity adapter or managed signer is supplied in this project package. Production startup/consume must remain fail-closed until configured and accepted. |

## End-to-end rehearsal interpretation

The E2E server explicitly reported `control_plane_enforcement=true`, `provider=local-simulator`, `provider_environment=simulated`, and `signing_backend.managed=false`; it also reported no configured trusted identity provider. The rehearsal therefore proves the strict-control-plane **sandbox** flow and simulator provenance only. It does not prove institutionally trusted identity, managed-key operation, strict live-provider enforcement, live-money payment capability, SAFR certification or UAE regulatory approval.

## Reproduce key checks

```bash
python -m compileall -q app scripts tests
python -m pytest tests/test_identity_provider_runtime.py tests/test_control_plane_api.py tests/test_safr_portability_v27.py -q
python -m pytest tests/test_deployment_guards.py tests/test_migrations.py tests/test_sandbox_separation.py tests/test_health.py -q
python -m pytest tests/test_provider_provenance.py tests/test_consume_atomic.py tests/test_mandate_hardening.py -q
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub --settle
```

For a disposable SQLite schema check:

```bash
ALEMBIC_URL=sqlite:////tmp/paari_v29_schema_check.db python -m alembic upgrade head
ALEMBIC_URL=sqlite:////tmp/paari_v29_schema_check.db python -m alembic check
```

Use an empty disposable database path for the migration check. Never point a destructive test or migration experiment at a deployment database.
