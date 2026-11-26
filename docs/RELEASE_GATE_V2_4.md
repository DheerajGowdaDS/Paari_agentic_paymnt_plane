# Paari v2.4 — Strict Controls and Verified Settlement Release Gate

**Release intent:** harden the real service posture and make payment status claims evidence-bound. This is not a certification for real-money use.

## Gate A — actual service posture

1. Copy `.env.example` to `.env` and replace every placeholder with a private sandbox value.
2. Run `docker compose up -d --build`.
3. Check `GET /health` for liveness and `GET /health/ready` for readiness.
4. The Compose service always sets `PAARI_CONTROL_PLANE_ENFORCEMENT=1` and `PAARI_REQUIRE_SIGNED_MANDATE=1`. Do not override these to zero in a shared service.
5. Submit a missing-mandate test intent and a cross-resource/cross-tenant test intent; both must be denied without minting authorization.

## Gate B — deterministic security regression

```bash
python -m compileall -q app sdk scripts llm_agent
python -m pytest -q -rs
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
```

Run no more than one pytest process at once. The fixture uses a disposable SQLite database. Do not point tests at a service/deployment database.

## Gate C — PostgreSQL schema/FK verification

Use a disposable database ending in `_test`, never a deployment database:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://paari:paari@127.0.0.1:5432/paari_test"
python -m pytest -q -rs tests/test_postgres_migration.py
```

The PostgreSQL migration/FK job is separately wired in GitHub Actions. Multi-worker concurrency and soak tests are still required; schema parity is not equivalent to concurrency proof.

## Gate D — Kilo and Razorpay test-mode lifecycle

```bash
python scripts/llm_smoke.py
python scripts/llm_agent_e2e.py --with-server --strict-control-plane
```

Expected endpoint boundary for the above command: `PROVIDER_SUBMITTED`, real Razorpay **test** order, no capture and no claim that money moved. Verify the order via Razorpay test API independently.

To prove settlement, separately execute a controlled test checkout/capture using Razorpay's documented test flow; receive a real signed webhook at the registered stable HTTPS URL; test duplicate and out-of-order delivery; then reconcile by reading provider evidence. The local `--settle` simulator is not evidence of real Razorpay settlement.

## Gate E — production security launch blockers

This source release intentionally rejects `PAARI_ENV=prod` and `prod-live` because:

- no managed KMS/HSM signing adapter is integrated; the current key service loads a local PEM;
- no trusted KYC/KYB identity-provider adapter is integrated;
- settlement/webhook certification and PostgreSQL concurrency/soak evidence remain outstanding;
- independent security review, runbooks, alerting, backup recovery and incident response remain outstanding.

Do not try to override these blockers with environment variables. Complete and test the actual adapters and operational controls, then review the launch gates again.

## State-to-message contract

- `AUTHORIZED`: authorization exists; execution has not happened.
- `PROVIDER_SUBMITTED`: provider order/request was created; settlement has not been verified.
- `PROVIDER_AUTHORIZED`: provider has authorized; capture/reconciliation remains pending.
- `CAPTURED`: provider reports capture; reconciliation remains pending.
- `PAID`: only use after provider evidence and reconciliation complete; model output alone never establishes this state.
- `PAID` from a local simulator is labeled simulator evidence, not a real provider settlement.
