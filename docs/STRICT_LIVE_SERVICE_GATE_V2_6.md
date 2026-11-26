# Paari v2.6 — Strict live-service gate and persistent E2E hand-off

## Why this update exists

The v2.5 live E2E hand-off report records a successful Razorpay **test-mode** settlement. It also records that the persistent service used `require_signed_mandate=true` while `control_plane_enforcement=false`, and that the live trial used a local PEM signing backend. Therefore the settlement is valid evidence for the signed-mandate payment lifecycle, but it is **not** evidence that the complete institutional SAFR control plane was enabled for that transaction.

The report also exposed test-mode configuration values. Treat them as compromised. This source archive intentionally excludes `.env`, private keys, local state, tunnel logs, and the unredacted report; the repository does not remotely rotate provider credentials.

## Changes in this release

1. `scripts/run_strict_sandbox_server.py` launches a persistent sandbox service and pins `PAARI_CONTROL_PLANE_ENFORCEMENT=1`, `PAARI_REQUIRE_SIGNED_MANDATE=1`, `PAARI_REQUIRE_USER_MANDATE=1`, and `PAARI_MODE=autonomous`. It refuses production-like profiles. It keeps the server alive after client-side E2E drivers exit, allowing provider webhooks and reconciliation to arrive.
2. `scripts/strict_service_gate.py` checks the active service's own `/health` and `/health/ready` responses. It verifies strict control-plane enforcement, signed/required mandates, database health, signer health, and real Razorpay test-mode provenance. It never creates a payment.
3. `/health` now reports principal identity-provider integration status separately from parent admin approval. The current release honestly reports no trusted principal KYC/KYB adapter.
4. `scripts/live_e2e_test.py` now targets an already-running service; it no longer spawns and terminates a child server before the webhook can arrive. Its default is fail-closed: strict control plane must be enabled. It refuses a positive strict live transaction while the trusted principal identity-provider adapter is absent; it does not seed synthetic high assurance. It can wait for an authenticated proof bundle to confirm `PAID` only when the explicit limited sandbox mode has produced an order and a human completes checkout.
5. The prior signed-mandate-only settlement flow is available only with `--signed-mandate-only-sandbox`. That mode requires sandbox/test provider provenance, signed mandates, and readiness failure solely because control-plane enforcement is disabled. The script prints a warning that this does not demonstrate strict SAFR runtime enforcement.
6. Docker Compose defaults to autonomous mandate posture while retaining strict control-plane and signed-mandate gates. Test-harness runtime artifacts are gitignored.

## Runbook

### 0. Rotate exposed credentials first

Rotate/regenerate the Razorpay test key pair where supported, generate a fresh webhook secret and update it in both Paari's private `.env` and the Razorpay dashboard, and rotate `PAARI_ADMIN_API_KEY`. Retire the old values and verify that they fail. Recreate/regenerate the local development signing key if exposure is suspected. Do not copy secrets from the session report. These are operator actions; this repository does not perform them automatically.

Stop the old test tunnel/listener when no longer needed, remove `docker-compose.override.yml`, and do not expose the database port unless required for a controlled local test.

### 1. Start the strict persistent sandbox

Use a private `.env` with sandbox/test credentials only, then run:

```powershell
python scripts/run_strict_sandbox_server.py
```

Or launch the strict Compose service:

```powershell
docker compose config
docker compose up -d --build
```

The service started by this launcher is a strict sandbox. It is not a production launcher and cannot substitute for managed KMS/HSM or trusted identity-provider integration.

### 2. Prove the persistent service's posture

```powershell
python scripts/strict_service_gate.py
python scripts/gate_a_service_probe.py
```

Expected: `/health` reports `control_plane_enforcement=true`, `require_signed_mandate=true`, and (with the strict sandbox launcher) `mandate_mode=autonomous`, `mandate_required=true`; `/health/ready` is HTTP 200. The gate reports that trusted principal identity is not configured as a warning until the identity adapter is implemented.

To make missing trusted identity a hard failure:

```powershell
python scripts/strict_service_gate.py --require-trusted-identity-provider
```

This is expected to fail on the present code, because no trusted principal KYC/KYB identity adapter is implemented.

### 3. Strict payment proof status

The local deterministic strict regression remains:

```powershell
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
```

A positive live Razorpay payment with **strict institutional control-plane enforcement** cannot yet be demonstrated safely by the live driver: the trusted principal identity adapter is absent, and the driver refuses to synthesize assurance or bypass missing principal/resource/policy facts. Implement the identity adapter and an operator-approved provisioning flow before adding this positive path.

### 4. Limited signed-mandate-only sandbox settlement (not strict SAFR proof)

Only when intentionally reproducing the earlier limited settlement on an isolated sandbox service where control-plane enforcement is **off**, with signed mandates required and the only readiness blocker being `control_plane_enforcement`, use:

```powershell
python scripts/live_e2e_test.py --signed-mandate-only-sandbox --wait-for-settlement --wait-timeout-seconds 600
```

The script reads actual server posture, requires the real Razorpay test adapter and `provider_environment=test`, uses INR 1.00 by default (100 minor units; configurable only up to INR 100.00), and never stops the server. The configured webhook tunnel and checkout host must be active separately. Complete the displayed checkout in a browser while the driver waits. It only reports verified settlement if the authenticated proof bundle says `final_state=PAID`, `settlement_source=provider`, `provider_environment=test`, `webhook_verified=true`, and `audit_record.chain_verified=true`.

Do **not** run this limited mode against the strict Compose service. Do not describe the result as full SAFR control-plane settlement evidence.

## Remaining production gates

- A real managed KMS/HSM signing adapter is implemented, key rotation tested, and health/permissions audited.
- Trusted principal KYC/KYB identity-provider integration is implemented and authoritative evidence is verified.
- PostgreSQL multi-worker concurrency, duplicate-consume races, aggregate limits, out-of-order webhook and ambiguous timeout recovery pass under load.
- Monitoring, backup/restore, incident response, key compromise and kill-switch runbooks are tested.
- Independent security review, provider/partner sign-off, and full SAFR four-disposition conformance are complete.

`PAARI_ENV=prod` and `prod-live` remain blocked by application startup guards. Do not override the blocks.
