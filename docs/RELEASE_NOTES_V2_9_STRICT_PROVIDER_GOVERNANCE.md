# Paari v2.9 — Strict Provider Governance Gate

## Scope

This release hardens the boundary where a governed payment authorization is consumed. It is a code-and-test milestone, not a claim that live identity, KMS/HSM, production settlement, SAFR certification, or UAE regulatory approval is complete.

## Changes

- **Strict consume-time revalidation:** strict control-plane execution rechecks the persisted intent, authorization-to-intent binding, single-use bound, permissive institutional disposition, active policy version, runtime transaction digest, principal/resource status, current agent and principal grants, and mandate-to-resource/provider/currency/amount binding.
- **SAFR envelope prerequisite:** production posture requires an unexpired processed Governance Envelope receipt bound to the exact intent, transaction, policy decision, request-context digest and authorization. The consume endpoint marks that receipt consumed in the same database transaction that reserves the one-time authorization and emits an audit event. An envelope receipt is not an authorization on its own.
- **Trusted identity adapter contract:** `POST /control/v1/principals/{principal_id}/verify` calls an explicitly pinned, healthy adapter. Accepted evidence is bound to tenant + subject digest, verification kind, jurisdiction, provider case, evidence digest, assurance level, retrieval time and expiry. Production execution refreshes provider case status; stale, revoked, missing, mismatched or unavailable evidence fails closed.
- **Schema update:** Alembic migration `e6f7a8b9c0d1` stores identity verification evidence metadata and precise Governance Envelope receipt bindings/consumption state.
- **Enterprise fleet functional coverage:** a 100-agent acceptance test asserts organization-scoped agent count, uniqueness, active status and risk-summary shape. This is not a production-scale benchmark.
- **Portability boundary:** signed export and destination-side validation remain metadata/provenance portability. Credentials, mandates, grants, payment tokens and spending authority are not transferred.
- **Replay behavior:** repeated consumption preserves the existing `409 Authorization already used or revoked` response.

## Configuration and migration

1. Install the repository's pinned dependencies in an isolated environment.
2. Back up the target database, then run `python -m alembic upgrade head`.
3. Configure `PAARI_REQUIRE_SAFR_ENVELOPE=1` for strict governed deployments.
4. Configure a real identity adapter as `PAARI_IDENTITY_PROVIDER_ADAPTER=package.module:create_provider` and explicitly allowlist its reviewed `provider_id` with `PAARI_TRUSTED_IDENTITY_PROVIDER_IDS`. Do not use the bundled test adapter in a deployment.
5. Configure an actual managed signer using the contract documented in `docs/KEY_MANAGEMENT_DESIGN_V2_5.md` and the repository's signing-backend configuration. An environment variable alone is not proof that a managed signer exists.
6. Keep live startup blocked until the signer and identity adapter report healthy/trusted, the provider and PostgreSQL setup pass acceptance, and required operational/security reviews are complete.

## Verification

- Validation record: [`VALIDATION_V2_9_STRICT_PROVIDER_GOVERNANCE.md`](VALIDATION_V2_9_STRICT_PROVIDER_GOVERNANCE.md). Three isolated targeted-test groups passed (69 tests total); the combined multi-module invocation timed out during teardown, and a full repository pass is not claimed.
- Strict sandbox E2E: `python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub --settle`.
- 100-agent fleet shape: `tests/test_safr_portability_v27.py::test_fleet_risk_summary_handles_one_hundred_agents`.
- Migrations: `python -m alembic upgrade head` and `python -m alembic check` against a disposable test database.

The bundled fake identity adapter is strictly a unit-test fixture. A successful strict stub E2E uses a local simulator and does not establish provider live-money readiness. The prior Razorpay `PAID` transaction was standard-posture test-mode and does not establish that strict SAFR governance guarded the same provider transaction.

## Still open

- A real trusted KYC/KYB/identity provider integration, provider contract and institutional acceptance.
- A genuine managed KMS/HSM client with key rotation, audit logging, historical public-key lookup and operational recovery.
- One strict provider E2E using that real identity adapter, managed signer, production-equivalent enforcement and a certified provider execution/settlement adapter (start in provider sandbox/test mode).
- PostgreSQL concurrency, race-condition and sustained 100-agent fleet load/soak testing.
- Complete escalation operations, audit retention/immutability review, full SAFR conformance, independent security review, UAE legal/regulatory review and partner sign-off.
