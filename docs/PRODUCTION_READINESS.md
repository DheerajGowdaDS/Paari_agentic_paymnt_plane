# Paari Production Readiness

> **v2.6 update (2026-10-23):** The live v2.5 session report shows `control_plane_enforcement=false` on the persistent live settlement service even though signed mandates were required. The settlement remains valid evidence for the signed-mandate test-mode payment path, but is **not** evidence of strict institutional control-plane enforcement on that service. v2.6 adds `scripts/run_strict_sandbox_server.py`, `scripts/strict_service_gate.py`, `/health` status for the missing trusted principal identity provider, and a persistent-server live driver that refuses to create orders in a permissive posture by default. See `docs/STRICT_LIVE_SERVICE_GATE_V2_6.md`.

The repository still does **not** contain a production KMS/HSM adapter or a trusted principal KYC/KYB identity-provider adapter. `PAARI_ENV=prod` and `prod-live` must remain blocked.

# Production readiness and rollout gate

## Current status

**Production-oriented control-plane foundation; not yet certified or safe to enable for live funds solely on the basis of this repository.** Existing agent delegation, proof-of-possession, signed mandates, bounded authorization, provider-state reconciliation, and audit functionality were preserved. The institutional data model, APIs, policy engine and strict payment-path enforcement were added with automated tests.

The production environment refuses to start unless it is configured for PostgreSQL, autonomous mandate posture, signed mandates, strict institutional control-plane enforcement, a 32-character minimum platform admin secret, and (for `prod-live`) a Razorpay live-mode key ID. The protocol signing-key loader refuses to auto-generate a new identity in production and rejects group/world-readable key files. This is a fail-closed deployment gate, not proof that external dependencies have been implemented or certified.


## Latest hardening update (2026-10-21)

- LLM configuration now supports `PAARI_LLM_PROVIDER=kilo`, Kilo's OpenAI-compatible API root, `KILO_API_KEY`, and `KILO_MODEL`. The documented free model ID is a convenience default only; access and availability must be re-probed at run time. Generic OpenAI-compatible settings are supported, and the legacy `BYNARA_*` configuration remains backward compatible. API keys are not included in the release ZIP.
- `/health` now reports `control_plane_enforcement` from the running server process. The E2E script asserts the server-reported posture rather than inferring it from a local command-line flag.
- The E2E harness now has a local-only `--strict-control-plane` path that creates organization-scoped controls, an active principal/resource, both access grants, a versioned policy, a signed mandate, and a provider binding. It checks that the persisted disposition is `AUTO_EXECUTE`, the audit chain contains the control-plane decision, and a missing mandate is rejected.
- A separate adversarial request bypasses the broker's local amount check to prove that the server itself rejects an amount exactly 20 times the delegated cap (`10,000,000` minor units vs `500,000`) without minting authorization. A tenant-scoped control-plane decision must persist as `DENY`.
- The local `--execute-stub` variant creates a synthetic order against the local Razorpay stub and verifies that a second consume of the same bounded authorization is rejected with HTTP 409. No external provider and no money movement are involved.
- The strict E2E's high-assurance principal and parent admin-approval tier are explicitly seeded as synthetic **test fixtures** in the throwaway SQLite database because no trusted identity/KYB provider integration is bundled. This does not validate production KYC/KYB and cannot be used against an external server.

## Verification for this update

- LLM gateway contract/configuration, control-plane API, health, state-machine, single-use consume and security/deployment guard tests: **52 passed**.
- `python -m compileall -q app llm_agent scripts tests alembic`: passed.
- `python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub`: passed, including explicit policy disposition, 20x delegated-cap server-side denial, audit-chain verification, provider-order creation in the local stub and HTTP 409 duplicate authorization rejection.
- A live call to Kilo and real Razorpay was **not run in this build environment** because API credentials are not packaged or present in the uploaded repository. Configure them locally to validate actual model entitlement and the Razorpay test endpoint.
- Full repository suite: **not verified**. A 289-test collection did not complete within the 300-second run; the combined run appeared to stall after reaching the MFA-auth test, although that MFA module passed when run by itself. Investigate test-order/SQLite-lock behavior and rerun the complete suite in CI before release. Focused results do not imply all repository tests pass.

## Required before live-money launch

1. **Identity and institutional verification:** integrate a real OIDC/FAPI/identity-provider validation path and signed/trusted callback before raising principal assurance above `low`; the current organization attestation endpoint is not KYC/KYB verification; integrate KYB/business verification; define organization lifecycle/suspension states and operations RBAC.
2. **Signing and secrets:** production startup now refuses to auto-generate the protocol signing key and rejects group/world-readable signing-key files. Before live launch, move Paari signing keys to managed KMS/HSM with rotation, audit and key-compromise runbooks. Store all provider credentials and OAuth refresh tokens in a secret manager. Never store secrets in resource metadata.
3. **Payment rails:** implement a documented adapter for each actual bank/PSP/open-banking/stablecoin rail. The adapter must provide idempotent submit, status lookup, authenticated webhooks/callbacks, exact amount/currency/beneficiary matching, refund/reversal semantics where applicable, reconciliation, timeout/unknown-outcome recovery and certification against provider sandbox/production contracts. Do not advertise open banking or stablecoin execution as available until these pass.
4. **Data correctness and concurrency:** run migrations and concurrency tests against the exact PostgreSQL version used in production; test parallel bounded-authorization redemption, exposure reservation, idempotency collisions, policy activation, audit writes and webhook deduplication across multiple workers. Keep serialization/unique-constraint races fail-closed and observable.
5. **Audit durability:** export signed/hash-chained audit heads to independently administered append-only/WORM storage with periodic verification; define retention, privacy minimization, tenant access and evidence export.
6. **Operations:** deploy metrics and alerts for deny/review rates, unknown provider outcomes, webhook failures, queue/reconciliation age, key expiry and audit-chain mismatch; add SLOs, on-call rotations, rate limits, back-pressure, dead-letter handling, backup/restore and disaster-recovery drills.
7. **Security validation:** threat-model review, dependency/image scanning, secret scanning, SAST/DAST, API fuzzing, cross-tenant/BOLA and replay tests, external penetration test, provider security review, privacy and regulatory/legal assessment for launch markets.
8. **Human review:** implement authenticated reviewer identities, separation of duties, reviewer authority limits, dual control, expiry/timeouts, fail-closed escalation and tamper-evident reviewer decisions. Existing step-up/review controls are not, by themselves, a complete staffed review operation.

## Release procedure

1. Use a disposable database to validate `alembic upgrade head` and rollback/restore procedures.
2. Run unit, route, migration, protocol-conformance and integration suites in CI; include PostgreSQL + real Redis if enabled by the deployment and provider sandbox contract tests.
3. Run strict institutional mode in sandbox with test-only provider credentials, active principal, current signed mandate, matching source resource, both required grants and a versioned active policy.
4. Verify every deny/review/allow creates the expected decision/audit evidence and that duplicate/replayed requests cannot create a second provider action.
5. Complete partner certification and sign off the checklist above before `PAARI_ENV=prod` or `prod-live` is deployed.

## Implemented versus external

- **Implemented in this repository:** fail-closed production key-loading guard, data models/migration for principals/resources/grants/policies/decisions/tenant control keys; deterministic disposition evaluator; strict institutional payment-path hook; server-derived intent risk baseline; signed-mandate validation reuse; decision + hash-chain audit persistence; new control-plane API tests.
- **Already present and preserved:** parent-signed delegation, proof-of-possession, mandate and bounded authorization logic, Razorpay checkout adapter, autonomous provider adapter contract, provider reconciliation/state machine and hash-chain audit.
- **Not supplied merely by this code:** actual KMS/HSM, trusted identity/KYB provider, open-banking/stablecoin adapters, secret manager, WORM audit store, managed reviewer workflow, production partner approvals and independent security/compliance validation.

## Migration check

- `alembic heads` should report the single current head `b3c4d5e6f7a8` after applying the v2.5 schema-normalization migration; the repository has one linear migration head. The full migration/integration suite still needs a complete CI run against the target PostgreSQL version.


## v2.4 release gate update (2026-10-22)

This release intentionally **does not permit `PAARI_ENV=prod` or `prod-live` to start**. The current source still uses a process-local Ed25519 PEM signer and does not integrate a trusted KYC/KYB identity provider. Startup now returns explicit launch blockers for those two missing controls instead of allowing environment variables to imply they exist.

The shipped Docker Compose service hard-enables `PAARI_CONTROL_PLANE_ENFORCEMENT=1` and `PAARI_REQUIRE_SIGNED_MANDATE=1`, passes `ALEMBIC_URL` explicitly, installs the PostgreSQL driver, and probes `/health/ready` rather than relying solely on liveness. `/health/ready` checks database connectivity, strict governance flags, admin-key strength, signing-key file presence, and provider/webhook configuration. Readiness in sandbox is not a live-money certification.

The LLM loop now replaces model-written payment-completion claims with a deterministic status derived from Paari state and proof. A provider order at `PROVIDER_SUBMITTED`, missing proof, an invalid audit chain, or an unverified webhook cannot be described as a completed payment. A simulator-originated `PAID` is explicitly labeled as simulator evidence.

CI's PostgreSQL migration job now sets `TEST_DATABASE_URL` to a disposable database whose name ends in `_test`, which is the variable the test suite actually reads. This is still only migration/FK parity coverage; production concurrency/soak testing remains a launch gate.

### Acceptance checklist

- [x] Docker Compose forces strict control-plane enforcement and signed mandates.
- [x] Container image includes the PostgreSQL driver and no longer copies paths excluded by `.dockerignore`.
- [x] Compose supplies Alembic's PostgreSQL URL and uses `/health/ready`.
- [x] Readiness fails closed when core runtime security prerequisites are missing.
- [x] LLM responses cannot overstate `PROVIDER_SUBMITTED` as settled.
- [x] CI points PostgreSQL migration tests at `TEST_DATABASE_URL` with a disposable `_test` database.
- [ ] Full test suite and PostgreSQL-specific tests pass in a clean CI run on this exact v2.4 tree.
- [ ] Run real Razorpay test-mode capture/checkout, signed webhook delivery, duplicate/out-of-order event tests, and independent reconciliation to `PAID`.
- [ ] Integrate trusted KYC/KYB identity proofing and managed KMS/HSM signing; until then production startup is blocked.
- [ ] Add PostgreSQL multi-worker concurrency/soak tests for one-time authorization, idempotency, and limits.
- [ ] Complete operator review workflow, incident response, security review and partner certification.

Never check in `.env`, `.pem`, provider keys, Kilo JWTs, webhook secrets, or real user/payment data.


## v2.5 managed-signing boundary and inherited verification fixes (2026-10-23)

- Added `app/signing_backends.py`; credential/session/bounded-authorization JWTs and agent-card signatures now route through the provider-neutral signer. The KMS/HSM wrapper validates the Ed25519 public key, signature length and each signature returned by the injected client; JWT validation resolves signing material by `kid` so a reviewed provider adapter can support rollover.
- **No concrete cloud KMS/HSM adapter is included.** Production is only allowed past the signing check if the active signer instance is a `KmsHsmSigningBackend` with a healthy client. The trusted KYC/KYB identity adapter is still absent and remains a hard production blocker.
- Added migration `b3c4d5e6f7a8` to reconcile duplicate PostgreSQL UNIQUE constraints vs named unique indexes; SQLite path is intentionally a no-op.
- Pytest collection is scoped to `tests/`; test fixtures clear ambient control-plane, deployment database and signer-provider variables before app imports; the operator-only live script uses the repository env loader rather than importing `python-dotenv`.
- Docker builds now create `/app/secrets` and `/app/data` with the unprivileged `paari` ownership before switching users.
- Readiness detects placeholder tokens and template syntax in admin/provider/webhook credentials and reports actual signer health without leaking key material.
- See `docs/RELEASE_PLAN_V2_5.md` for the phased remaining work and `docs/KEY_MANAGEMENT_DESIGN_V2_5.md` for the adapter contract. The exact v2.5 suite must be rerun from the release ZIP; v2.4 session-summary numbers are not to be copied forward as v2.5 results.

## v2.7 — UAE-first SAFR and portability additions (2026-10-24)

- Added strict SAFR Governance Envelope schema, action-context digest/signature/freshness validation, tenant-scoped envelope receipt and replay rejection.
- Added signed Agent Card / parent delegation portability package and import-side validator with out-of-band Paari issuer trust; destination authorization is not carried in the package.
- Added a provider-neutral identity verification contract and sandbox provider that never produces `VERIFIED` identity.
- Added `PAARI_HOME_JURISDICTION=AE` as metadata only.
- Refer to `docs/SAFR_CONFORMANCE_MATRIX_V2_7.md` for the difference between implemented primitives and target conformance.

Still open: new v2.7 migration and full suite must run against PostgreSQL in clean CI; concurrent multi-worker tests; all-four-disposition conformance and operational human review; full interception for data/API actions; independent audit storage; concrete managed KMS/HSM and trusted KYC/KYB adapters; UAE legal/regulatory scope assessment and partner/provider sign-off. The Governance Envelope validator returns `VALIDATED_ONLY` and is not itself authorization.
