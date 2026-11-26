# Paari v2.5 — Remaining Production-Readiness Plan

**Purpose:** carry the v2.4 verified test-mode settlement baseline forward while removing setup defects and creating a safe managed-signing integration boundary. This is a release candidate for further validation, not a live-money release.

## Current evidence baseline

The supplied 2026-10-22 session report states: 298 tests passed and 3 skipped on SQLite; two PostgreSQL migration tests passed separately; Alembic reported no schema drift on SQLite and PostgreSQL; strict-control-plane E2E passed; the five-check service probe passed; unsafe production configuration was refused; and one real Razorpay test-mode payment completed checkout/capture and reconciled to `PAID` after a signed webhook and direct-provider corroboration. These are reported results from that session and are not automatically results for this updated v2.5 tree; rerun the documented suite on this archive.

## Changes carried into v2.5

- Add Alembic normalization migration `b3c4d5e6f7a8` for duplicate single-column UNIQUE constraints whose matching named unique indexes already enforce uniqueness on PostgreSQL.
- Restrict pytest collection to `tests/`; prevent the operator-only `scripts/live_e2e_test.py` from being collected under the `*_test.py` convention.
- Clear ambient deployment posture, database and signer-provider variables before test collection and in the per-test isolation fixture.
- Remove `python-dotenv` from the live test script in favor of the repository-owned `llm_agent.env.load_env`.
- Create `/app/secrets` and `/app/data` with `paari` ownership in the Docker image before switching to the unprivileged runtime user.
- Make readiness reject placeholder credentials by whole-token and template syntax, not only by a leading `<`.
- Add a provider-neutral signing interface, KMS/HSM client contract, key-id-aware EdDSA JWT signing/verification, managed-signer health status, and fake-client contract tests.
- Keep production startup blocked when the signer is local/unhealthy or the trusted identity provider is missing.
- Ignore temporary compose override files and do not package `.env`, private keys, local databases, runtime logs, or the session report with its credentials.

## Ordered workstreams and exit criteria

### Phase 0 — Baseline and secrets (immediate)
- Rotate exposed Razorpay test credentials, webhook secret and Paari admin key; update `.env` and Razorpay dashboard settings.
- Redact configuration values from the session report before sharing.
- Stop the temporary webhook listener/tunnel and remove `docker-compose.override.yml` when not needed.
- Tag a clean baseline; run the test suite once with `.env` present and once absent; inspect archive contents for secret-like files.

**Exit:** no secrets in source/ZIP, deterministic test collection, reproducible baseline.

### Phase 1 — Managed signing implementation
- Select institution-approved KMS/HSM and implement its adapter against `docs/KEY_MANAGEMENT_DESIGN_V2_5.md`.
- Test signing, verification, old/new key overlap, rotation, revocation, outage and access-policy behavior.
- Publish trusted verification keys (for example a JWKS endpoint) and bind token `kid` to the appropriate key version.

**Exit:** production never reads a local PEM private key; actual managed adapter passes conformance and security review. The generic interface in this ZIP is not sufficient by itself.

### Phase 2 — Trusted identity/KYC/KYB
- Integrate trusted authentication/identity-provider evidence; verify issuer, signature, audience, freshness, subject/org binding and revocation.
- Keep synthetic identity restricted to isolated tests. Assurance cannot be self-asserted by agent or organization.

**Exit:** every production allow has independently verifiable, current principal and organization assurance.

### Phase 3 — PostgreSQL concurrency and recovery
- Exercise parallel authorization redemption, transaction/exposure limits, webhook duplicates, multi-worker reconciliation and provider timeout ambiguity on PostgreSQL.
- Add soak and failure-injection runs; ensure no blind retry can create duplicate payment actions.

**Exit:** database-level invariants survive multi-worker load and recovery.

### Phase 4 — Operations and resilience
- Finish metrics, alerts, incident response, backup/restore, key-compromise runbooks, emergency tenant/agent/provider kill switches and human-review staffing/timeout controls.

**Exit:** operators can detect, stop, reconstruct and safely recover an incident.

### Phase 5 — Independent security and SAFR conformance
- Review authentication, tenant isolation, authorization, evidence trust, webhook validation, key handling, data retention, dependencies and deployment settings.
- Exercise all four SAFR outcomes (`DENY`, `ESCALATE`, `AUTO_EXECUTE`, `OBSERVE`) and reconstruct audit evidence for each.

**Exit:** critical/high findings remediated or formally risk-accepted; all protected actions cross the governance checkpoint.

### Phase 6 — Partner sign-off and controlled pilot
- Agree accountabilities, data boundaries, provider idempotency/webhook contracts, exposure caps, operating hours, review procedures, incident notification and rollback.

**Exit:** institution/provider approves a limited pilot in writing; successful pilot evidence, not test count alone, gates any expansion.

## Current hard block

Do not override production-startup refusals. This repository deliberately does not include a cloud-vendor KMS/HSM client or trusted KYC/KYB integration. Full PostgreSQL concurrency/soak testing, operations, independent security review and partner sign-off also remain launch gates.
