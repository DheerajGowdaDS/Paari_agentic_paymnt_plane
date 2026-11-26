# Strict Provider Flow — Acceptance Checklist (v2.9)

This checklist defines the next end-to-end acceptance gate. Do not treat a green simulator rehearsal or a standard-posture provider payment as a pass for the strict provider flow.

## A. Institutional identity and signing

- [ ] Integrate a real, reviewed identity/KYB adapter that implements `verify`, `get_status`, and `healthcheck` in `app/identity_providers/contracts.py`.
- [ ] Provider ID is pinned in `PAARI_TRUSTED_IDENTITY_PROVIDER_IDS`; provider health is checked, evidence is bound to tenant/subject/purpose/jurisdiction, and status is refreshed at payment authorization/execution.
- [ ] Verify negative cases: unknown provider, unpinned provider, provider outage, rejected/revoked case, subject mismatch, verification-purpose mismatch, jurisdiction mismatch, weak assurance, missing evidence digest, expired evidence and clock anomalies.
- [ ] Integrate an actual managed KMS/HSM signing client through `PAARI_SIGNING_ADAPTER` and configured key ID. Test signing response verification, historical public-key lookup, rotation, access policy, audit events, health failures and incident recovery.
- [ ] Confirm production readiness/startup stays blocked if either adapter is absent, unhealthy or not trusted.

## B. Database and production posture

- [ ] Back up the database and run `python -m alembic upgrade head`; confirm migration head `e6f7a8b9c0d1` or later.
- [ ] Use PostgreSQL with tested isolation/locking. SQLite is not production concurrency evidence.
- [ ] Confirm actual runtime `/health` and `/health/ready` posture; do not trust intended `.env` values alone.
- [ ] Set `PAARI_CONTROL_PLANE_ENFORCEMENT=1`, `PAARI_REQUIRE_SIGNED_MANDATE=1`, `PAARI_REQUIRE_SAFR_ENVELOPE=1` and the appropriate autonomous production mode. Use real secret management; never commit credentials or private keys.
- [ ] Verify the provider adapter is the intended test/sandbox environment. Do not enable live-money credentials for acceptance until the institution explicitly authorizes it.

## C. End-to-end positive test (test provider first)

1. Register and authenticate an independent agent under a tenant-bound parent delegation.
2. Create/verify the principal using the configured trusted identity provider; ensure the provider case ID, evidence and expiry are persisted.
3. Create the mandate, governed resource, payment instrument binding, grants and versioned policy. Set explicit transaction-level and fleet-level limits.
4. Submit a payment intent and obtain the persisted institutional disposition.
5. Submit the signed Governance Envelope to `/control/v1/governance/envelopes/process`; check exact amount, currency, merchant/purpose, principal/resource, beneficiary digest and runtime request-context digest. Confirm it references the same saved decision and existing one-time authorization.
6. Consume the authorization using authenticated sender-constrained proof. Confirm identity is refreshed, the envelope is unexpired/unconsumed, and all policy/grants/mandate/resource/provider bindings remain current.
7. Complete provider sandbox/test submission, signed webhook verification, provider read-back/reconciliation and terminal settlement state. Retrieve the proof bundle and verify the complete audit chain and provider provenance.
8. Confirm replay cannot consume twice and that a retry produces no second provider side effect.

## D. Negative and concurrency tests

- [ ] Missing, expired, malformed, replayed or mismatched Governance Envelope: no provider submission.
- [ ] `DENY` and `ESCALATE`: no authorization consumption. Reviewer action must be a separately authenticated, scoped action; agents cannot set their own approval flag.
- [ ] Policy version changes after authorization; grant/resource/mandate/parent/agent is revoked; provider binding changes; transaction amount, currency, merchant, purpose or digest changes: fail closed.
- [ ] Amount above the bounded authorization or mandate: fail closed.
- [ ] Identity status turns rejected/revoked/expired between approval and consume: fail closed.
- [ ] Simultaneous consume requests: exactly one reservation/provider submission; all other requests receive stable replay/already-used outcomes.
- [ ] Forged, wrong-secret, duplicate and out-of-order webhooks; ambiguous provider timeout and reconciliation recovery.

## E. Enterprise fleet and portability

- [ ] Confirm risk-summary scoping and currency-separated aggregate exposure for at least 100 agents.
- [ ] Load/soak under representative concurrency on production-equivalent PostgreSQL; measure latency, DB locks, error rates, provider throttling and recovery. A functional 100-row test is not a load test.
- [ ] Emergency revocation invalidates credentials/grants/unconsumed authorizations and emits reconstructable audit evidence under concurrent consume conditions.
- [ ] Export package is signed and excludes private credentials, user mandates, provider tokens and active spending authority.
- [ ] Import checks out-of-band issuer trust and destination-local parent, principal, resource and consent; staging is idempotent; cross-tenant or repeated package attempts cannot transfer authority.

## F. Release evidence required

- [ ] Full repository suite passes in clean CI, with test database isolated from any deployment database.
- [ ] Migration upgrade/downgrade and model drift checks pass on supported database types.
- [ ] Independent security review/penetration testing and incident/operational runbooks are complete.
- [ ] UAE legal/regulatory counsel and partner acceptance are recorded for the actual selected identity, payment rails, data residency and operating model.

**Current release note:** v2.9 supplies stronger code paths, an identity adapter contract, acceptance tests and an explicit release checklist. It does not ship a real KYC/KYB vendor adapter or managed KMS/HSM client. Until those are configured and accepted, a positive strict production-provider payment must remain blocked.
