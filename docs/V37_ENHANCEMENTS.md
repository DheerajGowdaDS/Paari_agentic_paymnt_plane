# Paari v3.7 — Enterprise Treasury Governance, Portability and Security

**Release designation:** `v3.7.0-dev / LOCAL_DEVELOPMENT_PARTIALLY_VERIFIED`.

Built **additively** from the v3.6 backend-only source. Retains FastAPI onboarding, signature verification, SAFR governance, mandates, federation, payment simulator, provider adapters, reconciliation, audit, SDK and existing legacy APIs. Frontend is not included.

## Delivered in this source

1. **Parent-scoped treasury ceiling** (`v37_treasury_policies`): configurable INR/other ISO-like currency ceiling, versioned changes, explicit emergency `FROZEN` status, admin-only unfreeze. One approved parent can govern a fleet of 100+ agents. This is a **per-parent portfolio**, not a multi-parent corporate group aggregate.
2. **Per-agent risk management** (`v37_agent_risk_rules`): daily reserved exposure, per-hour non-denied request velocity, suspension, parent ownership checks. Existing agent mandates remain independent; limits are intersected, not replaced.
3. **Payment pre-execution enforcement**: applied at `/payments/intent` before an authorization can be created, at signed human-review release preflight, and at `/payments/authorizations/{id}/consume`. Risk gates fail closed when a policy is frozen, an agent suspended, a cap exceeded or currencies do not match.
4. **Conservative reservation accounting**: uses all non-denied payment intents within the UTC day (including pending/unknown transactions) as risk exposure. This does not assert actual spent/settled money. A PostgreSQL row-level lock on the parent policy serializes admissions at READ COMMITTED **when all admissions use this code path**. SQLite has no equivalent multi-writer row locking; concurrency acceptance against PostgreSQL is still mandatory.
5. **Portfolio analytics**: registered fleet, each agent's status and reserved spending, shared exposure, rule-based observations for unusual per-agent request frequency or multiple agents paying the same merchant. These signals are heuristics, not fraud determination.
6. **Consent-scoped demo data portability**: parent registers an encrypted synthetic balances/transactions dataset; issues agent-specific, field-limited, purpose/destination/expiry-bound grants; agents authenticate with **mandatory verified** signed request proof to receive only permitted fields; Paari signs the export with its issuer key and logs the digest. Parent can revoke grants and purge live ciphertext. PAN, bank-account numbers, private keys and other arbitrary fields are rejected by a strict schema. No real bank connector or institution-to-institution data transfer is claimed.
7. **Agent identity portability completion**: import a signed source Agent Card / parent delegation package using out-of-band issuer trust, anti-replay digest and explicit destination-parent consent. After staging, destination parent **registers a fresh agent with a new key and delegation**, then links identity lineage. Source identity remains distinct. Existing mandates, account rights, credentials, tokens and grants are **not transferred**. Staging checks source expiry and local status; external source revocation/status still needs a trusted online check in future.
8. **Parent login hardening**: track invalid password attempts and lock an account for 15 minutes after five consecutive failures (parent-specific). This is not a substitute for MFA, IP throttles, audit-alert delivery or production identity management.
9. **Database migration:** `d7e8f9012345`, additive six enterprise tables and parent login lockout columns. Reuses the established Alembic chain.
10. **100-agent demonstration script:** `scripts/v37_treasury_100_agents_demo.py` registers a synthetic fleet via live localhost API requests and applies individual risk limits; it does not create payment authority or move funds.

## Security boundaries / limitations

- Parent onboarding approval remains **manual sandbox approval**, not KYC/KYB verification. Demo agreements and provider integrations have not become regulated by adding v3.7.
- v3.7 dataset portability is a **local demonstration API**, not transport-level encrypted export to a bank or cross-border platform. The local HTTPS/secure-delivery layer, data retention across backups, field-level provenance, legally reviewed data processing, and recipient-side verification remain future work. Sandbox dataset encryption requires **separate** `PAARI_V37_DATA_ENCRYPTION_SECRET`.
- New v3.7 onboarding and portability APIs are blocked in production (`PAARI_LIVE=1` or `PAARI_ENV=prod/prod-live`) until regulated identity, managed signing and independently reviewed OAuth/MFA flows are integrated.
- `PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON` must be configured **out of band**, containing pinned issuer signing key IDs mapped to PEM public keys. The public key embedded in a portable package is *not* sufficient evidence of trust.
- Paari cannot verify a source agent's current status across independent platforms without an online revocation/attestation service. This v3.7 stage is not certified inter-platform portability.
- Shared treasury limits are currently per approved parent; a **group-wide budget spanning multiple parents/organizations** requires an additional enterprise-root and budget hierarchy. Revenue risk indicators, behavioral models, confidential computing and real provider constraints are future enhancements.
- The full strict SAFR + three-party federation + independent receiver + PostgreSQL E2E release gate is **not passed**. The v3.7 tests use disposable SQLite and loopback simulator configuration; test results do not imply real settlement.

## Next hardening gates

1. True PostgreSQL serializable/row-lock concurrency test with 100 agents and simultaneous authorizations; confirm at most one provider consume and no shared budget overrun.
2. Repeat test with provider timeouts, restart/recovery, reconciliation, revoked grants/mandates, frozen treasury, expired imported cards, compromised agent keys and audit tampering.
3. Complete strong admin MFA, password reset/recovery, permissioned key rotation, issuer-key management and online agent revocation checks.
4. Add independently verified bank data connectors, licensed payment-provider capabilities, user-consent/legal review, and actual destination-encrypted transport before any external data portability claim.
5. Run full regression and complete strict PostgreSQL + SAFR + federation + receiver flow; secure an independent security audit and appropriate regulatory review.
