# Paari enterprise agent-risk, data-portability and payment-rail extension

**Baseline:** v3.7.1, additive extension  
**Release posture:** local integration preview; not a production-certified release  
**Architecture principle:** agents propose financial actions; Paari independently evaluates authority and risk; configured payment infrastructure executes only after its own controls.

This document maps the requested product priorities to the implementation in this archive. “Implemented” means a local API/UI workflow exists; it does not mean that an external bank, blockchain, KYC/KYB provider, or receiving institution has been certified or connected.

## 1. Enterprise agent-fleet risk management

The existing treasury risk engine remains the enforcement point for parent-scoped portfolios. It supports:

- One shared daily reserved-exposure ceiling per approved parent, with a single configured currency.
- A per-agent daily cap, hourly request limit and suspension flag.
- Conservative exposure accounting: every non-DENY intent counts as reserved exposure, including pending or unknown provider states. This is not a settled-balance calculation.
- Runtime checks at payment-intent admission and authorization consumption/revalidation.
- Parent policy row locking using `SELECT ... FOR UPDATE` on PostgreSQL so compliant admissions serialize on that parent policy row. This locking property still requires a real PostgreSQL concurrency acceptance run; SQLite tests do not establish it.
- Emergency parent freeze, with parent-level freeze and Paari administrator unfreeze.
- Advisory risk signals for high request velocity, multiple agents using one merchant, and exact merchant/amount/currency patterns across agents. Signals are not proof of fraud and do not automatically make a decision.

The Organization Portal's **Treasury & risk** page now exposes the shared ceiling, remaining and reserved exposure, individual agent limits/velocity/suspension, risk observations and emergency freeze.

**Remaining enterprise scale gap:** the current budget model is per parent and one currency. It is not a corporate group hierarchy with multiple subsidiaries, FX-normalized exposure, budget reservations across multiple currencies, or a distributed global treasury. A 100-agent registration and policy demonstration exists; true concurrent payment admission across 100 agents on PostgreSQL remains a production gate.

## 2. Financial data and consent control

The existing v3.7 data model is intentionally limited to synthetic datasets of two schemas:

- `balances`: `account_alias`, `balance_minor_units`, `currency`, `as_of`.
- `transactions`: `transaction_id`, `amount_minor_units`, `currency`, `merchant`, `date`, `category`.

Parent users can register encrypted synthetic data, create per-agent field-level grants, define purpose/destination/expiry, review grant and export evidence, revoke grants and purge live ciphertext. The portal now exposes these functions under **Data permissions & portability**.

The additive list routes return dataset metadata, not raw records:

- `GET /v37/enterprise/data/datasets`
- `GET /v37/enterprise/data/grants`
- `GET /v37/enterprise/data/exports`

For encrypted portability, the parent can pin an RSA recipient public key (minimum 2048 bits) when issuing consent. The agent cannot substitute a different destination key at export time. The export uses AES-256-GCM for the payload and RSA-OAEP-SHA256 to wrap the one-time content key; the resulting envelope is signed by Paari and its digest is audited. The destination's private key must remain at the destination. The API does not deliver the envelope to an external endpoint; the agent runtime receives it and must use an independently secured transport to transfer it.

**Production data boundary:** these routes are sandbox-only and use synthetic data. They are not a live open-banking aggregator or a production data-sharing gateway. A production connector still needs provider/TPP authentication, explicit end-user consent, token lifecycle, field provenance, purpose limitation, revocation propagation, data-retention and backup deletion policies, recipient identity verification, transport controls, legal basis and independent security review.

## 3. Agent and data portability

The signed Agent Card portability workflow remains identity-lineage staging, not authority transfer. Destination must register a fresh agent with a new key and delegation; mandates, credentials, private keys, API permissions and data grants do not migrate automatically. The new encrypted data-export envelope binds consent to the destination label and pinned recipient public-key fingerprint.

The destination label by itself is not proof that the destination endpoint is controlled by the intended institution. A production federation service must establish destination organization identity, authenticate the endpoint, verify issuer/revocation status online, protect transport and receipts, and require local destination acceptance before data or an agent is activated.

## 4. Open-banking and stablecoin payment rails

The portal includes a **Payment rail lab** and the API supports auditable route previews:

- `GET /v37/enterprise/rails/capabilities`
- `POST /v37/enterprise/rails/simulate`
- `GET /v37/enterprise/rails/simulations`

Each preview is tied to an existing ALLOW intent, current unconsumed bounded authorization and provider transaction still in AUTHORIZED state. A unique `(intent_id, rail)` constraint prevents alternative duplicate previews; identical retry is idempotent. Open banking requires only a synthetic `sbx-` consent marker; it does not verify bank consent. Stablecoin preview validates EVM address shape and records a wallet fingerprint; it does not screen the address, sign a transaction, broadcast, observe confirmations or prove finality.

Responses explicitly state `authorization_consumed=false`, `external_submission=false` and `settlement_confirmed=false`.

**Not implemented:** live Open Banking/PSD2 payment initiation, FAPI/TPP onboarding, bank OAuth/SCA, account data access, payment submission, webhooks, live stablecoin testnet broadcast, mainnet broadcast, custody or key signing, token/chain allowlists, sanctions/AML wallet screening, bridge controls, confirmations or settlement finality. The included capabilities endpoint reports adapters as `NOT_CONFIGURED` and execution mode as `SIMULATION_ONLY`.

## 5. Independent receiver-side governance

The existing `/control/v1/receivers` service supports organization-bound institution registration with a pinned Ed25519 public key, receiver lifecycle controls, beneficiary registration and blocking, and cryptographically signed receiver claims bound to the original allowed intent, beneficiary, amount and currency. The claim is accepted only after provider submission, and credit-attested evidence requires provider capture/reconciliation. The claim is evidence only: it does not change provider transaction state or declare settlement.

A local Paari administrator approval sets `identity_assurance=ADMIN_APPROVED`; it is explicitly **not external KYB or banking authorization**. The independent receiving-party workflow still needs real institution onboarding, key custody and rotation, mTLS/signing key operations, evidence retention, SLA/retry handling, network trust and interoperability validation.

## 6. Database and release changes

This extension adds Alembic revision `f2a3b4c5d6e7` (after `f1a2b3c4d5e6`) with:

- `destination_public_key_pem` and `destination_key_fingerprint` columns on `v37_data_grants`.
- New `v37_rail_simulations` table with unique `(intent_id, rail)` and parent/intent audit context.

Apply using `python -m alembic upgrade head`. Back up the database and test both upgrade and restore before production rollout.

## 7. Release gates — do not remove

The existing `/health/ready` production fail-closed checks must remain in force. The following gates are still outstanding:

1. PostgreSQL integration tests for concurrent shared-budget admission, simultaneous consume/replay, failover, deadlock/timeout recovery and process restart.
2. Full end-to-end browser + API + PostgreSQL verification for onboarding, fleet controls, data grant/export, receiver claims and payment state/reconciliation.
3. Independent application/cryptographic security audit, threat model, penetration test, dependency and supply-chain review.
4. Managed KMS/HSM signing and encryption-key lifecycle; no local PEM signing key in a production image or distributable source archive.
5. Named staff identities, MFA, granular RBAC, reviewer separation-of-duties, short-lived sessions and privileged-action attribution (the shared root administrator API key is sandbox/internal-only).
6. KYC/KYB and trusted identity-provider integration with evidence verification and monitoring.
7. Real open-banking/TPP and stablecoin providers, regulatory/contractual clearance, sandbox conformance, webhook validation, operational key custody and independently verified settlement/reconciliation.
8. Production data governance: data-protection impact assessment, lawful basis, purpose/retention, deletion propagation, incident response and recipient trust.
9. Multi-organization treasury hierarchy, multi-currency FX risk, and group-wide concurrency/budget enforcement if the product is marketed to global enterprise treasuries.
10. Disaster recovery, backup restore, observability, alerting, incident runbooks, rate limits, WAF/DDoS protection, secure headers/CSP, TLS, secrets rotation and capacity testing.

**Readiness statement:** this package improves the local product demonstration and adds real, testable control-plane logic. It is not production-ready for live financial activity. Do not enable live payment or external data routes until each applicable gate is evidenced and the environment's readiness endpoint reports ready.
