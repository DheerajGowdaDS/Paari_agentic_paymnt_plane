# Paari institutional control plane — architecture v2

## Product boundary

**The agent proposes. Paari decides. A regulated partner executes.** Paari is a policy, identity, risk and authorization control plane, not a new payment rail and not a custodian of bank credentials. The bank, PSP, treasury or stablecoin provider remains authoritative for account eligibility, payment execution, final settlement state and rail-specific obligations.

## Nine layers

1. **Organization and agent management.** Organization-scoped administration and existing parent/delegation-based agent registration. Root administration can suspend/reactivate tenants; suspension revokes tenant admin keys and strict payment governance rejects suspended tenants. Root administration issues high-entropy organization control keys; raw keys are disclosed once and only hashes are persisted.
2. **Agent identity and credential.** Existing signed delegation, registered key, Paari credential/card, proof-of-possession session and replay protection. An Agent Card is descriptive evidence, not spend authority.
3. **Principal, user, consent and mandate.** A principal is registered under an issuer/identity-provider namespace and begins `PENDING`. Only a separate authorized verification operation may activate it. Payment authority still requires a current, signed user mandate; a principal row alone is not consent.
4. **Resource and data governance.** Bank/open-banking accounts, treasury accounts, stablecoin wallets, provider mandates, datasets and APIs are represented by opaque resource references. Time-bounded grants specify subject, resource, action and consent reference. No passwords, raw account credentials, keys, tokens, card numbers or PINs belong in resource records.
5. **Financial authority and intent.** Existing payment intent and mandate objects bind amount, currency, beneficiary/merchant, purpose, action, agent, principal and provider instrument/resource. Amounts use integer minor units.
6. **Policy and risk.** Versioned, tenant-owned policy bundles define evidence and risk thresholds. The initial risk model is deterministic and explainable, based on transaction-to-limit ratio and recent intent velocity. It is an initial rules baseline, not a validated fraud model.
7. **Bounded authorization.** Existing single-use, expiring, transaction-bound authorization continues to gate execution. Mandatory authorization failures cannot be overridden by risk scores or agent/LLM-generated traces.
8. **Execution gateway.** The existing `PaymentProvider` and `AgenticPaymentProvider` contracts isolate execution from governance. Razorpay is the currently implemented non-agentic adapter; the autonomous provider seam deliberately refuses when no real, documented provider contract is configured. Open-banking and stablecoin are supported as governed resource types, **not yet as certified, live execution adapters**. Implement and certify each rail-specific adapter before enabling it for real funds.
9. **Reconciliation and audit.** Existing provider state machine, webhook verification, direct-read corroboration, reconciliation and hash-chained audit remain. A hash chain detects changes; production deployments must additionally export/checkpoint audit heads to independently controlled append-only storage.

## Payment decision path

```text
Agent request + sender-constrained proof
  -> authenticate agent, tenant and parent delegation
  -> resolve active user mandate and verify its signature
  -> resolve principal through a unique issuer-scoped mapping
  -> resolve exactly one live provider binding and its source resource
  -> verify agent AND principal grants for payment:execute
  -> verify policy version, beneficiary, purpose, currency and financial limits
  -> calculate evidence quality and deterministic risk score
  -> SAFR-style disposition: DENY | ESCALATE | AUTO_EXECUTE | OBSERVE
  -> only eligible decision: mint transaction-bound single-use authorization
  -> provider adapter submits idempotently
  -> verified provider evidence + reconciliation confirms settlement
  -> persist decision, state transitions and audit events
```

Strict institutional mode (`PAARI_CONTROL_PLANE_ENFORCEMENT=1`) fails closed when any required principal, signed mandate, source resource, matching provider binding, active policy or resource grant is missing or ambiguous. It does not choose the first among ambiguous principals/bindings. `ESCALATE` goes through existing step-up/review controls; `OBSERVE` is durably recorded, but the initial version's score is not a replacement for partner fraud controls.

## Administration API

Prefix: `/control/v1`. Organization operations require `X-Paari-Org` and an organization-bound `X-Paari-Control-Key` with the required scope. Key issuance/revocation is root-admin-only and uses `X-Admin-Api-Key`.

| Endpoint | Purpose |
|---|---|
| `POST /control/v1/organizations/{org_id}/status` | Root-only tenant suspension/reactivation; suspension revokes tenant control keys |
| `POST /control/v1/admin-keys` | Issue a tenant-scoped key (raw value returned once) |
| `POST /control/v1/admin-keys/{key_id}/revoke` | Revoke a tenant key |
| `POST /control/v1/principals` | Register a pending issuer-scoped principal |
| `POST /control/v1/principals/{principal_id}/attest` | Record an organization attestation and activate at low assurance; does not verify an identity provider |
| `POST /control/v1/principals/{principal_id}/revoke` | Revoke principal and its active principal grants |
| `POST /control/v1/resources`, `GET /control/v1/resources` | Register/list opaque governed resources |
| `POST /control/v1/resources/{resource_id}/grants` | Grant time-bounded resource/action access |
| `POST /control/v1/grants/{grant_id}/revoke` | Revoke a grant |
| `POST /control/v1/policies` | Create immutable policy version; optionally activate |
| `GET /control/v1/policies/active` | Read active policy bundles |
| `GET /control/v1/decisions?disposition=ESCALATE` | Query tenant-scoped disposition history for risk operations |
| `GET /control/v1/decisions/{decision_id}` | Read the policy version, reasons and evidence/risk scores for one decision |

Principal attestation records an organization-provided reference and activates the principal at **low assurance**; it does **not** call a KYC/KYB provider or cryptographically verify an OIDC/FAPI identity token. Client-supplied assurance elevation is prohibited. Low assurance maps to a score below the default auto-execution threshold and therefore escalates rather than auto-executes. A trusted identity/KYB adapter must independently set higher assurance after validating issuer, subject, audience, expiry, signature, nonce and revocation status before production auto-execution is enabled.

## Tenant isolation and secrets

- Tenant ID is taken from a key-bound header and verified against the stored key row; request bodies cannot choose the tenant.
- Agent and principal must both have active grants scoped to the exact resource/action.
- Provider account references are opaque. Actual credentials belong in a secret manager, outside these tables and APIs.
- Never route by untrusted client-supplied provider/class names. If a new provider adapter is added, map it through deployment-owned allowlisted configuration, implement provider event authentication and idempotency, and test cross-tenant boundaries.
- Run the full Alembic migration chain (`alembic upgrade head`), including `b3c4d5e6f7a8` schema normalization, before enabling strict mode.

## v2.7 extension — UAE-first SAFR Governance Envelope and portability

Paari v2.7 extends the original nine business domains with a formal ingress contract for each protected action and a signed identity/delegation portability package. It does not replace the existing payment-intent and bounded-authorization path.

- `app/safr/envelope.py` defines the versioned `paari.safr.governance-envelope` contract, action digest, freshness and Ed25519 verification.
- `POST /control/v1/governance/envelopes/validate` checks current tenant-scoped identity/delegation, principal/resource, grants and payment authority bindings, stores a unique anti-replay receipt and appends an audit event. It returns `VALIDATED_ONLY`; it neither evaluates all policy nor issues authorization.
- `app/portability.py` builds/verifies signed Agent Card and parent-delegation artifacts using an out-of-band Paari issuer trust anchor. Authority is never carried over to a destination tenant.
- `app/identity_providers/contracts.py` gives KYC/KYB providers a replaceable contract, not a live identity integration.
- `PAARI_HOME_JURISDICTION=AE` advertises a UAE-first deployment default; it does not enable a regulated service or a rail.

See `docs/UAE_GLOBAL_SAFR_ARCHITECTURE_V2_7.md`, `docs/SAFR_CONFORMANCE_MATRIX_V2_7.md`, and `docs/UAE_IDENTITY_KMS_AND_OPEN_FINANCE_V2_7.md` for scope and gaps.
