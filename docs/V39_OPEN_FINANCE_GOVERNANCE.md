# Paari v3.9 — Open Finance Context Governance

**Release classification:** local development / sandbox integration release. This release connects the existing Setu Account Aggregator lifecycle to Paari consent binding, encrypted financial-context snapshots and optional payment-policy freshness enforcement. It does not certify an FIU/FIP integration, initiate payments through Setu, or establish production readiness.

## What changed

1. **Consent-to-mandate binding API.** An organization can bind an ACTIVE Setu consent to an ACTIVE `UserPaymentMandate` only when the consent subject and mandate user match within the same organization. `SETU_AA_REQUIRE_SIGNED_MANDATE=1` is the default; the mandate signature is reverified before data-session creation and context retrieval. Revoked bindings cannot be reactivated; a new consent is required.
2. **Completed data-session persistence.** When Setu reports `COMPLETED` or `PARTIAL`, Paari normalizes the FI payload into provider-neutral account summaries and persists a `FinancialContextSnapshot`. The raw Setu response is encrypted with AES-256-GCM; Paari also records a SHA-256 digest, tenant, consent, session, source freshness timestamp (the oldest returned account-balance timestamp), completeness and normalizer version. An absent source timestamp, incomplete account summary or provider `PARTIAL` session is not treated as fresh. Raw transaction details are not returned by the organization context endpoint.
3. **Tenant-scoped context retrieval.** The organization can retrieve the latest available normalized context only through its `X-Paari-Control-Key` and `X-Paari-Org` credentials. Consent revocation invalidates its bindings and snapshots locally before attempting Setu-side revocation. If the provider is unavailable, the API still blocks local use and returns `provider_revocation_pending=true` so an operator can retry. Binding revocation prevents that mandate from retrieving or using the context.
4. **Payment governance integration.** The payment-intent path records `open_finance_context` evidence (connection, consent, snapshot, freshness, completeness, account count and currency list). By default this is OBSERVE-only and does not block existing payment demonstrations. When `PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT=1`, missing, inactive, stale, partial or incomplete context blocks payment intent admission and is rechecked at review release and provider-consumption time.
5. **Context is not authority.** Account Aggregator data is an input to risk and governance. It never creates a user mandate, agent delegation, payment instrument, beneficiary approval or bounded payment authorization. It does not authorize a payment or prove that funds are available for a particular payment rail.

## Setu lifecycle API

All `/integrations/setu-aa/v1/*` lifecycle routes require an organization control key and tenant header.

### 1. Create consent

`POST /integrations/setu-aa/v1/consents`

```json
{
  "subject_user_id": "user-123",
  "purpose": "cash-flow context for delegated supplier payments",
  "consent": {
    "vua": "user-handle@setu",
    "consentDuration": {"unit": "MONTH", "value": "1"}
  }
}
```

The `consent` payload is the Setu sandbox request body. Paari stores tenant/user linkage, the provider consent reference, a digest of the stated purpose and lifecycle status; it does not return or persist the user's VUA in the consent view.

### 2. Refresh and approve consent

`POST /integrations/setu-aa/v1/consents/{setu_consent_id}/refresh`

The provider must report `ACTIVE`. Pending, revoked or expired provider consent cannot be bound for retrieval.

### 3. Bind active consent to signed user mandate

`POST /integrations/setu-aa/v1/consents/{setu_consent_id}/mandate-binding`

```json
{"mandate_id": "mandate-123"}
```

The mandate must belong to the same organization and consent subject, be ACTIVE and within its validity window. By default, its Ed25519 user signature must verify. The endpoint is tenant-admin gated; the organization must ensure that the user-facing consent and mandate-creation journey has captured the user's explicit intent to associate this data purpose with that mandate.

### 4. Create and poll data session

`POST /integrations/setu-aa/v1/sessions`

```json
{
  "setu_consent_id": "<paari-setu-consent-id>",
  "data_range": {"from": "2026-11-01", "to": "2026-11-21"},
  "data_format": "json"
}
```

`GET /integrations/setu-aa/v1/sessions/{data_session_id}` polls Setu. Once the provider reports `COMPLETED` or `PARTIAL`, Paari validates the provider session/consent references and persists encrypted raw data plus normalized summary. No snapshot is created from a still-pending session.

### 5. Retrieve normalized context

`GET /integrations/setu-aa/v1/mandates/{mandate_id}/financial-context`

Returns normalized account summaries, context provenance, freshness, completeness and an indication that the raw response is encrypted. The raw FI response is not returned by this route.

### 6. Revoke access

- `POST /integrations/setu-aa/v1/bindings/{binding_id}/revoke` revokes one mandate binding.
- `POST /integrations/setu-aa/v1/consents/{setu_consent_id}/revoke` immediately revokes local consent, all active bindings and snapshots, then attempts provider revocation. A provider outage returns `provider_revocation_pending=true`; local use remains blocked and the call can be retried.

## Payment policy settings

| Setting | Default | Purpose |
|---|---|---|
| `SETU_AA_ENABLED` | `false` | Enables Setu sandbox routes when true. |
| `SETU_AA_REQUIRE_SIGNED_MANDATE` | `1` | Requires a valid signed user mandate for binding and retrieval. |
| `PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET` | unset | Dedicated secret used to derive the AES-GCM data-encryption key. |
| `PAARI_V37_DATA_ENCRYPTION_SECRET` | unset | Sandbox compatibility fallback only when the dedicated key is absent. |
| `PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT` | `0` | `1` makes fresh bound context mandatory at admission and execution. |
| `PAARI_FINANCIAL_CONTEXT_MAX_AGE_HOURS` | `24` | Maximum context age when freshness is evaluated; bounded to 15 minutes–90 days. |

Use independently generated secrets of at least 32 characters. Set a dedicated `PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET` for every persistent sandbox. Production key custody must use a managed KMS/HSM adapter and an approved rotation/backup procedure; the environment-secret implementation is not a production key-management solution.

Default `OBSERVE` mode intentionally preserves existing local payment flows when no Open Finance connection exists. Enabling `PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT=1` changes the authorization policy and should only be done for a tenant whose consent, binding and refresh operations have been validated. Regardless of the setting, Setu context never replaces mandate, delegation, SAFR, receiver, treasury, provider or rail checks.

## Payment example

An agent proposes a ₹5,000 supplier payment. Paari first authenticates the Agent Card and session, checks parent delegation, resolves the signed user mandate, applies SAFR, receiver and treasury controls, and evaluates the Open Finance evidence. If a tenant has enabled the fresh-context requirement, Paari requires an ACTIVE Setu consent bound to that exact user's current mandate and a complete, source-timestamped snapshot within the configured freshness window. Only after every independent authorization requirement is satisfied can Paari issue bounded payment authorization. The configured payment provider—not Setu—then handles payment execution and status; Paari records the provider result and audit evidence.

This example describes the intended local protocol. It is not proof of live Indian payment execution or settlement.

## Validation

The v3.9 focused tests cover:

- Signed mandate requirement and rejection of unsigned mandate binding.
- Consent/mandate tenant and subject linkage.
- Completed Setu session normalization and encrypted raw-payload persistence.
- Organization-scoped retrieval of normalized context.
- Binding revocation and retrieval denial.
- Fresh-context-required fail-closed policy behavior.

Run:

```bash
python -m pytest -q tests/setu/test_setu_governance_v39.py tests/setu/test_setu_binding.py tests/setu/test_setu_persistence.py tests/setu/test_setu_normalizer.py
```

The full Setu adapter tests require the `respx` development dependency from `requirements-dev.txt`. A focused pass does not replace a full repository regression run, PostgreSQL migration/concurrency run, live Setu UAT verification or external security review.

## Still outstanding

- Full user-facing consent capture and signed binding UX; the current binding API is organization-admin gated and the organization must prove that its upstream journey captured user intent.
- Provider-specific encrypted FI-data decryption/verification contract for each Setu product version, signed webhook/poll authenticity and production data retention/erasure policy.
- PostgreSQL race/concurrency and failure-recovery testing for multiple simultaneous sessions and snapshots.
- Complete payment provider integration and independent evidence of actual settlement.
- Managed KMS/HSM, HSM-backed key rotation, real KYC/KYB, production RBAC/MFA, operational controls, legal/regulatory assessment and independent penetration testing.

**Release conclusion:** v3.9 connects the local Setu consent lifecycle to persisted financial context and an optional Paari payment-governance gate. It remains a local engineering and sandbox-integration release—not a production-ready or regulator-approved financial service.
