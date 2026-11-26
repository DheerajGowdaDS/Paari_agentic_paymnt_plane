---
goal: Implement a consent-bound Setu AA financial-context lifecycle without weakening Paari payment controls
version: 1.0
date_created: 2026-11-21
last_updated: 2026-11-21
owner: Paari engineering
status: 'Planned'
tags: [feature, setu, account-aggregator, consent, safr, portal, sandbox]
---

# Introduction

![Status: Planned](https://img.shields.io/badge/status-Planned-blue)

Implement the Setu Account Aggregator sandbox lifecycle as a tenant-bound,
consent-first financial-context feature. The feature must not treat AA data as
identity proof, proof of funds, payment authority, or settlement confirmation.
It must preserve Paari's existing mandate, SAFR, bounded-authorization,
provider, reconciliation, and audit invariants.

## 1. Requirements & Constraints

- **REQ-001**: Persist each Setu consent with its Paari organization, requester, provider consent ID, provider status, expiry, consent URL, requested data range, and immutable creation metadata.
- **REQ-002**: Require an organization-scoped administrator credential for every Setu consent, status, revocation, data-session, and financial-context operation; do not use the global local admin key for tenant data access.
- **REQ-003**: Accept Setu notification payloads only after a documented, configured, cryptographically verifiable callback-authentication contract is available; otherwise record no trusted status transition from a callback.
- **REQ-004**: Create a Setu data session only for a persisted, tenant-owned consent whose latest provider status is `ACTIVE` and whose requested date range is inside the consent's permitted range.
- **REQ-005**: Encrypt raw decrypted Setu FI payloads at rest with a dedicated versioned data-encryption key, retain only the minimum normalized facts required for policy evaluation, and never expose raw FI data to agents.
- **REQ-006**: Normalize Setu deposit-account summaries and transactions into a provider-neutral, tenant-bound financial-context model with source, consent, data-session, freshness, and provenance fields.
- **REQ-007**: Add SAFR financial-context checks as an opt-in advisory policy first. A missing, stale, incomplete, or unverifiable financial context must produce `OBSERVE` or `ESCALATE`; it must never mint an `ALLOW` decision by itself.
- **REQ-008**: Render parent/organization-facing consent state, linked-account summaries, freshness, and Setu trace identifiers in the Organization Portal without embedding administrator keys, access tokens, raw statements, PAN, account numbers, or decrypted FI payloads.
- **REQ-009**: Add a simulated-provider end-to-end test proving that an approved Setu consent and fresh normalized context may contribute evidence to SAFR, while Paari's independent delegation, mandate, risk, and bounded-authorization checks remain required.
- **REQ-010**: Preserve the existing Mastercard adapter and the existing Setu routes during migration; new lifecycle routes must be additive and versioned under `/integrations/setu-aa`.
- **REQ-011**: Persist an explicit `SetuConsentMandateBinding` only after server-side verification that the Setu consent and signed `UserPaymentMandate` have the same `org_id` and `subject_user_id`; require this active binding before a financial-context snapshot can be used for a payment-risk evaluation.
- **SEC-001**: Never log Setu client secrets, access tokens, full VUA values, full account numbers, PAN, addresses, or decrypted FI payloads.
- **SEC-002**: Hash or encrypt sensitive external identifiers before audit persistence; audit events must contain only pseudonymous identifiers and consent/session state transitions.
- **SEC-003**: Enforce organization ownership in SQL queries, route authorization, callback lookup, and portal responses. A consent/session/context from one `org_id` must never be visible to another organization.
- **SEC-004**: Make Setu callback verification fail closed. If Setu does not supply a stable signed webhook contract, use polling only and label callbacks as untrusted observations.
- **SEC-005**: Do not use AA balance, account availability, consent approval, or a Setu notification as a substitute for authenticated user mandate, provider authorization, capture, reconciliation, or settlement evidence.
- **CON-001**: Use Alembic migrations only; do not create tables at import time.
- **CON-002**: Support both SQLite test databases and PostgreSQL. Run `alembic check` against SQLite and PostgreSQL after model changes.
- **CON-003**: Do not run two pytest processes concurrently because the repository shares a SQLite test database.
- **CON-004**: Setu sandbox credentials remain in ignored `.env`; source code, test fixtures, reports, and migration files must contain no real credentials or FI data.
- **GUD-001**: Follow the existing `app/integrations/setu/client.py` adapter boundary, `app/audit.py` append-only audit path, `app/v37/risk.py` risk-gate pattern, and `app/portal_extension.py` authenticated portal-feed pattern.
- **PAT-001**: Treat `ProviderTransaction` settlement provenance and Setu financial context as separate domains. Setu context is evidence for governance only; it never changes a provider transaction state.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Create encrypted, organization-scoped consent and financial-context persistence with a forward-only migration.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Add `SetuConsent`, `SetuConsentMandateBinding`, `SetuDataSession`, and `FinancialContextSnapshot` SQLAlchemy models in `app/models.py`. Require `org_id`, provider identifiers, status, timestamps, encrypted raw-payload reference or ciphertext, normalized context version, and unique `(org_id, provider_consent_id)` / `(org_id, provider_session_id)` constraints. Require the binding to retain the server-resolved `subject_user_id`, Setu consent ID, and Paari mandate ID. Do not add financial fields to `PaymentIntent`. |  |  |
| TASK-002 | Create a new Alembic revision after the current head migration. Create the three tables, tenant indexes, unique constraints, and foreign keys; seed nothing; include SQLite and PostgreSQL-compatible upgrade/downgrade operations. |  |  |
| TASK-003 | Add `app/financial_context/storage.py` with envelope-encryption helpers that use a new `PAARI_SETU_DATA_ENCRYPTION_SECRET`, a versioned ciphertext format, SHA-256 payload digest, and redacted identifier helpers. Reject missing/placeholder secrets whenever Setu persistence is enabled. |  |  |
| TASK-004 | Add model/migration tests in `tests/test_setu_persistence.py` for tenant isolation, uniqueness, consent-to-mandate subject matching, ciphertext round-trip, and absence of plaintext account/PAN fields in audit detail. |  |  |

### Implementation Phase 2

- GOAL-002: Implement an organization-authorized Setu consent and session lifecycle with polling-based truth.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-005 | Extend `app/integrations/setu/client.py` with typed provider calls for consent status, consent revocation, data-session creation, and data-session retrieval. Preserve existing token caching and convert upstream failures to `SetuAAUpstreamError` without including provider secrets or bearer tokens. |  |  |
| TASK-006 | Replace global-admin access for lifecycle operations in `app/integrations/setu/router.py` with the existing organization-admin-key verification pattern from `app/models.py::OrganizationAdminKey`. Require `org_id` resolution from the key server-side; reject caller-provided organization IDs. Keep `/status` non-sensitive. |  |  |
| TASK-007 | Add lifecycle routes that create a persisted consent, poll and persist consent status, revoke a tenant-owned consent, create a valid data session, poll session status, and fetch raw FI data only after `PARTIAL` or `COMPLETED`. Route responses must contain only safe identifiers, state, timestamps, and normalized summaries. |  |  |
| TASK-008 | Add `app/integrations/setu/service.py` to own status transitions, provider-to-local status mapping, date-range validation, encrypted raw payload persistence, audit recording, and tenant checks. The router must not contain persistence or policy logic. |  |  |
| TASK-009 | Add API tests in `tests/test_setu_lifecycle.py` using `respx`: active-consent session creation, rejection of pending/revoked/foreign consent, data-range bounds, partial/completed retrieval, encrypted raw-data persistence, and route-level organization isolation. |  |  |

### Implementation Phase 3

- GOAL-003: Add a verified notification design without trusting unsigned provider callbacks.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-010 | Obtain and record the Setu production and sandbox webhook authentication specification before implementation. Add the exact provider-authentication settings to `docs/integrations/SETU_AA_SANDBOX.md`; do not invent an HMAC header or signature format. |  |  |
| TASK-011 | Implement `POST /integrations/setu-aa/webhooks` only after TASK-010 is complete. Verify the raw request body using the documented Setu mechanism before parsing JSON, resolve the tenant through the persisted consent/session, deduplicate by provider notification ID, and append a redacted audit event. |  |  |
| TASK-012 | If Setu has no verifiable callback contract for the configured product, omit the webhook route and implement scheduled/poll-on-read reconciliation in `app/integrations/setu/service.py`; expose callback status as `UNVERIFIED_NOT_CONFIGURED`. |  |  |
| TASK-013 | Add notification tests in `tests/test_setu_notifications.py` for valid update, forged update rejection, replay rejection, missing tenant relation rejection, and audit redaction. |  |  |

### Implementation Phase 4

- GOAL-004: Normalize Setu FI data and expose tenant-safe financial-context snapshots.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-014 | Extend `app/financial_context/normalizer.py` with `normalize_setu_fi_data(payload)` that extracts only masked account reference, account type, currency, balance, balance timestamp, transaction window, transaction count, and source FIP/session metadata. Reject malformed data and preserve unknown values as null rather than inferring them. |  |  |
| TASK-015 | Store the normalized result as `FinancialContextSnapshot` with source `setu_aa`, consent ID, data-session ID, source freshness timestamp, completeness state, and payload digest. Store raw provider FI data only through TASK-003 encryption helpers. |  |  |
| TASK-016 | Add organization-admin routes for a consent's latest normalized snapshot and freshness state. Return masked identifiers and summary aggregates only; deny cross-tenant reads. |  |  |
| TASK-017 | Add normalizer tests in `tests/test_setu_normalizer.py` for valid DEPOSIT data, partial sessions, missing summary fields, malformed FI data, PII redaction, and snapshot source provenance. |  |  |

### Implementation Phase 5

- GOAL-005: Add opt-in SAFR financial-context evidence without weakening mandatory payment controls.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-018 | Add a tenant-owned `FinancialContextPolicy` model and migration with state, currency, minimum post-payment reserve, maximum freshness seconds, required completeness state, and enforcement mode `OBSERVE` or `ESCALATE`. Do not create an `ALLOW` mode. |  |  |
| TASK-019 | Implement `app/safr/financial_context.py` to locate a fresh, tenant-owned snapshot for the payment's parent/organization context, calculate a conservative post-payment reserve only when currency and timestamp are present, and return structured reason evidence. Missing/stale/currency-mismatched data must return `OBSERVE` or `ESCALATE`, never a successful payment authorization. |  |  |
| TASK-020 | Integrate the financial-context evaluator into the existing SAFR/control-plane decision path before bounded authorization creation. Preserve the existing order: request proof, identity, delegation, mandate, risk, control plane, SAFR, bounded authorization. Add reason codes such as `FINANCIAL_CONTEXT_STALE`, `FINANCIAL_CONTEXT_INSUFFICIENT_RESERVE`, and `FINANCIAL_CONTEXT_UNAVAILABLE`. |  |  |
| TASK-021 | Add tests in `tests/test_setu_safr_context.py` proving: fresh context may add evidence; insufficient reserve escalates; stale/missing context cannot produce allow; a valid context cannot override a denied mandate, delegation, risk, or control-plane decision. |  |  |

### Implementation Phase 6

- GOAL-006: Add portal visibility and a simulated end-to-end demonstration.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-022 | Add authenticated organization-scoped portal feeds in `app/portal_extension.py` for Setu consent status, linked masked accounts, snapshot freshness/completeness, and SAFR financial-context evidence. Do not include raw FI data, VUA, account numbers, OAuth tokens, or administrator credentials. |  |  |
| TASK-023 | Add a Setu AA section to `web/organization/index.html` using existing portal authentication and API patterns. Show sandbox-only labels, consent URL handoff status, data freshness, and incomplete/failed states. Do not embed secrets or use browser-side provider calls. |  |  |
| TASK-024 | Add portal tests in `tests/test_setu_portal.py` for tenant isolation, no secret/PII rendering, stale-context warning, and the absence of financial data from the unauthenticated public HTML shell. |  |  |
| TASK-025 | Add `scripts/setu_aa_agentic_demo.py` and `tests/test_setu_agentic_demo.py` using `respx` and a simulated provider. Demonstrate: tenant-bound consent -> active status -> completed session -> normalized snapshot -> SAFR evidence -> existing mandate/delegation controls -> bounded authorization -> simulated provider/reconciliation. Assert that removal of consent/context does not create payment authority. |  |  |
| TASK-026 | Update `docs/integrations/SETU_AA_SANDBOX.md` and `docs/MASTERCARD_TO_SETU_AA_MIGRATION_REPORT.md` with final routes, demo commands, test counts, sandbox-only limits, and the explicit statement that Setu data does not execute payments. |  |  |

## 3. Alternatives

- **ALT-001**: Store only Setu consent IDs and fetch provider data for every policy decision. Rejected because it creates provider availability coupling, lacks reproducible governance evidence, and risks repeated FI retrieval outside consent frequency.
- **ALT-002**: Use Setu AA balances as an automatic `ALLOW` signal. Rejected because financial context is not identity proof, payment authority, confirmed available funds, or settlement evidence.
- **ALT-003**: Accept Setu notifications without verification because the sandbox docs show payloads. Rejected because an unverified callback permits forged consent/session state.
- **ALT-004**: Place Setu logic inside `app/routers/payments.py`. Rejected because provider transport, consent lifecycle, encrypted data handling, and portal views are distinct from the payment governance boundary.

## 4. Dependencies

- **DEP-001**: Setu Bridge AA sandbox product with Client ID, Client Secret, Product Instance ID, configured consent object, and approved callback/authentication documentation.
- **DEP-002**: A new independently generated `PAARI_SETU_DATA_ENCRYPTION_SECRET` of at least 32 characters, stored only in ignored local/deployment secret storage.
- **DEP-003**: Existing organization-admin-key issue/verification functions and existing `app.audit.record_audit` append-only audit implementation.
- **DEP-004**: Setu sandbox test customer/mobile and consent webview access for real sandbox verification after the mock/respx test suite passes.
- **DEP-005**: PostgreSQL test database ending in `_test` for schema parity and tenant/concurrency checks.

## 5. Files

- **FILE-001**: `app/models.py` — add tenant-bound Setu consent, session, snapshot, and policy models.
- **FILE-002**: `alembic/versions/<new_setu_lifecycle_revision>.py` — add forward-only schema migration.
- **FILE-003**: `app/integrations/setu/client.py` — extend typed Setu AA transport methods.
- **FILE-004**: `app/integrations/setu/service.py` — new lifecycle, status, encryption, audit, and tenant-ownership service.
- **FILE-005**: `app/integrations/setu/router.py` — replace global local-admin data operations with organization-authorized lifecycle routes.
- **FILE-006**: `app/financial_context/storage.py` — new encrypted raw-payload storage helpers.
- **FILE-007**: `app/financial_context/normalizer.py` — add Setu FI normalization.
- **FILE-008**: `app/safr/financial_context.py` — new conservative context evaluator.
- **FILE-009**: `app/portal_extension.py` — add authenticated Setu portal feeds.
- **FILE-010**: `web/organization/index.html` — add sandbox-labeled consent/context dashboard.
- **FILE-011**: `scripts/setu_aa_agentic_demo.py` — new simulated end-to-end demonstration.
- **FILE-012**: `docs/integrations/SETU_AA_SANDBOX.md` — update operational instructions and limitations.

## 6. Testing

- **TEST-001**: Verify SQLite and PostgreSQL migrations create the Setu lifecycle schema and `alembic check` reports no drift.
- **TEST-002**: Verify organization-admin authorization and cross-tenant denial for every Setu consent/session/context route.
- **TEST-003**: Verify provider token caching, upstream error redaction, consent state mapping, and date-range enforcement with `respx`.
- **TEST-004**: Verify encrypted raw FI payload storage and ensure audit/HTTP output contains no access token, PAN, full account number, or decrypted payload.
- **TEST-005**: Verify callbacks are signature-verified and replay-safe, or verify that callbacks are absent and reconciliation is polling-only.
- **TEST-006**: Verify Setu FI normalization handles completed/partial/malformed payloads without inventing unavailable data.
- **TEST-007**: Verify SAFR financial context cannot widen a denial and can only observe or escalate when data is missing, stale, incomplete, or below reserve.
- **TEST-008**: Verify the portal renders only masked tenant-owned data and never ships secrets or raw FI payloads.
- **TEST-009**: Verify the simulated end-to-end path requires independent delegation, mandate, SAFR/control-plane, and bounded authorization even with fresh Setu data.

## 7. Risks & Assumptions

- **RISK-001**: Setu's available webhook authentication contract may differ by product/environment or may not be sufficient for trustworthy inbound processing. The implementation must block callback-driven state changes until verified.
- **RISK-002**: Decrypted FI payloads can contain highly sensitive personal and financial data. Persistence increases breach impact and requires encryption, retention, deletion, access control, and audit design.
- **RISK-003**: A financial-context reserve calculation can be stale, incomplete, currency-incompatible, or inconsistent with provider-cleared funds. It must remain advisory/escalatory.
- **RISK-004**: Linking data context to a payment decision may create jurisdiction-specific privacy, consent, and FIU compliance obligations that are outside this sandbox's current assurance.
- **ASSUMPTION-001**: The configured Setu Bridge product is an AA/FIU sandbox product and its Product Instance ID is tenant-independent at the provider layer; Paari will nevertheless enforce tenant ownership locally.
- **ASSUMPTION-002**: The existing organization-admin-key mechanism can be reused or extended without exposing a global administrator credential to organization users.
- **ASSUMPTION-003**: Setu sandbox provides test consent webview access and an approved test mobile/FIP flow for the final manual verification.

## 8. Related Specifications / Further Reading

- `docs/integrations/SETU_AA_SANDBOX.md`
- `docs/MASTERCARD_TO_SETU_AA_MIGRATION_REPORT.md`
- `docs/STAGE1_REGULATORY_PITCH_BOUNDARIES.md`
- `docs/SECURITY.md`
- Setu AA quickstart: <https://docs.setu.co/data/account-aggregator/quickstart>
- Setu consent flow: <https://docs.setu.co/data/account-aggregator/api-integration/consent-flow>
- Setu data flow: <https://docs.setu.co/data/account-aggregator/api-integration/data-apis>
- Setu notifications: <https://docs.setu.co/data/account-aggregator/api-integration/notifications>
