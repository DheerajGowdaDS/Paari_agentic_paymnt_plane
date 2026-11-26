# Paari Two-Workspace Product Portal — Integration Guide

This package separates Paari's internal platform operations from the external parent/organization experience. It is an additive UI/API integration for the Paari v3.7.1 backend; it does not replace the core identity, payment, mandate, governance, provider, reconciliation, or audit services.

## Package contents

- `web/paari_product_portal.html` — two-workspace responsive product UI.
- `app/portal_extension.py` — additive parent-facing feeds, Agent Card verification, Paari platform operations and platform-scoped read/action endpoints.
- `app/portal_page.py` — serves the HTML at `/portal` on the same origin as the API.
- `MAIN_PY_INTEGRATION.txt` — exact `app/main.py` additions.

## 1. Install

Copy the files into the corresponding locations in the Paari repository:

```text
web/paari_product_portal.html
app/portal_extension.py
app/portal_page.py
```

Apply the two imports and two `include_router` calls from `MAIN_PY_INTEGRATION.txt` in `app/main.py`.

The portal is then served from:

```text
http://127.0.0.1:8000/portal
```

Serving the UI and API from the same origin is recommended. If you host the HTML separately, configure an explicit CORS allowlist and set the API base URL in the portal; do not use wildcard CORS with credentials.

## 2. Configure platform administrator access

The Paari Platform Console uses the existing root administrator authentication boundary (`PAARI_ADMIN_API_KEY`). Configure a strong random secret of at least 32 characters in the backend environment. Do not put the key in HTML, source control, local storage, or a distributable `.env` file.

For platform-wide, multi-tenant operations, leave `PAARI_ADMIN_ORG` unset/empty. A non-empty `PAARI_ADMIN_ORG` intentionally scopes older admin surfaces and can cause platform-wide parent/tenant visibility to be incomplete.

The portal holds the entered key in JavaScript memory only for the current page session. Disconnect clears it. This is suitable for a controlled internal sandbox/demo, not the final public production authentication model.

## 3. Two workspaces

### A. Paari Platform Console — internal Paari use

Access it from **Paari Console** in the top navigation. It requires the root platform administrator key and provides:

- Global overview and attention items across tenants.
- Parent onboarding review queue and parent directory.
- Institution/provider application review queue where v3.6 provider applications exist.
- Tenant directory, tenant provisioning, tenant status operations and tenant-scoped control-key issuance.
- Cross-tenant agent fleet visibility and emergency agent revocation.
- Platform-wide payment tracker with per-payment detail and audit evidence.
- Read-only cross-tenant policy bundles and control-plane decisions.
- Platform-wide audit event view.

The platform console's global role is intentionally distinct from an organization control key. Organization control keys are tenant-scoped and are issued through the existing `/control/v1/admin-keys` endpoint; the secret is returned once.

### B. Organization Portal — parent/client use

External users register as an individual or organization, await Paari's manual approval, then log in after approval. An approved parent can register agents, receive the Paari-signed Agent Card, manage its own agents/treasury context and view its own payment activity. Parent-facing transaction feeds are scoped using the authenticated parent token; they are not global.

## 4. Required tenant provisioning order

For a new organization that needs a formal tenant boundary, follow this sequence:

1. Parent submits registration through the existing v3.6 onboarding route.
2. Paari reviews and approves the parent in the Platform Console.
3. Paari provisions a new tenant from Tenant Management.
4. Parent logs into the Organization Portal.
5. Parent registers agents under the now tenant-bound parent.
6. Paari returns its signed Agent Card and credential material according to the existing registration contract.

The additive provisioning endpoint deliberately refuses to provision a tenant for an unapproved parent. It also refuses to silently reassign a parent who already has agents or is already bound to a different organization. Existing legacy parents/agents should be migrated through a separately designed migration process, not by changing `org_id` in place.

## 5. API additions

The router is mounted at `/portal/v1` and adds the following families:

- Parent scoped: `/parent/overview`, `/parent/agents`, `/parent/transactions`, `/parent/transactions/{intent_id}`.
- Public Agent Card verification: `/public/agent-cards/{agent_id}/verify`, `/agent-cards/{agent_id}/qr.svg`.
- Paari platform: `/platform/overview`, `/platform/parents`, `/platform/parents/pending`, `/platform/parents/{id}/review`, `/platform/providers/pending`, `/platform/providers/{id}/review`, `/platform/tenants`, `/platform/tenants/provision`, `/platform/agents`, `/platform/agents/{id}/revoke`, `/platform/payments`, `/platform/payments/{intent_id}`, `/platform/governance`, `/platform/audit`.

All `/platform/*` routes require the root Paari administrator key. Parent routes require the parent access token. Public Agent Card verification returns signed card details and signature validation only; it does not authorize a payment or establish that a mandate is currently active.

The portal also calls existing v3.6 onboarding/agent APIs, existing `/v1/orgs` and `/control/v1` control-plane APIs, and v3.7 treasury endpoints. The additive router does not replace those endpoints.

## 6. Multi-tenant governance boundary

- Platform Console: global monitoring and Paari-level operations.
- Organization Portal: the authenticated parent's own agents, payment requests and account scope.
- Organization control-plane administration: use the relevant `X-Paari-Org` and tenant-scoped `X-Paari-Control-Key` on the existing control-plane routes.
- Platform governance screen is read-only. Tenant policy mutation remains within the tenant-scoped control-plane key boundary; the root console must not silently edit an organization's policy on its behalf.

## 7. Run and validate

Use the existing v3.7.1 environment and apply migrations before starting the app:

```bash
python -m alembic upgrade head
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/portal`.

Run existing tests, then add integration acceptance tests for:

- Pending parent cannot log in/register agents until Paari approval.
- Unapproved parent cannot be provisioned as a tenant.
- Approved parent can be provisioned only once and before agent registration.
- Parent cannot read another parent's agents or transactions.
- Tenant A control key cannot read/write Tenant B resources.
- Root Platform Console can read cross-tenant metrics but is authenticated only by the root administrator key.
- Platform agent revocation invalidates credentials and outstanding authorizations.
- Platform payment details return only persisted audit evidence; PAID remains provider-confirmed only.

## 8. Production security notes

This is a production-oriented UI and additive backend integration, not a production security certification. The current shared root API key is a sandbox/internal-operations authentication method. Before public production use, replace browser-entered shared admin keys with named Paari staff identities, MFA, RBAC, short-lived server-side sessions, reviewer attribution, approval separation-of-duties and auditable privileged actions. Enforce HTTPS, rate limiting, CSP, secure cookie/session controls, key rotation and operational monitoring. Keep KYC/KYB and managed KMS/HSM fail-closed requirements from the v3.7.1 technical blueprint.

Do not treat an organization/provider application approval in this console as payment-provider certification, banking authorization, regulatory approval or settlement connectivity. Provider sandbox/live integrations remain separate engineering and onboarding work.
