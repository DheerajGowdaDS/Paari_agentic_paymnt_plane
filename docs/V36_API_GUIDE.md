# v3.6 API guide — backend only

Base URL: `http://127.0.0.1:8000`. Complete request/response definitions at `/docs` (FastAPI OpenAPI). **These examples use fictional data only.** All amounts are integer minor units (INR paise).

| Stage | Method / route | Authentication | Main fields/outcome |
| --- | --- | --- | --- |
| Read demo agreements | `GET /v36/agreements` | Public | Version + SHA256 + demo text |
| Parent registration | `POST /v36/parents/register` | Public | `parent_type`, `name`, `identifier` (PAN/GSTIN), representative details, `password`, accept checkboxes → parent ID + registration reference |
| Check registration | `GET /v36/parents/status/{registration_reference}` | Secret reference | Pending, approved or rejected only |
| Parent review | `POST /v36/admin/parents/{parent_id}/review` | `X-Admin-Api-Key` | approve flag, identity/contact/authority manual checks, reviewer note |
| Parent login | `POST /v36/parents/login` | ID + password | Parent access token valid 30 minutes; pending parents blocked |
| Agent registration | `POST /v36/agents/register` | `Authorization: Bearer <parent token>` | `basics`, `agent_public_key_pem`, `delegation`, `escalation_contact`, `accept_agent_security` → signed card + credential |
| Create sandbox mandate | `POST /v36/mandates/create` | Parent bearer token | `agent_id`, limits, merchant allowlist, currency, validity and explicit payer authority confirmation |
| Revoke agent | `POST /v36/agents/{agent_id}/revoke` | Parent bearer token | Revokes agent and credentials |
| Revoke mandate | `POST /v36/mandates/{mandate_id}/revoke` | Parent bearer token | Revokes consent |
| Provider registration | `POST /v36/providers/register` | Public | Legal entity, registration, official contact, representative, rail, currencies, agreement checkboxes |
| Provider review | `POST /v36/admin/providers/{provider_id}/review` | Admin key | Manual checks and approval |
| Publish provider requirements | `POST /v36/admin/providers/{provider_id}/requirements` | Admin key | `required_context_fields`, amount cap, currency → next version |
| Read active requirements | `GET /v36/providers/{provider_id}/requirements` | Public | Current approved requirements |
| Create payment intent | `POST /payments/intent` | Agent session + sender-constrained proof | Existing payment fields **plus `provider_id` for v3.6 agents**; policy checked against mandate and provider |
| Consume bounded authorization | `POST /payments/authorizations/{authorization_id}/consume` | Agent session + proof | Rechecks provider policies + existing risk, federation, mandate, receiver controls before local simulator call |

### Example simplified person onboarding

```json
{
  "parent_type": "person", "name": "Ravi Kumar", "identifier": "ABCDE1234F",
  "representative_name": "Ravi Kumar", "representative_email": "ravi@example.invalid",
  "representative_phone": "9000000000", "password": "unique-long-random-password",
  "accept_terms": true, "accept_privacy": true, "accept_agent_security": true
}
```

Organization registration changes `parent_type` to `organization`, sends a 15-character GSTIN, and uses the organization name as `name`. **Format checking is not government identity verification.** Agreements returned by the `/v36/agreements` API are development-only templates, not final legal texts.

### Four-section agent request

```json
{
  "basics": {"name":"PurchaseBot","agent_type":"shopping_assistant","purpose":"Pay approved suppliers","description":"Supplier payments"},
  "agent_public_key_pem":"<agent public key created by the SDK>",
  "delegation":{"capabilities":["make_payment"],"limit_minor_units":100000,"currency":"INR","valid_days":30},
  "escalation_contact":{"name":"Ravi Kumar","email":"ravi@example.invalid","phone":"9000000000"},
  "accept_agent_security":true
}
```

Paari automatically binds the parent from the authenticated session and signs delegation with the parent sandbox key. **The agent private key is NEVER sent to Paari.** After registration the client uses existing `/auth/challenge` → `/auth/verify` APIs to obtain the sender-constrained session, and `X-Paari-Proof` to sign each payment request (see `sdk/paari_agent/crypto.py`).

### Provider requirements

Use `payment_rail="razorpay_simulator"` only with a configured loopback stub. Other rails can be registered as institutional applications but cannot execute as there is no compatible integration. Example policy:

```json
{
  "required_context_fields": ["parent_id","agent_id","merchant","purpose"],
  "max_amount_minor_units": 100000, "required_currency": "INR"
}
```

A v3.6 enrolled agent's payment intent without `provider_id`, an active signed mandate, or mandatory context is denied. Changes to provider policy invalidate pending release/consume unless reauthorized against new policy. Existing strict SAFR and three-party federation controls are separate: enable and configure them for their own acceptance tests.
