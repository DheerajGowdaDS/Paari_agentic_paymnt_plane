# Setu Account Aggregator sandbox adapter

This adapter provides consent-based financial-data access through Setu AA. It is
not a payment-initiation, settlement, KYC, or payment-authority integration.
Paari does not use Setu account data to approve payment intents.

## Configure

Setu AA requires all three values from the Setu Bridge Account Aggregator
product. Do not put them in source code or share them in chat.

```dotenv
SETU_AA_ENABLED=true
SETU_AA_ENV=sandbox
SETU_AA_AUTH_BASE_URL=https://uat.setu.co/api/v2
SETU_AA_BASE_URL=https://fiu-sandbox.setu.co/v2
SETU_AA_CLIENT_ID=your_bridge_client_id
SETU_AA_CLIENT_SECRET=your_bridge_client_secret
SETU_AA_PRODUCT_INSTANCE_ID=your_bridge_product_instance_id
```

The adapter obtains and caches the OAuth access token from
`POST /auth/token`, then sends `Authorization: Bearer <token>` and
`x-product-instance-id` to the AA API.

## Local admin API

All data and consent routes require `X-Paari-Admin-Key` matching the local
`PAARI_ADMIN_API_KEY`.

- `GET /integrations/setu-aa/status`
- `POST /integrations/setu-aa/account-availability`
- `POST /integrations/setu-aa/consents`
- `GET /integrations/setu-aa/consents/{consent_id}`
- `POST /integrations/setu-aa/consents/{consent_id}/revoke`
- `POST /integrations/setu-aa/sessions`
- `GET /integrations/setu-aa/sessions/{session_id}`

Example account-availability request:

```json
{"mobile_number":"9999999999"}
```

Example data-session request:

```json
{
  "consent_id":"<approved-consent-id>",
  "data_range":{"from":"2024-01-01T00:00:00Z","to":"2024-12-31T23:59:59Z"},
  "data_format":"json"
}
```

## Consent and notification boundary

The customer must approve the consent on Setu's consent URL before a data
session can be created. Configure Setu Bridge notifications according to
Setu's documentation, but do not treat an unverified notification as payment
or identity authority. This initial adapter intentionally does not persist
financial data, process webhooks, or make payment decisions from AA data.

## Sandbox only

Use Setu sandbox URLs and synthetic test data only. Production requires Setu
FIU onboarding, a verified notification-authentication design, consent
lifecycle/audit retention, tenant ownership enforcement, secret management,
and a privacy/legal review.
