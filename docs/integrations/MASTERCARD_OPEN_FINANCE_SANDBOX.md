# Paari Mastercard Open Finance US Sandbox

This connector is a **financial-data adapter**, not a payment-initiation or funds-movement integration. Mastercard credentials stay server-side. Payment execution remains a separate provider integration.

## Configure
Set the following in `.env` (never commit this file):

```dotenv
MASTERCARD_ENABLED=true
MASTERCARD_ENV=sandbox
MASTERCARD_API_BASE_URL=https://api.finicity.com
MASTERCARD_PARTNER_ID=your_partner_id
MASTERCARD_PARTNER_SECRET=your_partner_secret
MASTERCARD_APP_KEY=your_app_key
PAARI_ADMIN_API_KEY=your_paari_admin_key
```

## Sandbox workflow
1. `GET /integrations/mastercard/status` checks enabled/credential presence (never returns secrets).
2. `POST /integrations/mastercard/customers/testing` creates a Test Drive customer.
3. `POST /integrations/mastercard/connect-url` returns the Connect URL; complete the customer institution/account flow in Connect.
4. `POST /integrations/mastercard/customers/{customer_id}/refresh` requests account refresh; respect provider policies and avoid repeated automated refreshes.
5. `GET /integrations/mastercard/customers/{customer_id}/accounts` returns a normalized account summary.
6. `POST /integrations/mastercard/transactions` retrieves transaction history for the specified date range.

All mutation/data endpoints require `X-Paari-Admin-Key` equal to `PAARI_ADMIN_API_KEY`. This is an initial local-admin gate; before production, replace with the Paari's established administrator authorization, strict tenant ownership, audited consent lifecycle, provider request schemas/version validation, and secrets management. Do not expose these endpoints publicly.

## Endpoint payloads
Customer: `{"username":"abc_test","first_name":"Alex","last_name":"Example"}`
Connect: `{"customer_id":"...","redirect_uri":"https://your-local-return.example"}`
Transactions: `{"customer_id":"...","account_id":"...","from_date":1700000000,"to_date":1700086400}`

Mastercard API shapes and versions vary by partner/project. Validate request/response fields and endpoints against the API specification enabled for your project. This implementation is sandbox-oriented and is not production certified. Data retrieval is not customer consent by itself; connect/consent status, scope, freshness, and revocation must be enforced in a deployment before decisions use the data.

## Agentic payment demo (simulated money movement)
Agent proposes an intent -> Paari identity/delegation/mandate checks -> fetch customer-permitted financial context -> evaluate liquidity policy (e.g. post-payment balance must remain above a reserve) -> SAFR disposition -> bounded authorization -> existing simulated provider -> reconciliation/audit. Mastercard data alone never authorizes or executes a payment. Do not infer guaranteed available funds or settlement from account balances.
