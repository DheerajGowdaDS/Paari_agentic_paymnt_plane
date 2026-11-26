# Mastercard Open Finance to Setu AA migration report

**Status:** Local sandbox verification complete for Setu token authentication and
account availability. This report is a technical source of truth for the
migration decision; it is not a production-readiness or regulatory assessment.

**Scope:** Paari local sandbox only. No real payment was initiated, no money was
moved, and no production credentials are recorded in this document.

## Executive summary

Paari initially contained a sandbox-only Mastercard Open Finance US adapter for
financial-data retrieval. During local verification, its first provider request
to Mastercard/Finicity was blocked by an Incapsula/Imperva edge response before
a normal provider authentication response was returned. Adding a standard
browser-like `User-Agent` did not change that result. Consequently, the
Mastercard credentials could not be conclusively validated and the adapter could
not create a Test Drive customer from this environment.

The project now includes an independent Setu Account Aggregator (AA) sandbox
adapter, appropriate for consent-based financial-data access in the Indian AA
ecosystem. Setu UAT token generation and an authenticated account-availability
request both succeeded from the same local environment after the correct AA
Product Instance ID was configured.

This is an **addition**, not a destructive removal: the Mastercard adapter
remains in the repository, while Setu AA is a separate integration. Neither
adapter is connected to Paari payment authorization or settlement.

## Decision record

| Item | Mastercard Open Finance adapter | Setu AA adapter |
|---|---|---|
| Intended function | US-oriented financial-data retrieval | Indian consented financial-data retrieval via AA gateway |
| Payment initiation / settlement | Not implemented | Not implemented |
| First live sandbox check | Failed at provider edge | Passed token and account-availability checks |
| Local environment reachability | Provider returned WAF block page | Provider returned JSON success response |
| Credential validation outcome | Inconclusive; API authentication was not reached | Client ID, secret, and AA Product Instance ID validated through successful flow |
| Current project role | Retained but not operationally verified from this environment | Verified local sandbox adapter |

## Mastercard issue: observed facts

### Adapter configuration and initial health

The Mastercard adapter was configured through these local-only variables:

```dotenv
MASTERCARD_ENABLED=true
MASTERCARD_ENV=sandbox
MASTERCARD_API_BASE_URL=https://api.finicity.com
MASTERCARD_PARTNER_ID=...
MASTERCARD_PARTNER_SECRET=...
MASTERCARD_APP_KEY=...
```

The Paari status endpoint confirmed that the integration was enabled and that
all required configuration variables were present. This confirms configuration
presence only; it does not prove that provider credentials are accepted.

### Provider request attempted

Paari attempted the documented Mastercard/Finicity partner authentication
request:

```text
POST https://api.finicity.com/aggregation/v2/partners/authentication
```

with the configured Finicity application key and partner authentication payload.
The provider returned:

```text
HTTP 403 Forbidden
```

The direct response was an HTML Incapsula/Imperva block page, rather than a
normal Mastercard JSON authentication or validation response. The provider page
identified an Incapsula incident ID:

```text
935000440159022492-329431198619601716
```

### Interpretation

The evidence proves that the request reached Mastercard/Finicity's edge
infrastructure and was rejected there. It does **not** prove any one of the
following explanations individually:

- an incorrect Partner ID, Partner Secret, or App Key;
- an IP, geography, reputation, or account-entitlement restriction;
- a provider WAF/bot-protection rule; or
- an endpoint/project mismatch.

Because the edge response was not a normal API authentication response, the
credentials were not conclusively accepted or rejected by the intended
application-level authentication endpoint.

### User-Agent diagnostic change

A standard browser-like `User-Agent` was added to the Mastercard client’s token
and subsequent requests. A focused regression test confirmed the header is
sent. Retesting still resulted in HTTP 403 from the same provider
authentication URL. Therefore, changing the HTTP `User-Agent` alone did not
resolve the provider-edge block.

The project does not route provider traffic through arbitrary VPNs, residential
proxies, or other mechanisms intended to evade provider access controls. Any
future Mastercard re-test should use an egress network explicitly permitted by
Mastercard/Finicity and, if required, formally allowlisted by that provider.

## Reason for adopting Setu AA

Setu AA is a better-aligned local sandbox integration for the present Indian
use case because it exposes consent-driven financial-information workflows on
the Account Aggregator rail. Its documented model requires a Financial
Information User (FIU) product configuration, user consent, and a Product
Instance ID.

The migration decision is based on these verified engineering considerations:

1. **Reachability:** Setu UAT token and AA requests succeeded from the existing
   local environment.
2. **Consent model:** Setu requires an end-user consent flow before financial
   data sessions are created or retrieved.
3. **Explicit product binding:** Each AA request carries an
   `x-product-instance-id`, binding it to the configured Setu Bridge AA product.
4. **Separation of concerns:** Setu AA provides financial-data access only. The
   Paari adapter deliberately does not turn balances, account availability, or
   received FI data into payment authority.
5. **No disruption to payment controls:** Paari’s existing agent identity,
   mandate, SAFR, bounded-authorization, provider settlement, reconciliation,
   and audit paths were not modified.

This is not a claim that Setu AA makes Paari production-ready or regulator
approved. Production use requires Setu FIU onboarding, privacy/legal review,
verified notification handling, consent lifecycle controls, tenant ownership
controls, managed secrets, and independent security review.

## Setu AA implementation

### Environment contract

The Setu adapter requires all three values issued for the Setu Bridge AA
product:

```dotenv
SETU_AA_ENABLED=true
SETU_AA_ENV=sandbox
SETU_AA_AUTH_BASE_URL=https://uat.setu.co/api/v2
SETU_AA_BASE_URL=https://fiu-sandbox.setu.co/v2
SETU_AA_CLIENT_ID=...
SETU_AA_CLIENT_SECRET=...
SETU_AA_PRODUCT_INSTANCE_ID=...
```

`SETU_AA_PRODUCT_INSTANCE_ID` must be the Product Instance ID for the Setu
**Account Aggregator** sandbox product associated with the configured client
credentials. A value from another Setu product or environment will not work.

### Adapter behaviour

`app/integrations/setu/client.py` implements:

1. Token generation through `POST /auth/token` using `clientID` and `secret`.
2. In-memory OAuth token caching with an expiry safety margin.
3. `Authorization: Bearer <token>` and `x-product-instance-id` headers on AA
   requests.
4. Account availability: `POST /account-availability`.
5. Consent creation, retrieval, and revocation.
6. Data-session creation and retrieval after customer consent.
7. Sanitized upstream failure handling: the public Paari route returns HTTP 502
   without returning credentials or access tokens.

`app/integrations/setu/router.py` exposes local admin-gated routes:

```text
GET  /integrations/setu-aa/status
POST /integrations/setu-aa/account-availability
POST /integrations/setu-aa/consents
GET  /integrations/setu-aa/consents/{consent_id}
POST /integrations/setu-aa/consents/{consent_id}/revoke
POST /integrations/setu-aa/sessions
GET  /integrations/setu-aa/sessions/{session_id}
```

All data and consent operations require `X-Paari-Admin-Key` equal to the
local `PAARI_ADMIN_API_KEY`. The status route reveals only enabled/configured
booleans and mode; it never returns credentials.

The adapter is mounted in `app/main.py` and its environment variables are
passed through the app service in `docker-compose.yml`.

### Deliberate limits

The Setu adapter does not:

- initiate payments, send money, settle transactions, or create provider orders;
- approve Paari payment intents from account balances or availability;
- persist decrypted financial information;
- implement or trust Setu callbacks/webhooks; or
- claim that a sandbox account-availability result proves a customer's identity,
  account ownership, available funds, or payment settlement.

Setu consent/data-session notifications must be configured on Setu Bridge. A
production notification endpoint requires a documented authentication and
verification design before any received event is used for business decisions.

## Verification record

### Automated validation

The following local validation command completed successfully after the Setu
changes:

```text
python -m compileall -q app tests
python -m pytest -q tests/setu tests/mastercard/test_client.py tests/mastercard/test_normalizer.py
docker compose config -q
```

Result:

```text
8 passed
```

The focused Setu tests cover:

- token request and cached-token/header behaviour;
- Setu AA sandbox account-availability request path;
- consent creation request path;
- integration status output without secret disclosure;
- admin-key enforcement; and
- application router registration.

### Live local sandbox verification

The local Docker application was rebuilt and started with the Setu configuration.

1. `GET /integrations/setu-aa/status` returned:

```json
{"enabled":true,"credentials_configured":true,"mode":"sandbox"}
```

2. The first authenticated account-availability attempt returned a Setu JSON
   `NotFound` error stating that no configuration existed for the supplied
   Product Instance ID. This established that the token exchange succeeded but
   that the originally configured Product Instance ID was incorrect or from a
   different product/environment.

3. After the Setu AA Product Instance ID was corrected locally, Paari sent:

```text
POST /integrations/setu-aa/account-availability
```

with the Paari admin key and a Setu sandbox test mobile number. The request
returned HTTP 200 with available AA/VUA entries and a Setu trace ID. This is
positive evidence that:

- Setu UAT token acquisition works;
- the Client ID and Client Secret work;
- the AA Product Instance ID is valid for the configured sandbox product;
- Paari forwards authorization and product-instance headers correctly; and
- the local Setu AA account-availability endpoint works end-to-end.

No credentials, OAuth access tokens, or full provider payloads are recorded in
this report.

## Not yet verified

The following are not claimed as completed:

- end-user consent creation and approval in Setu’s consent webview;
- Setu notification/callback delivery and verification;
- data-session completion and retrieval of financial information;
- any use of real customer data;
- tenant-scoped consent persistence and audit lifecycle;
- production Setu FIU onboarding and production endpoints;
- production payment initiation, payment settlement, or banking certification;
- full Paari test-suite completion, PostgreSQL concurrency/failover validation,
  or independent penetration/security assessment.

## References

- Setu AA quickstart: <https://docs.setu.co/data/account-aggregator/quickstart>
- Setu consent flow: <https://docs.setu.co/data/account-aggregator/api-integration/consent-flow>
- Setu data flow: <https://docs.setu.co/data/account-aggregator/api-integration/data-apis>
- Setu account availability: <https://docs.setu.co/data/account-aggregator/api-integration/account-availability-apis>
- Setu OAuth token generation: <https://docs.setu.co/dev-tools/bridge/v1/generate-token>
- Setu notification guidance: <https://docs.setu.co/data/account-aggregator/api-integration/notifications>
- Local Setu integration guide: `docs/integrations/SETU_AA_SANDBOX.md`
