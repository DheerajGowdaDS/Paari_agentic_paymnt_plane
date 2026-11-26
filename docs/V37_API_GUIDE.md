# Paari v3.7 — Enterprise API quick reference

All routes are under `/v37/enterprise`, require a **manually approved v3.6 parent** (unless noted), and currently operate **only in sandbox**.

| Method | Route | Actor | Purpose |
|---|---|---|---|
| PUT | `/treasury/policy` | Parent Bearer | Set per-parent currency and total daily reserved-exposure ceiling |
| POST | `/treasury/freeze` | Parent Bearer | Immediately stop new intents/consumption and data exports |
| POST | `/admin/treasury/{parent_id}/unfreeze` | Paari admin key | Reactivate after administrator review |
| PUT | `/treasury/agents/{agent_id}/risk` | Parent Bearer | Per-agent daily cap, hourly velocity and suspension |
| GET | `/treasury/exposure` | Parent Bearer | Portfolio overview and reserved exposure |
| GET | `/treasury/signals` | Parent Bearer | Rule-based advisory multi-agent risk observations |
| GET | `/data/datasets` | Parent Bearer | List this parent's dataset metadata only (no plaintext records) |
| POST | `/data/datasets` | Parent Bearer | Register encrypted synthetic dataset (balances / transactions) |
| DELETE | `/data/datasets/{dataset_id}` | Parent Bearer | Revoke grants and remove live ciphertext |
| GET | `/data/grants` | Parent Bearer | List scoped data grants and status |
| POST | `/data/grants` | Parent Bearer | Agent- and field-limited scoped consent for one purpose and destination; optional pinned RSA recipient public key |
| POST | `/data/grants/{grant_id}/revoke` | Parent Bearer | Revoke data permissions |
| GET | `/data/exports` | Parent Bearer | List export digests and audit metadata |
| POST | `/data/export` | Agent session + `X-Paari-Proof` | Retrieve field-minimized, Paari-signed demo data export |
| POST | `/data/portability/export` | Agent session + `X-Paari-Proof` | Return recipient-encrypted, Paari-signed export for the public key pinned at consent time |
| GET | `/rails/capabilities` | Public capabilities | Declare simulation-only rail adapter status |
| POST | `/rails/simulate` | Parent Bearer | Persist non-executing open-banking or stablecoin route preview for an authorized intent |
| GET | `/rails/simulations` | Parent Bearer | List this parent's route previews and non-settlement state |
| POST | `/portability/stage` | Destination parent Bearer | Verify and stage issuer-pinned signed Agent Card export |
| POST | `/portability/{migration_id}/activate` | Destination parent Bearer | Link fresh destination agent identity (no authority transfer) |

### Simple treasury policy example

```json
{
  "currency": "INR",
  "daily_limit_minor_units": 1000000
}
```

This creates an illustrative shared **₹10,000** daily reserved-exposure budget for agents belonging to that parent. All money values are integer minor units.

### Per-agent risk example

```json
{
  "daily_limit_minor_units": 100000,
  "hourly_request_limit": 5,
  "suspended": false
}
```

### Scoped data grant example

```json
{
  "dataset_id": "<dataset-id>",
  "agent_id": "<agent-id>",
  "allowed_fields": ["balance_minor_units", "currency"],
  "purpose": "Daily treasury position reporting",
  "destination": "Treasury-B",
  "valid_hours": 3
}
```

Agent data exports use the **same signed request proof** and bearer session scheme as payment requests, with path `/v37/enterprise/data/export`. The dataset is encrypted in local storage; only the fields authorized in the grant are returned to the agent. The `payload_sha256` digests the content before adding export ID and issuer signature; the issuer signature covers the entire returned envelope (minus the signature field itself). **Do not treat the destination label as verified delivery to that institution.** The additive encrypted portability route can pin an RSA recipient public key when the parent grants consent; it returns an encrypted envelope to the agent and does not itself deliver it to the recipient.

### Agent migration example

`POST /portability/stage` requires a *separately trusted* issuer key (`PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON`) and a signed package from the existing export API. Following successful staging, register a fresh agent under the destination parent through `/v36/agents/register`, then call `/portability/{id}/activate` with `destination_agent_id` and `acknowledge_new_delegation=true`. Reissue all mandates and resource/data grants. A staged link **does not authorize a payment**.

### Environment variables

Keep the existing v3.6 sandbox secrets from `.env.v36.example`. In addition, supply a **different**, random 32+-character `PAARI_V37_DATA_ENCRYPTION_SECRET` for demo datasets. For staged agent migration supply separately pinned `PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON` with the issuer's key ID and PEM public key. Never place private keys or production customer information in committed files.

### Testing

```bash
python -m pytest -q tests/test_v37_enterprise.py tests/test_v36_onboarding.py tests/test_backend_only_api.py tests/test_mandate_hardening.py
```

Full strict PostgreSQL concurrency and live provider verification remain release-blocking follow-ups.


### Encrypted portability envelope

When creating a grant, an optional `destination_public_key_pem` field pins an RSA public key (2048 bits minimum). The agent can then call `/data/portability/export` with the same scoped grant, purpose, destination, signed session and request proof. Paari minimizes fields, encrypts the payload with AES-256-GCM, wraps the one-time key with RSA-OAEP-SHA256 and signs the envelope. The export is logged. The API does not provide external transport or prove that the destination label belongs to the expected organization.

### Open-banking and stablecoin route preview

`POST /rails/simulate` requires an existing ALLOW intent, current unused bounded authorization and `AUTHORIZED` provider transaction. For `open_banking`, use a synthetic `sbx-` consent reference; no bank consent is verified. For `stablecoin`, supply network, chain ID, asset symbol and an EVM-format public wallet address; no wallet screening or broadcast occurs. Both return `external_submission=false`, `authorization_consumed=false` and `settlement_confirmed=false`. These routes are simulation-only and are not live payment adapters.

For the full feature boundary and production release gates, see [V38_AGENTIC_RISK_AND_PORTABILITY.md](V38_AGENTIC_RISK_AND_PORTABILITY.md).
