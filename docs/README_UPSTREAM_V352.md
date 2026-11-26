> **Paari v3.5.2 MVP hardening update:** Read [README_MVP_HARDENING.md](README_MVP_HARDENING.md) and [REGULATOR_DEMO_STATUS_V352.md](docs/REGULATOR_DEMO_STATUS_V352.md). This is an unverified production/non-certified development release; the regulatory gate explicitly returns NO-GO pending mandatory live tests.

# Paari v3.5 — Federated Agentic Payment Control Plane

**Development release (local integration). Not production certified; no real-money assurance.**

Paari is an infrastructure-layer **control plane**, not a bank, custodian, payment network, or settlement ledger. This release builds on the uploaded Paari source and the v3.4 receiver extension. The separate v3.3.1 commit cannot be independently verified as identical to the source used here.

## What works in this codebase

- Existing Paari identity, signed parent delegation, signed Agent Card and staged identity-only portability (destination permissions do NOT transfer).
- Existing user mandates, institutional SAFR envelopes and policy engine, signed sender-constrained request proof, bounded single-use payment authorization, provider execution, non-terminal `CAPTURED`, independently reconciled `PAID`, replay controls and tamper-evident audit chain.
- v3.4 tenant-scoped receiving institution and beneficiary governance, signed receiver acknowledgements, pre-authorize and pre-consume receiver checks.
- **New v3.5:** org-scoped signer enrollment, three separately signed governance agreements (`SENDER_ORG`, `USER`, `RECEIVER`), externally signed consent and institutional acceptance, purpose/beneficiary/currency/amount/expiry/version binding, signer and agreement revocation, active institutional policy digest, strict preauthorization and pre-consume enforcement, independently reverified signed user payment mandate in strict mode.
- **New v3.5:** a Paari-signed, minimal-data Payment Context Envelope for every recorded payment decision (including denied requests). Context digest and ID are linked to the established `intent_decided` hash-chained audit event. Context is **not** an execution authorization or proof of beneficiary credit.
- Tenant-scoped evidence APIs and a refreshed professional local-only web operator console at `/console/`, including separate federation/consent and payment-context inspection.

## Quick start — clean local development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
$env:PAARI_ENV="sandbox"
$env:PAARI_RECEIVER_ENFORCEMENT="1"
$env:PAARI_FEDERATION_ENFORCEMENT="1"
$env:PAARI_BENEFICIARY_HASH_SECRET="USE_A_NEW_RANDOM_48_PLUS_CHARACTER_SECRET_FROM_YOUR_SECRET_STORE"
# Configure PAARI_DATABASE_URL to your dedicated local PostgreSQL database.
# Always back up existing databases before migrations.
python -m alembic upgrade head
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/console/` for the local operator interface. **Do not expose the UI directly on the public Internet.** It uses developer-only org control keys; a production portal needs institutional SSO, authorization scopes, independent signing/reviewer services and a backend-for-frontend.

The v3.5 Alembic head is `f8a9b0c1d2e3`. Before applying it to an existing installation, confirm the Alembic history matches this supplied source. Never run destructive test database reset tools against a real database.

## Federated authorization setup

1. Register a parent, agent and active delegated authority through existing Paari APIs.
2. Register and administratively approve a receiving institution with its public key and create a governed beneficiary (v3.4). Administrative approval **does not** mean external KYB.
3. Create a **cryptographically signed user payment mandate** using the existing user-mandate API. The v3.5 enforcement mode will reject unsigned mandates.
4. Provision organization-scoped control credentials. The platform root is used only to issue those credentials and approve the receiving institution; never send root secrets to browser JavaScript.
5. `GET /control/v1/federation/requirements` to obtain the active institutional `policy_digest` and required signed roles.
6. Register USER and SENDER_ORG public keys through `POST /control/v1/federation/signers`. These are **operator-attested local identity bindings**; independent KYC/identity assurance remains a production dependency. The RECEIVER key is pinned separately by v3.4.
7. Have each of three actors sign a distinct `AgreementClaims` payload with their **own private key outside Paari**. The payload fixes org, agent, beneficiary, purpose, currency, per-payment maximum, policy digest, document digest, issued time, expiry, role and unique agreement ID.
8. Use `python scripts/v35_sign_agreement.py --claims claims.json --private-key /safe/location/actor.pem --out signed.json` in that actor's private environment. Ingest through `POST /control/v1/federation/agreements` under the sending organization key.
9. When the agent submits a new payment, existing mandates and SAFR controls run; additionally, v3.5 checks the **intersection of all three roles** and current policy digest. Missing, changed, expired, revoked or forged agreements deny the intent.
10. Before consuming a bounded authorization, v3.5 repeats signed user mandate, all-active-mandate intersection, three-role agreement and immutable context checks. A failure blocks use **before atomic reservation or provider submission**.
11. The operator can retrieve `GET /control/v1/federation/contexts/{intent_id}`. The response provides context payload, digest and signature validation. Receiving attestations and provider settlement evidence are separate records.

This flow is enforced when `PAARI_FEDERATION_ENFORCEMENT=1`, in live mode, and in production environment modes. Non-federated legacy sandbox behaviour remains available only with enforcement disabled.

## APIs introduced

| Endpoint | Purpose |
|---|---|
| `GET /control/v1/federation/requirements` | Active policy digest and expected signers |
| `POST /control/v1/federation/signers` | Register authorized local signer public key |
| `POST /control/v1/federation/signers/{id}/revoke` | Revoke signer; new policy checks fail |
| `POST /control/v1/federation/agreements` | Verify and store independent signed agreement |
| `GET /control/v1/federation/agreements` | List current tenant agreements |
| `POST /control/v1/federation/agreements/{id}/revoke` | Withdraw signed consent/approval |
| `GET /control/v1/federation/contexts/{intent_id}` | Inspect Paari-signed payment-context evidence |

All registry and context inspection endpoints use existing org-scoped control keys. Agreements require `control:write`; inspection requires `control:read`. A receiver's independent key signs receiver acceptance, although the sending org currently submits the signed message to the registry. Production will need authenticated machine-to-machine receiver transport.

## Tests and status

Run `pytest -q tests/test_v35_federated_governance.py tests/test_audit.py tests/test_v34_receivers.py` on a **disposable test database only**. The project suite reads `.env.test` and may recreate its disposable database; do not run it with production credentials. Use a dedicated PostgreSQL database name ending `_test` for PostgreSQL verification.

The new checks cover missing consent, three independent Ed25519 signatures, forged receiver signatures, policy drift, consent revocation after authorization, signed-context tampering before provider submission, tenant isolation and existing audit chain. See `PAARI_V3_5_RELEASE_NOTES.md` for exact tests run during creation.

## Production blockers / future phases

- Independent identity verification and consent binding for USER and SENDER_ORG signers, true KYB of receiving institutions and beneficiary account ownership, and verifiable legal agreements.
- Separate receiving-organization runtime with its own governance engine, real authenticated sender-to-receiver HTTP preflight and receiving-side decision signing (currently the receiver signs a policy receipt verified by the sender control plane).
- Brokered destination onboarding and active portability/revocation distribution. Existing portability staging does not transfer or automatically activate authority.
- Real independent bank/Open Finance, treasury funding/reservations and stablecoin custody/finality adapters. Receiving attestation is **not** independent beneficiary credit. Provider corroborated `PAID` remains distinct from credited-beneficiary finality.
- Managed KMS/HSM, transport mTLS, externally anchored audit records, SSO/OIDC/FAPI client identity, maker-checker review completion, operational HA/DR, concurrency/race testing, controlled key rotation, PostgreSQL upgrade testing, penetration testing, jurisdictional regulatory mapping and approvals.

This is a **real implementation milestone for v3.5**, but NOT the completed production multi-institution payment infrastructure.
