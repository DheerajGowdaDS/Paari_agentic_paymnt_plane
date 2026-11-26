# Paari v2.7 — UAE-first SAFR Control Plane and Portability

## Product direction

v2.7 frames Paari as an agent management and runtime risk control plane for enterprise financial actions. UAE (`AE`) is the default home-jurisdiction metadata; this is product/deployment metadata only and does not imply UAE regulatory authorization or payment-rail availability.

## Delivered

- Added a versioned Pydantic Governance Envelope contract with schema `paari.safr.governance-envelope` v1.0, canonical action digest, Ed25519 signature verification, expiry and maximum 300-second lifetime, action-context binding and strict payment-field validation.
- Added `POST /control/v1/governance/envelopes/validate`, which checks authenticated tenant binding, active registered agent and parent, persisted parent-signed delegation, key binding/signature, active principal and resource, relevant access grants, and for payment actions the mandate signature, amount/currency/merchant bounds and payment-instrument binding.
- The envelope route stores an anti-replay receipt and audit record. It returns `VALIDATED_ONLY`, `policy_evaluated=false`, `authorization_issued=false` and `execution_permitted=false`. It is not an authorization API; execution must still use the existing runtime policy and bounded-authorization path.
- Added signed, least-privilege Agent Card/delegation portability export and an import-side validator that requires a Paari issuer key from an out-of-band trusted key map. It never transfers spending authority or exports private keys, session tokens, mandates, grants, payment-provider credentials or bounded authorizations.
- Preserved the original parent delegation signature on new registration/key-rotation records. Older records without a persisted signature cannot be exported; reissue/re-register a signed delegation rather than fabricate it.
- Added provider-neutral KYC/KYB identity-provider contracts. The included sandbox provider can never return VERIFIED and is not a substitute for an actual provider.
- Added `PAARI_HOME_JURISDICTION=AE` metadata and a health response flag `jurisdiction_metadata_only=true`.
- Added JSON Schema for the Governance Envelope and specific tests for signature/context tampering, expiry/TTL, replay, portability signatures, authority non-transfer and endpoint behavior.
- Added UAE identity/KYB/KMS/Open Finance evaluation notes and explicit SAFR conformance matrix.

## Important limits

- Not full SAFR conformance: the new envelope route validates records but does not itself run the complete versioned policy engine, emit a disposition or mint authorization. The existing payment path remains authoritative for payment decisions/execution.
- `data.read`, `data.write` and `api.invoke` can be represented and validated as envelopes; actual interception/execution of arbitrary data/API operations is not yet implemented.
- No actual UAE PASS/Sumsub or other identity-provider client is included.
- No concrete AWS KMS/HSM adapter is included.
- No new live Kilo/Razorpay transaction was run for this release.
- No claim of CBUAE approval, license, SAFR certification or production readiness is made.

## Migration

Alembic revision: `c4d5e6f7a8b9` (delegation signature persistence and envelope receipts). Nullable delegation signature preserves old database rows; use signed re-registration before portability export.
