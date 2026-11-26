# Agent Card and Delegation Portability — v2.7

## Purpose

Paari portability allows an enterprise to export verified agent identity metadata and a parent-signed delegation artifact, so another trusted control plane can inspect the provenance instead of requiring the exporting platform to be blindly trusted. Portability is not delegation of payment authority across tenants.

## Endpoints and tooling

- Export: `GET /control/v1/organizations/{org_id}/agents/{agent_id}/portability-export`
- Required headers: `X-Paari-Org` and a valid organization control key with `control:read` scope.
- Local package validator: `python scripts/validate_agent_portability.py --help`
- Package schema/implementation: `app/portability.py`; API: `app/control_plane/router.py`.

The consumer must receive the Paari issuer public key through a separate trusted channel and pass it as the validator trust anchor. The `public_key_pem` embedded in the package is useful for inspection, but does not establish trust on its own.

## Package contents

- Paari package type/version and issuer key ID/algorithm/fingerprint.
- Signed Agent Card and public-key binding.
- Parent identity metadata, parent public key and original parent-signed delegation claims/signature.
- Export policy documenting which fields are portable and what must never be exported.

## Excluded by design

Private keys, session tokens/JWTs, user mandates, destination resource grants, provider credentials and tokens, bounded authorizations and tenant-private data are never exported.

## Import requirements

1. Trust the Paari issuer key from an out-of-band allow-listed trust store.
2. Verify the outer package, Agent Card and parent delegation signatures.
3. Check agent/parent/key/delegation expiry, status and revocation with authoritative registries. A portable artifact is not by itself a current status query.
4. Bind the imported identity to the destination tenant's organization and local governance policy.
5. Require destination-side principal consent, new resource grants and new transaction-specific authorization. Never reuse the source tenant's mandate or authority.

## Legacy records

Delegation signatures are nullable for backward compatibility with earlier database rows. If the original parent signature was not persisted, the export endpoint refuses export with a conflict and tells the operator to reissue/re-register a signed delegation. Paari must not reconstruct or fabricate a parent signature.

## Security boundaries

- Portability exports identity and provenance, not current execution permission.
- A suspended/revoked identity should not be reactivated merely by importing an older signed package. The importer must check authoritative current status and apply its own acceptance policy.
- Signature validity is not KYC/KYB. Parent public-key possession is not proof the parent is legally constituted.
- Treat packages as sensitive identity metadata; apply data minimization, access control, retention and audit.
