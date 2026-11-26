# Paari v2.5 — Managed Signing Interface and Key-Lifecycle Contract

**Status:** interface and contract tests implemented; provider-specific KMS/HSM adapter NOT included.

## Security objective

Move Paari-issued credentials, sessions, bounded authorizations and agent-card signatures behind a provider-neutral Ed25519 signing boundary. Protocol code must never need access to production private-key bytes. A production key is selected by an opaque key identifier (`kid`) and signatures are validated against the public key bound to that identifier.

## Implemented in this release

- `app/signing_backends.py` defines a `SigningBackend` protocol and `KmsHsmClient` protocol.
- `LocalPemSigningBackend` retains a development-only sandbox/test implementation.
- `KmsHsmSigningBackend` wraps an injected provider client, checks that the public key is Ed25519, requires raw 64-byte Ed25519 signatures, and verifies every returned signature before it is emitted.
- Paari credential, session, and bounded-authorization JWT issuance now uses the interface to construct compact EdDSA JWS tokens. The protected header carries the signer's active `kid`.
- JWT validation resolves the key by the token's `kid`, then lets PyJWT verify signature, issuer, audience, expiry and required claims.
- Managed adapters must resolve previous public keys by old `kid` for at least the lifetime of artifacts signed under those keys. The tests exercise v1/v2 key overlap using a fake client.
- Health/readiness exposes only backend kind, key id and health status; never private-key data, access tokens, or credentials.
- Production guards inspect the active signer's `managed` and `healthcheck()` results. Setting an environment variable alone does not turn a local signer into a managed signer.

## Sandbox configuration

```dotenv
PAARI_SIGNING_BACKEND=local_pem
PAARI_SIGNING_KEY_ID=paari-1
PAARI_SIGNING_KEY_PATH=./paari_signing_key.pem
```

Local PEM keys are for development/test use only. Never commit PEMs or sync them through shared folders. The application should be stopped and the local key regenerated when test key exposure is suspected.

## Managed adapter contract

Configure a provider-specific Python module only after it has been implemented and reviewed:

```dotenv
PAARI_SIGNING_BACKEND=kms_hsm
PAARI_SIGNING_ADAPTER=your_package.paari_kms:create_signing_backend
PAARI_SIGNING_KEY_ID=<provider-key-version-id>
```

`create_signing_backend()` must return `KmsHsmSigningBackend(client, active_key_id)`. The provider-specific client must implement:

- `sign_ed25519(key_id: str, message: bytes) -> bytes`: call the managed key and return the raw 64-byte Ed25519 signature for the exact bytes supplied.
- `get_public_key_pem(key_id: str) -> str`: resolve the active key and historical verification keys by key id, without returning any private material.
- `healthcheck() -> bool`: verify the signing service and key configuration are available; it must fail on permission/configuration errors.

The wrapper cryptographically verifies the result of every sign operation against the public key for the active key id. A malformed signature, key mismatch, unknown old key, or unhealthy provider fails closed.

**Important:** this release contains the generic interface and fake-client tests, not an AWS KMS, Google Cloud KMS, Azure Key Vault, PKCS#11 or bank-HSM implementation. Production remains blocked by the missing trusted identity integration and other launch gates. Do not configure a made-up module path to bypass that block.

## Key lifecycle requirements before production

1. **Provisioning:** create the Ed25519 key in an approved managed HSM/KMS; private-key export must be disabled where supported; restrict key use to the Paari service identity.
2. **Key identity:** every credential/JWT must carry a stable key id; publish the corresponding public key and algorithm metadata through a trusted discovery/JWKS mechanism.
3. **Rotation:** activate a new key id for signing while retaining old public keys for verification through the maximum token TTL plus clock-skew and revocation propagation windows. Test tokens signed before rotation and after rotation.
4. **Revocation:** disable compromised key versions; define which credentials are invalidated immediately and which use independent revocation lists. Do not treat mere signature validity as proof of mandate/credential liveness.
5. **Auditing:** record key-id, operation, caller identity, purpose and timestamp without logging payload secrets or signature-service credentials.
6. **Recovery:** document dual-control approval, backup/restore constraints, emergency rotation, key compromise handling, outage behavior and rollback. Signing service outage must stop new token issuance; it must not silently fall back to local PEM.
7. **Validation:** run concurrency, throughput, latency, outage, wrong-key, malformed-signature and rotation-overlap tests against the real adapter in a dedicated environment.

## Launch rule

`PAARI_ENV=prod` and `prod-live` must remain blocked until the actual managed adapter is installed and healthy, trusted KYC/KYB assurance is verified in the payment decision, PostgreSQL concurrency/soak tests pass, and the independent security-review launch gate is signed off.
