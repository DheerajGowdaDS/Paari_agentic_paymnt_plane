# Stage 1 zero-trust agent ingress (local sandbox)

## Security boundary

The dedicated Nginx listener on port `8443` performs mutual TLS client
certificate validation. The FastAPI middleware then requires the request to
arrive from an explicitly trusted proxy CIDR, checks the proxy's TLS-success
signal, resolves the SHA-256 fingerprint against Paari's certificate registry,
and verifies that the certificate, Agent Card and parent organization are
currently active. The certificate must have exactly one subject CN matching the Agent Card ID, exactly one SAN containing `urn:paari:agent:<agent_id>`, sole `clientAuth` EKU, `CA=false`, digital-signature KeyUsage and a supported client public-key size. The configured issuing CA must be currently valid, self-signed, marked as a CA and permitted to sign certificates.

Registration additionally requires a proof-of-possession signature from the Agent Card's own private signing key. That canonical signature binds the Agent ID, organization ID, certificate fingerprint, serial, validity and Agent Card key fingerprint. The database pins the transport certificate to the key version that signed it. A key rotation is accepted only during the explicit old-key grace period; afterwards, a new certificate binding signed by the new Agent Card key is required.

The gateway's 403 response is issued before the payment-intent endpoint is
called. A failed ingress attempt is recorded as a separate append-only
`gateway_ingress_denied` audit event with `payment_intent_created=false` and
`authorization_issued=false`; it is not placed in the payment ledger/history.

## Create local certificates

```bash
python scripts/mtls_pki.py init --out ./local_pki
python scripts/mtls_pki.py issue-client --out ./local_pki --agent-id <AGENT_ID> --org-id <ORG_ID> \
  --agent-card-private-key ./agent-private.pem --agent-card-public-key ./agent-public.pem
```

Configure the API process:

```dotenv
PAARI_REQUIRE_MTLS_INGRESS=1
PAARI_MTLS_CA_CERT=./local_pki/ca.crt
PAARI_MTLS_TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

For Docker, replace the proxy CIDR with the exact dedicated proxy container IP
or subnet. Do not use a broad private range in a shared or production network.
The app port must be private; firewall or container-network policy must prevent
untrusted clients from reaching it directly.

Register the issued certificate PEM:

```http
POST /control/v1/agents/{agent_id}/mtls-certificates
X-Admin-Api-Key: <PAARI_ADMIN_API_KEY>
Content-Type: application/json

{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
  "agent_card_signature_b64": "<base64 Agent Card proof-of-possession signature>"
}
```

The admin API verifies the CA signature, strict certificate profile and Agent Card proof-of-possession before persisting the fingerprint and Agent Card key fingerprint. The request JSON must contain both `certificate_pem` and `agent_card_signature_b64`. The generated registration payload does not contain either private key. Revoke using
`POST /control/v1/agents/{agent_id}/mtls-certificates/{fingerprint}/revoke`.
The application checks revocation on every protected payment-intent ingress;
revocation is therefore not dependent on a CRL refresh interval.

## Limits

This is a locally testable reference ingress integration, not a production PKI
service. Production requires a managed CA/HSM or enterprise certificate
authority, secure key distribution, high-availability revocation state,
Nginx hardening, exact trusted-proxy network isolation, TLS penetration testing,
certificate lifecycle automation, and independent verification that all public
paths to the application bypass neither Nginx nor the middleware.

## Strict local sandbox helper

Use `python scripts/paari_sandbox.py preflight --mtls` to validate `.env`, distinct sandbox secrets, Docker Compose and local PKI files without printing secret values. Use `python scripts/paari_sandbox.py up --mtls` to start the Compose profile. Run `python scripts/run_stage1_sandbox_checks.py` for the Stage 1 certificate/KYB/evidence tests and local SAFR verifier.

This remains a local sandbox. The Compose/Nginx ingress path must be started and validated in a Docker-enabled environment; a passing in-process middleware test does not prove the container deployment is running.
