# Paari Stage 1 — Strong Agent Card Binding and Local Sandboxes

## What the stronger binding proves

A client certificate is no longer registered based only on its subject name, certificate fingerprint and administrator API call. Registration requires a detached proof-of-possession signature from the signing private key corresponding to the public key registered in the Agent Card. The signed canonical payload is domain-separated (`PAARI_AGENT_MTLS_CERTIFICATE_BINDING`) and binds the proof to:

- Agent ID and organization ID
- Client certificate SHA-256 fingerprint and serial number
- Certificate validity interval
- Agent Card signing-key fingerprint

The server checks the proof against the current Agent Card key, then stores the Agent Card key fingerprint alongside the transport certificate record. At each protected payment-intent ingress it rechecks that fingerprint. A signing-key rotation therefore invalidates the mTLS binding unless the certificate is still associated with the old key during the explicit key-sunset grace interval. Old Stage 1 certificate records are migrated with an empty fingerprint and rejected until they are re-registered.

The certificate profile is strict: exact Agent Card CN, exactly one matching Agent Card URI SAN, sole `clientAuth` EKU, `CA=false`, digital-signature KeyUsage, current validity, supported key strength and signature by the configured valid CA.

## Local sandbox profiles

1. **API + KYB sandbox:** PostgreSQL, FastAPI, portal workspaces and opt-in synthetic KYB outcomes.
2. **mTLS ingress sandbox:** API + PostgreSQL + Nginx reference ingress + locally generated CA/server/client certificates. Only the protected payment-intent POST paths are covered by the mTLS middleware in this stage.
3. **Stage 1 verification sandbox:** focused certificate/KYB/reason-evidence tests plus the offline SAFR local demo. `--full` adds the longer simulated-provider HTTP E2Es.

## Quick start

```powershell
Copy-Item .env.example .env
# Edit .env: PAARI_ENV=sandbox; PAARI_KYB_SIMULATION=1; set independent random secrets
python scripts/paari_sandbox.py preflight
python scripts/paari_sandbox.py up
python scripts/run_stage1_sandbox_checks.py
```

For the mTLS profile:

```powershell
python scripts/mtls_pki.py init --out .\local_pki
python scripts/paari_sandbox.py preflight --mtls
python scripts/paari_sandbox.py up --mtls
```

Register an agent certificate using the Agent Card proof:

```powershell
python scripts/mtls_pki.py issue-client --out .\local_pki --agent-id <AGENT_ID> --org-id <ORG_ID> `
  --agent-card-private-key .\agent_keys\<AGENT_ID>.private.pem `
  --agent-card-public-key .\agent_keys\<AGENT_ID>.public.pem --agent-card-algorithm ed25519
```

The generated `*.register.json` contains only the certificate PEM and Agent Card signature. Its transport private key and the Agent Card private key remain local. Submit the JSON to `POST /control/v1/agents/<AGENT_ID>/mtls-certificates` with the organization-scoped admin API key.

## Sandbox boundary

- Synthetic KYB scenarios are not legal KYC/KYB verification.
- Local CA/private keys are development-only.
- The simulated provider does not move real money.
- A receiver `ACCEPTED` acknowledgement is not proof of beneficiary credit.
- Do not expose the app port or mTLS sandbox publicly.
- Do not enable simulation flags in production.
- The Docker/Nginx profile still needs execution in a Docker-enabled environment and independent deployment review.
