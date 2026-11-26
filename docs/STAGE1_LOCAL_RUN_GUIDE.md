# Paari Stage 1 local run guide (Windows PowerShell / Docker Desktop)

This guide runs the sandbox demonstration only. It does not connect to a live KYB provider or move real money.

## 1. Prepare an isolated sandbox

Use a fresh working copy of this archive. Install Python 3.11 (recommended by the project) and Docker Desktop with Compose support. Create the local environment file:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and replace every `replace-with-...` value with a different, randomly generated sandbox secret. Keep `PAARI_ENV=sandbox`. For the onboarding walkthrough only, set:

```dotenv
PAARI_KYB_SIMULATION=1
```

Do not set `PAARI_KYB_SIMULATION=1` in production. These simulated outcomes are not legal identity verification. Keep `PAARI_REQUIRE_MTLS_INGRESS=0` in `.env`; the optional mTLS Compose overlay enables the gateway-specific setting for the app service.

## 2. Generate local mTLS certificates

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python scripts/mtls_pki.py init --out .\local_pki
```

The command creates a sandbox CA, gateway server certificate/key and certificate-authority file. Treat `local_pki\ca.key`, `local_pki\server.key` and every `clients\*.key` as private secrets. Do not upload or distribute them.

## 3. Start the local stack with the mTLS ingress profile

```powershell
docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d --build
```

The local endpoints are:

- Organization Portal: `http://127.0.0.1:8000/organization`
- Paari Console: `http://127.0.0.1:8000/console`
- API health: `http://127.0.0.1:8000/health`
- mTLS agent ingress: `https://agent-gateway.local:8443`

The mTLS overlay keeps Uvicorn's proxy-header rewriting disabled so the API validates the actual gateway TCP peer, not a forwarded client address. The application port is loopback-bound on the host; the application must not be exposed publicly or reachable through another untrusted ingress path. For repeatable environment checks and compose control, use `python scripts/paari_sandbox.py preflight --mtls`, `python scripts/paari_sandbox.py up --mtls`, `python scripts/paari_sandbox.py status --mtls` and `python scripts/paari_sandbox.py down --mtls`.

## 4. Register a certificate against an approved Agent Card

First create/approve a sandbox parent and register an Agent Card through the Organization Portal. The agent operator must retain its Agent Card signing private key and provide its matching public key (and organization ID) for the binding workflow. Copy the exact agent ID and organization ID, then issue the matching transport certificate. The private signing key is read locally only to create the proof-of-possession signature; it is never included in the payload sent to Paari:

```powershell
$AgentId = "<AGENT_ID>"
$OrgId = "<ORG_ID_FROM_AGENT_CARD>"
python scripts/mtls_pki.py issue-client --out .\local_pki --agent-id $AgentId --org-id $OrgId `
  --agent-card-private-key ".\agent_keys\$AgentId.private.pem" `
  --agent-card-public-key ".\agent_keys\$AgentId.public.pem" --agent-card-algorithm ed25519
$Registration = Get-Content ".\local_pki\clients\$AgentId.register.json" -Raw | ConvertFrom-Json
$Body = @{ certificate_pem = $Registration.certificate_pem; agent_card_signature_b64 = $Registration.agent_card_signature_b64 } | ConvertTo-Json -Compress
$AdminKeyLine = Get-Content .env | Where-Object { $_ -match '^PAARI_ADMIN_API_KEY=' } | Select-Object -First 1
$AdminKey = $AdminKeyLine.Substring('PAARI_ADMIN_API_KEY='.Length)
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/control/v1/agents/$AgentId/mtls-certificates" `
  -Headers @{ "X-Admin-Api-Key" = $AdminKey } `
  -ContentType "application/json" -Body $Body
```

The client certificate is now bound in two ways: (1) strict certificate subject/SAN/EKU/BasicConstraints/KeyUsage and configured-CA signature checks, and (2) a proof-of-possession signature made by the Agent Card's own signing key over this exact certificate fingerprint, serial, validity, agent ID, organization ID and Agent Card key fingerprint. The database pins the certificate to that Agent Card signing-key version. If the Agent Card key rotates, the certificate is accepted only while the configured old-key grace period remains open; after that it must be rebound. The Agent Card private key is read locally to make the proof and must never be sent to Paari.

**Migration note:** existing Stage 1 certificate rows are not silently upgraded to strong binding. They receive an empty key-fingerprint sentinel and fail closed until re-registered using a new proof-of-possession payload.

## 5. Exercise the gateway and revocation path

Use the generated client certificate/key when calling the dedicated listener. For example, this request deliberately uses an empty JSON object so it can demonstrate that TLS and gateway authentication succeeded before the downstream payment API rejects the invalid payment body:

```powershell
curl.exe --resolve "agent-gateway.local:8443:127.0.0.1" `
  --cacert .\local_pki\ca.crt `
  --cert ".\local_pki\clients\$AgentId.crt" `
  --key ".\local_pki\clients\$AgentId.key" `
  -H "Content-Type: application/json" -d "{}" `
  https://agent-gateway.local:8443/v1/payments/intent
```

Then revoke that certificate using the fingerprint returned at registration:

```powershell
$Fingerprint = "<SHA256_FINGERPRINT_FROM_REGISTRATION>"
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/control/v1/agents/$AgentId/mtls-certificates/$Fingerprint/revoke" `
  -Headers @{ "X-Admin-Api-Key" = $AdminKey } `
  -ContentType "application/json" -Body '{"reason":"Stage 1 revocation acceptance test"}'
```

Repeat the same `curl.exe` request. Gateway authentication should now return HTTP 403, and a separate `gateway_ingress_denied` audit event should exist. It must not create a payment intent or authorization.

## 6. Run the targeted Stage 1 tests

```powershell
python scripts/run_stage1_sandbox_checks.py
# Longer provider-stub HTTP E2Es:
python scripts/run_stage1_sandbox_checks.py --full
```

See `STAGE1_VALIDATION_REPORT.md` for the verified test scope and limitations. Docker Compose/Nginx must be validated in your own Docker environment before treating this optional ingress deployment as operational.
