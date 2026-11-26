# Paari v4.0.0 — Federated Agentic Financial Control Plane

Paari v4.0 consolidates the v3.9 Open Finance governance work with atomic tenant/currency/period treasury reservations, signed receiver pre-execution acknowledgements, durable provider-reconciliation scheduling, idempotent provider recovery and a production-oriented multi-tenant deployment reference. It is designed as a **SaaS control plane with a PaaS developer/API layer**: organizations operate agents and policies through the Organization Portal, while agent platforms integrate through authenticated APIs and SDKs.

**Start here for v4.0:** [System architecture and SaaS/PaaS model](docs/V40_ARCHITECTURE.md), [v4.0 release notes and validation](docs/V40_RELEASE_NOTES.md), [production deployment guide](deploy/production/ENVIRONMENT.md), [security packaging notice](docs/SECURITY_PACKAGING_NOTICE.md).

**Readiness boundary:** this repository is a locally runnable development/sandbox release with production-oriented deployment templates. It is not a hosted production service, independent security certification, financial licence or proof of real-money autonomous settlement. PostgreSQL concurrency, provider-specific production behavior, managed KMS/HSM and trusted identity-provider integrations must be completed and independently verified before live use.

Stage 1 builds on the v3.7.1 baseline with sandbox mTLS agent ingress, proof-of-possession certificate-to-Agent-Card binding (including key-version pinning and revocation), synthetic KYB exception simulation, and structured SAFR decision evidence. It is a locally demonstrable engineering increment, not a production certification.

**Built from Paari v3.6.** Includes the two-workspace product portal and preserves all v3.5/v3.6 backend components and adds enterprise agent-fleet risk controls, signed identity-migration workflow, consent-scoped demo data portability, parent login lockout and a 100-agent onboarding demonstration.

**Start here:** [Portal refinement summary](docs/PORTAL_REFINEMENT_2026-11-03.md), [Parent review implementation guide](docs/ORGANIZATION_PORTAL_PARENT_REVIEW.md), [V37_ENHANCEMENTS.md](docs/V37_ENHANCEMENTS.md), [docs/V37_API_GUIDE.md](docs/V37_API_GUIDE.md), [docs/V38_AGENTIC_RISK_AND_PORTABILITY.md](docs/V38_AGENTIC_RISK_AND_PORTABILITY.md), [V37_TEST_REPORT.md](docs/V37_TEST_REPORT.md), [V38_TEST_REPORT.md](docs/V38_TEST_REPORT.md). The refined two-workspace portal is served from `/portal`; prior v3.6 implementation notes are retained for context.

## Stage 1 local sandboxes

- [Strong Agent Card binding and sandbox guide](docs/STAGE1_STRONG_BINDING_AND_SANDBOXES.md)
- [mTLS ingress design](docs/STAGE1_ZERO_TRUST_GATEWAY.md)
- [Windows local run guide](docs/STAGE1_LOCAL_RUN_GUIDE.md)
- `python scripts/paari_sandbox.py preflight` checks sandbox settings without printing secret values. Add `--mtls` to check Docker Compose and local PKI files.
- `python scripts/paari_sandbox.py up` starts the Postgres/API sandbox; `up --mtls` adds the Nginx mTLS profile.
- `python scripts/run_stage1_sandbox_checks.py` runs the Stage 1 tests and local SAFR verifier; add `--full` for longer simulated-provider HTTP E2Es.

The mTLS registration payload now requires `agent_card_signature_b64`, signed by the Agent Card private key. Existing certificate bindings without an Agent Card key fingerprint fail closed after migration and must be re-registered.

See [Security packaging notice](docs/SECURITY_PACKAGING_NOTICE.md): the uploaded input archive contained populated environment credentials, a local unencrypted Paari signing key, generated CA/server key material and SQLite databases. These artifacts are excluded from this v3.9 distributable. Treat the old issuer key as exposed and rotate it if it was ever used.

## v4.0 platform capabilities

- Tenant-scoped treasury budgets and atomic payment-authorization reservations.
- Receiver-signed `ACCEPTED` / `REJECTED` pre-execution acknowledgements; credit attestations remain separate from provider settlement.
- Durable reconciliation schedule with backoff, lease-based claiming and dead-letter review.
- Separate API and reconciliation-worker deployment; migrations run as a one-off release job, not on every API replica startup.
- Tenant-scoped control-plane APIs, Agent SDK/API integration surface and separate Organization Portal / Paari Console workspaces.
- Production reference topology for PostgreSQL, API replicas, a dedicated worker and secret-managed configuration.

The hosted SaaS/PaaS commercial and operating model is described in [V40_ARCHITECTURE.md](docs/V40_ARCHITECTURE.md). Subscription billing, plan metering, enterprise SSO/SCIM, tenant-specific key isolation and a live hosted control plane are not delivered by this source package.

## Local setup

Python 3.11 recommended (Python 3.13 used for the focused test run). Copy `.env.example` to `.env` and configure **independent, random** 32+-character sandbox secrets. The Setu AA and financial-context settings are documented in `docs/V39_OPEN_FINANCE_GOVERNANCE.md`. Supply an additional independent `PAARI_V37_DATA_ENCRYPTION_SECRET` for synthetic dataset encryption. Do not use real PAN, bank accounts or consumer finance data in this sandbox.

```bash
python -m venv .venv
# Activate the virtual environment (Windows: .venv\Scripts\Activate.ps1)
pip install -r requirements-dev.txt
# Set PAARI_ENV=sandbox and PAARI_DATABASE_URL / ALEMBIC_URL to a sandbox DB
# Set all secrets from .env.example. Keep Setu disabled until UAT credentials
# and user-consent/mandate binding flows are configured.
python -m alembic upgrade head
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Windows PowerShell example for one setting: `$env:PAARI_ENV='sandbox'`. Set all remaining variables likewise before migration and startup. Open `http://127.0.0.1:8000/docs` to inspect the actual backend endpoints.

```bash
python -m pytest -q tests/test_v40_treasury.py tests/test_v40_receiver_precheck.py tests/test_reconcile_worker.py
```

For synthetic enterprise fleet registration, first register and manually approve a parent with the v3.6 APIs. Set `PAARI_PARENT_ID` and `PAARI_PARENT_PASSWORD`, then run:

```bash
python scripts/v37_treasury_100_agents_demo.py --count 100
```

That demonstration uses live local API calls and generated agent keys, but discards the private keys and does **not** execute payments. Use a fresh throwaway sandbox database and only demo contact details.

## Safety and readiness

- The source includes a two-workspace product portal (`/portal`). The Organization Portal navigation is intentionally focused on Overview, Agent Registry, Payment Tracker, Treasury & Risk, and Organization. Data-permission/portability and payment-rail backend modules are retained in the codebase but are not exposed as Organization Portal pages in this refinement. The SAFR parent-review queue is sandbox-gated; no real money movement, certified KYC/KYB, approved legal agreements, live open-banking payment initiation or live stablecoin broadcast is included.
- v4.0 treasury ceilings are tenant/currency/period scoped and reserve exposure during authorization. `FAILED` and `PROVIDER_UNKNOWN` retain reservations until provider evidence resolves the outcome; `PAID` commits reserved exposure to spent. PostgreSQL contention testing remains a release acceptance requirement.
- Set `PAARI_REQUIRE_TREASURY_BUDGET=1` to fail closed when a tenant has no currency budget. Set `PAARI_REQUIRE_RECEIVER_PRECHECK=1` to require a signed receiver `ACCEPTED` event before execution; any receiver `REJECTED` event blocks that intent. Sandbox defaults keep this optional.
- A receiver acknowledgement proves only that the registered receiver key signed a claim. It does not establish legal identity/KYB, payment settlement or beneficiary credit. `CREDIT_ATTESTED` is post-capture evidence and cannot set provider state to `PAID`.
- Agent identity migration never imports payment mandates, credentials, keys or data grants. New destination consent and runtime proof are required.
- Data permissions and encrypted portability operate on synthetic balances/transactions only. Recipient-key pinning improves encryption binding, but the destination is not independently verified and the API does not deliver data to external institutions.
- PostgreSQL concurrency/recovery, complete strict multi-institution SAFR E2E, live external rail conformance, managed keys, MFA, independent security audit and full operational acceptance remain outstanding. **This remains a local development/integration preview, not a production-certified financial service.**


## Paari v3.7.1 stability fixes

- Copy `.env.example` to `.env` and replace all placeholders with independently generated values. Use a URL-safe value for `PAARI_POSTGRES_PASSWORD` because it is used in the database URL. Never commit `.env` or `paari_signing_key.pem`.
- The Compose deployment enables control-plane, receiver, federation, signed-mandate, and SAFR-envelope enforcement by default. Configure a trusted identity-provider adapter and provider sandbox credentials separately; a healthy `/health` endpoint does not imply `/health/ready` is ready.
- If `docker-compose.local.yml` is used with an existing volume created with a different database password, changing the Compose environment alone does not rotate the existing PostgreSQL role. Rotate the role password through a trusted local database session before reconnecting with the new value.
- Do not use `docker compose down -v` unless you intend to delete persistent database data.
- The test suite uses a disposable database and simulated provider by default. Provider-test success is not production certification.

### Compose quickstart (local sandbox only)

```powershell
Copy-Item .env.example .env
# Edit .env: replace each placeholder with an independently generated secret.
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-WebRequest http://127.0.0.1:8000/health/ready
```

The local PEM key is generated in the named `signing_keys` volume if absent; never
copy a real signing key into this archive. `/health/ready` may correctly return HTTP
503 until provider sandbox credentials and all required configuration are present.
The Compose healthcheck uses `/health` as a liveness probe. The host API port is bound
to loopback only. Do not run `docker compose down -v` unless intentionally deleting
all named Compose volumes and their data.


## Paari v3.7.1 local test run

The strict control-plane checkout-flow harness is available against an isolated
SQLite database and a local Razorpay-compatible stub. It uses synthetic identity,
receiver and federation fixtures; these fixtures are test evidence only, not KYC/KYB.

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
```

This command verifies one signed, bounded order submission, single-use replay
rejection, institutional control-plane and SAFR evidence, and an over-limit denial.
It does **not** verify provider-native autonomous settlement, a real Razorpay payment,
or production identity verification. The harness uses standard checkout mode for
the local order test because the repository does not include a provider-native
agentic-mandate adapter; autonomous mode correctly fails closed without one.

The three `test_pqc_*.py` modules require the optional `liboqs-python` package.
They now skip cleanly when that optional dependency is absent; PQC functionality has
not been validated in environments without liboqs.


## Enterprise risk modules retained in the backend

The Organization Portal exposes **Treasury & Risk** as its enterprise risk workspace. Data permissions/portability and payment-rail route-preview modules remain in the backend for future integration but their separate portal pages and navigation have been removed to keep the customer workspace focused. The Platform Console Approvals & Applications page now reviews parent applications only; provider/institution application cards have been removed from that page. The parent review flow for SAFR escalations is documented in [the portal refinement summary](docs/PORTAL_REFINEMENT_2026-11-03.md) and [the parent-review implementation guide](docs/ORGANIZATION_PORTAL_PARENT_REVIEW.md).


## Stage 1 validation snapshot (2026-11-16)

The earlier Stage 1 validation session recorded 137 selected tests passing. In the current packaging pass, 52 selected Stage 1/onboarding/control-plane/portal regression tests were rerun successfully, along with compilation and 17/17 local demo checks. An additional broader batch did not complete within its 180-second limit, and the complete repository suite is not claimed as passing. See [STAGE1_VALIDATION_REPORT.md](docs/STAGE1_VALIDATION_REPORT.md) for exact scope and limitations. The optional Docker/Nginx ingress profile still requires validation in a Docker-enabled environment.


## Security packaging note

The updated archive excludes the local unencrypted signing key found in the input bundle. Treat that input key as exposed and follow [the rotation and packaging notice](docs/SECURITY_PACKAGING_NOTICE.md) before relying on signatures from any environment that used it.


## Parent-facing SAFR escalation review

A payment held for SAFR escalation or parent step-up appears in the authenticated parent's Organization Portal Overview and Payment Tracker review queue. Parent decisions require password re-authentication and a reviewer note. Approval re-runs Paari release checks and may issue a bounded single-use authorization for the owning agent; rejection uses the signed reject path and denies the intent. The parent dashboard never receives the authorization token. See [Parent Portal Refinement Test Report](docs/PARENT_PORTAL_REFINEMENT_TEST_REPORT.md) for the tested boundary. This implementation is sandbox-only and is not a production parent-key custody or reviewer identity design.


## Separate Paari websites

- External Organization Portal: `http://127.0.0.1:8000/organization` (also available at legacy `/portal`).
- Internal Paari Console: `http://127.0.0.1:8000/console`.
- Full guide: `docs/SEPARATE_WEBSITES_GUIDE.md`.

The two UI documents are independently maintained under `web/organization/` and `web/internal/`; both connect to the shared Paari API.

## Stage 1 security and regulator-briefing increment

For the local onboarding walkthrough, set `PAARI_KYB_SIMULATION=1` in the sandbox `.env`. This only enables the synthetic KYB journeys; the API and both portals label them as non-verification. Keep it `0` outside the local demo. The simulation selector remains hidden unless the API confirms that this flag is enabled.

Stage 1 adds a locally runnable zero-trust agent ingress reference, sandbox KYB
journeys and evidence-first SAFR decisions. See:

- `docs/STAGE1_ZERO_TRUST_GATEWAY.md` — mTLS topology, certificate enrollment,
  Agent Card binding, revocation, trusted-proxy rules and local setup.
- `docs/STAGE1_REGULATORY_PITCH_BOUNDARIES.md` — accurate capability wording,
  responsibility model and outstanding legal/technical assurance gates.
- `docs/STAGE1_VALIDATION_REPORT.md` — exact local checks, selected test results,
  and validation items that could not be completed in this environment.
- `docs/STAGE1_LOCAL_RUN_GUIDE.md` — Windows/Docker Desktop sandbox setup,
  local CA generation, Agent Card certificate enrollment and revocation walkthrough.
- `deploy/nginx/paari-mtls-agent-ingress.conf` and
  `docker-compose.mtls.yml` — optional dedicated mTLS payment-ingress profile.
- `scripts/mtls_pki.py` — local-only CA, gateway and agent-certificate generation.

The sandbox KYB simulator is opt-in (`PAARI_KYB_SIMULATION=1`) and supports
`auto_approve`, `review_required`, `reject` and `provider_unavailable`. Its
records explicitly state `sandbox_only=true` and `legal_identity_verified=false`.
It does not call ACRA, MCA or any live KYC/KYB service. The simulation must never
be treated as legal identity evidence or used in a production environment.

The mTLS gateway profile is enabled with:

```bash
python scripts/mtls_pki.py init --out ./local_pki
python -m pip install -r requirements.txt -r requirements-postgres.txt -r requirements-dev.txt
# Complete .env with independent sandbox secrets before starting Compose.
docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d --build
```

For an existing active Agent Card, issue and register its certificate:

```bash
python scripts/mtls_pki.py issue-client --out ./local_pki --agent-id <AGENT_ID> --org-id <ORG_ID> \
  --agent-card-private-key ./agent-private.pem --agent-card-public-key ./agent-public.pem
```

Post the generated `local_pki/clients/<AGENT_ID>.register.json` payload (certificate plus Agent Card proof-of-possession signature) to `POST /control/v1/agents/<AGENT_ID>/mtls-certificates` using the Paari administrator API key. The Agent Card private key signs the exact certificate/organization binding payload locally and is never submitted to Paari. Use the issued client certificate and key when calling
the dedicated `https://agent-gateway.local:8443/v1/payments/intent` listener.
See the gateway guide for DNS/hosts-file and certificate details.

`/health/ready` and production startup gates require explicit production mTLS
configuration. Direct application access is not a substitute for the trusted
proxy: production networks must prevent all bypass paths and pin a narrow proxy
CIDR. The optional compose profile is a developer sandbox, not a production
PKI service.

Every newly recorded payment intent now exposes versioned `reason_codes`,
`reason_evidence` and `reason_catalog_version`; strict institutional control-plane
decisions persist the corresponding fields as well. Evidence includes server-side
policy evaluations, observed transaction values, and configured thresholds. For
example, a velocity review records the observed request count and the configured
limit/window. Null or unavailable values are not filled from client assertions.

**Release status:** this is a local security/governance increment, not a
production-ready or regulator-approved release. Live launch remains blocked
until the independently verifiable gates in
`docs/STAGE1_REGULATORY_PITCH_BOUNDARIES.md` are complete.


## v3.9 Open Finance governance increment

The Setu AA lifecycle now supports active consent binding to a same-user signed payment mandate, completed data-session normalization, AES-GCM encrypted source snapshots, organization-scoped financial-context retrieval and revocation propagation. The payment-intent flow records Open Finance context provenance and freshness as an additional governance signal. Fresh context is optional/OBSERVE-only by default; explicitly enabling `PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT=1` makes it mandatory at payment admission and execution.

The Setu integration supplies account information only. It does not initiate or execute payments, confer payment authority, or prove funds will settle through a payment rail. Read [docs/V39_OPEN_FINANCE_GOVERNANCE.md](docs/V39_OPEN_FINANCE_GOVERNANCE.md) for API payloads, configuration, lifecycle and limitations.

**v3.9 release status:** targeted local tests pass for the new binding, snapshot, encryption, retrieval, revocation and freshness-gate paths. The broader Setu test group could not be collected in the packaging environment because the `respx` development dependency was unavailable; no complete repository-suite pass is claimed. PostgreSQL concurrency, external Setu UAT and real provider settlement remain outstanding. This remains a local engineering and sandbox integration release, not a production-ready financial service.
