# Paari v3.4 receiver control-plane extension

**Development/local integration release — not production certified.** See [Paari v3.4 release notes](PAARI_V3_4_RELEASE_NOTES.md) for newly implemented receiver controls, console UI, run instructions, acceptance status and remaining production blockers.

---

# Paari v3.0 — Locally Demonstrable SAFR Runtime Governance

> **Local-first demonstration milestone (26 October 2026).** Built on the corrected
> v2.9 project and the July 2026 *Safeguards for Agentic Finance at Runtime*
> (SAFR) white paper. This release adds a local capability portal, signed-envelope
> decision demonstrations, human-review previews, repeatable local E2Es and
> persistent sandbox storage. **No money is moved and this is not a certified
> SAFR implementation or production-ready release.** See
> [`docs/RELEASE_NOTES_V3_0_LOCAL_DEMO.md`](docs/RELEASE_NOTES_V3_0_LOCAL_DEMO.md)
> and [`docs/SAFR_LOCAL_CONFORMANCE_V3_0.md`](docs/SAFR_LOCAL_CONFORMANCE_V3_0.md).

## Run the complete local demonstration

**Windows PowerShell** (Python 3.11 installed):

```powershell
.\start-local-demo.ps1
```

**Linux / macOS** (Python 3.11 and `venv` installed):

```bash
./start-local-demo.sh
```

Or install `requirements-dev.txt` and launch `python scripts/start_local_demo.py`.
Open **http://127.0.0.1:8765**. The persistent Paari API runs on
**http://127.0.0.1:8000/docs**. Click the eight SAFR policy examples and run both
payment E2Es. Offline verification: `python scripts/verify_local_demo.py --full`
checks every policy case and both payment demos without external accounts. For review-queue actions, copy the local reviewer code printed by
this command's terminal. All use demo-only authority, synthetic evidence and
local simulated settlement. Use Ctrl+C to stop.

If you have Docker and prefer real PostgreSQL, see `docker-compose.local.yml`
and the command examples in the v3.0 release notes. The default SQLite option
works without Docker and keeps its data under `data/local_demo/` across restarts.

### SAFR scope and trust boundaries

The portal renders the **four** SAFR dispositions (DENY / ESCALATE /
AUTO_EXECUTE / OBSERVE) using the real Paari rule engine, signed Governance
Envelopes, a sample review queue and a separately verifiable local audit ledger.
The local policy simulator is distinct from the real Paari API and can never
execute a payment. The two provider E2Es call Paari's real HTTP endpoints but
use explicitly isolated disposable local payment simulators. They are **not** a
single strict institutional autonomous E2E, and the scenario identity evidence
is NOT KYC/KYB. SAFR requires independently authenticated action provenance;
our synthetic trace is not independent evidence.

---

# Paari — UAE-First Agent Management & Runtime Risk Control Plane (v2.9 strict provider governance gate)

> **Corrected v2.9 source-package addendum (26 October 2026):** Schema/driver fixes, per-request proof JWTs, and strict provider-test preflight restrictions have been added to this package. See [the corrected-package change log](docs/V2_9_CORRECTED_PACKAGE_CHANGELOG.md). The original standard-posture Razorpay test-mode payment was not rerun as part of this patch; production KYC/KYB, managed signing and certification remain outstanding.


> **v2.9 strict provider governance gate:** provider consumption now rechecks the persisted intent, current permissive control-plane decision, policy version, transaction digest, principal/resource state, active grants, and payment-instrument binding. In production posture, every consume also requires a current provider-refreshed trusted principal identity and an unexpired processed SAFR envelope bound to the same intent, decision, context, and single-use authorization. New identity-evidence persistence and envelope-consumption fields are migration-backed. A 100-agent fleet inventory acceptance test has been added; it is a functional check, not a production load/soak certification. See [`docs/RELEASE_NOTES_V2_9_STRICT_PROVIDER_GOVERNANCE.md`](docs/RELEASE_NOTES_V2_9_STRICT_PROVIDER_GOVERNANCE.md) and [`docs/STRICT_PROVIDER_FLOW_ACCEPTANCE_V2_9.md`](docs/STRICT_PROVIDER_FLOW_ACCEPTANCE_V2_9.md).
>
> **Important release boundary:** the repository adds a provider contract and strict wiring, not a genuine vendor identity adapter or cloud KMS/HSM integration. The successful Razorpay test-mode run described in the v2.8 report used standard posture; it is not evidence that strict governance was applied to that live-provider transaction. The strict end-to-end proof remains simulator-only until a real trusted KYC/KYB adapter and managed signer are installed and accepted. Production startup stays fail-closed. Full SAFR conformance, PostgreSQL concurrency/soak evidence, production human escalation, audit retention hardening, UAE regulatory review, and independent security review remain open. `PAARI_HOME_JURISDICTION=AE` is metadata, not a license or proof of rail availability.

Paari is a trust and governance layer between **any AI agent** and payment infrastructure. The agent never receives standing payment authority. Paari verifies who the agent is, who authorized it, what it is allowed to do, and whether a specific payment should execute.

> **What Paari does today.** Paari enables an AI agent to *propose* a payment while Paari verifies identity, delegated authority, the user mandate, limits and transaction policy before issuing a single-use bounded authorization. The protocol now has a complete **provider-native autonomous settlement path** (`PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID`) and an explicit reference provider for no-human-checkout conformance testing. A real-money deployment still requires a payment provider to expose and enable a server-to-server mandate/token debit contract; Paari never treats a normal checkout order as autonomous settlement. The agent proposes; Paari independently validates authority and authorizes execution.

```text
Any AI Agent
    |
    v
Parent Authority + Signed Delegation
    |
    v
Paari Agent Identity / Card / Credential
    |
    v
Proof-of-Possession Authentication
    |
    v
Payment Intent
    |
    v
Governance: identity -> authority -> capability -> limits -> currency -> risk -> MFA
    |
    +---- ALLOW ----> Single-use Bounded Authorization
    |
    +---- REVIEW ---> Parent-signed step-up approval
    |
    +---- DENY -----> No provider authorization
    |
    v
Provider Execution (Razorpay adapter)
    |
    v
Verified Webhook / Reconciliation
    |
    v
PAID / FAILED / UNKNOWN + Hash-chained Audit
```

## UAE-first SAFR runtime control plane (v2.9 strict provider governance gate)

Paari's product direction is **agent management + runtime risk control**, similar in operating model to enterprise API management, with financial mandates, pre-execution risk decisions and reconciliation added. The target lifecycle is:

```text
Agent / enterprise workflow
    -> signed Governance Envelope for each protected action
    -> agent + parent delegation + principal + resource verification
    -> versioned Controls Repository and evidence checks
    -> SAFR disposition: DENY | ESCALATE | AUTO_EXECUTE | OBSERVE
    -> transaction-bound bounded authorization (where policy permits)
    -> provider execution adapter
    -> audit evidence + provider reconciliation
```

Paari preserves the v1 parent-registration model: parents register agents, bind public keys, sign capabilities/limits/expiry into a delegation, and Paari maintains the Agent Card and credential lifecycle. Agent portability exports identity metadata and signed provenance only; it does not transfer private keys, user mandates, resource grants, provider tokens or spending authority. The receiving organization must independently trust the issuer key and re-authorize the agent.

Implementation details and the explicit distinction between sandbox-tested behavior and remaining conformance work are in [`docs/SAFR_CONFORMANCE_MATRIX_V2_7.md`](docs/SAFR_CONFORMANCE_MATRIX_V2_7.md) and [`docs/SAFR_SANDBOX_MILESTONE_V2_8.md`](docs/SAFR_SANDBOX_MILESTONE_V2_8.md). UAE identity and Open Finance vendor/regulatory evaluation is recorded in [`docs/UAE_IDENTITY_KMS_AND_OPEN_FINANCE_V2_7.md`](docs/UAE_IDENTITY_KMS_AND_OPEN_FINANCE_V2_7.md).

The schema for the action contract is [`schemas/paari-safr-governance-envelope.v1.schema.json`](schemas/paari-safr-governance-envelope.v1.schema.json). API routes use organization-scoped control keys: `POST /control/v1/governance/envelopes/validate` validates envelope ingress and stores a replay receipt without issuing authority; `POST /control/v1/governance/envelopes/process?transaction_id=...` binds a payment envelope to the persisted policy disposition and reports the live status of the existing bounded authorization; `GET /control/v1/organizations/{org_id}/fleet/risk-summary` reports tenant-scoped risk/exposure; the fleet agent-revoke route invalidates credentials/grants/unconsumed authorizations; and portability export/import routes stage metadata while preserving destination-side authorization. The process route still does not execute payment.

## OpenAI-compatible LLM gateways (including Kilo.ai)

The brokered agent loop can use any tested OpenAI-compatible chat-completions endpoint that supports tool calling. Configuration resolution prefers Kilo when `KILO_API_KEY` is set (or `PAARI_LLM_PROVIDER=kilo`), then a generic gateway, while preserving the older `BYNARA_*` names for compatibility. Example local `.env` settings:

```dotenv
PAARI_LLM_PROVIDER=kilo
KILO_API_BASE=https://ai-gateway.kilo.ai/api/v1
KILO_API_KEY=<your-kilo-jwt-api-key>
KILO_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
```

Model availability and free-tier access can change; `scripts/llm_smoke.py` validates the configured model catalog entry and performs an actual tool-call probe before the full E2E run. A catalog listing alone is not proof that a model is entitled or operational. Keep provider keys in a local ignored `.env` or secret manager. Do not send customer secrets or real payment credentials to a free-tier model gateway.

To test the new strict institutional layer locally without API spend:

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane
# Include local-stub capture, signed webhook, reconciliation to PAID, proof verification and authorization replay checks (still no real money):
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub --settle
```

The `--execute-stub --settle` variant is the deterministic end-to-end sandbox rehearsal: it executes one order against the local stub, simulates capture, verifies signed-webhook and replay behavior, reconciles to `PAID`, and checks the settlement provenance in the proof bundle; it also verifies the bounded authorization cannot be consumed twice. Use `--execute-stub` alone when deliberately testing only provider submission without settlement. This command starts a throwaway sandbox, enables autonomous signed-mandate and strict control-plane gates, provisions organizations/resources/access grants/versioned policy through the control-plane API, then checks a signed mandate, audited `AUTO_EXECUTE` decision, a server-enforced 20x over-cap denial and audit-chain verification. Its synthetic high-assurance result is seeded only into the temporary SQLite fixture and is **not** a production identity verification. For real-model + Razorpay test-order validation, configure Kilo plus Razorpay test credentials in local `.env` and run:

```bash
python scripts/llm_agent_e2e.py --with-server --strict-control-plane
```

An order ending in `PROVIDER_SUBMITTED` is not a settled payment. These E2E commands never capture a real Razorpay order; settlement requires a real payer and verified provider callback.

## Core security model

### 1. Agent Trust

```text
Parent Authority
  -> verified trust tier
  -> parent-signed delegation
  -> agent public-key binding
  -> Paari Agent Card
  -> Paari credential
```

The parent delegation is authoritative for capabilities, payment limit, currency, and expiry. Agent-requested permissions are never trusted. Agent and parent private keys stay with their owners.

### 2. Agent Authentication

An agent proves possession of its private key through challenge/response. Paari issues a short-lived session bound to the authenticated credential and key fingerprint.

For protected v1 payment requests, Paari also requires a sender-constrained `Paari-Proof-JWT` bound to:

- the authenticated session token hash
- the agent identity
- HTTP method and exact path
- issue time
- a one-time proof JTI

Preferred HTTP form:

```http
Authorization: Bearer <session-token>
X-Paari-Proof: <Paari-Proof-JWT>
```

The reference implementation still accepts the legacy JSON `session_token` field for compatibility; new clients should use the Authorization header. Session tokens must never appear in URLs.

### 3. Payment Governance

Every payment intent is evaluated independently:

1. Agent identity and credential status
2. Parent authority status
3. Delegation validity
4. Requested capability
5. Per-transaction amount limit
6. Delegated currency
7. Velocity/risk rules
8. Step-up requirement
9. Idempotency and transaction state

The result is exactly one of:

- `ALLOW` — Paari may mint bounded payment authorization.
- `REVIEW` — step-up/dual-control approval required.
- `DENY` — no provider authorization is created.

### 4. Bounded Payment Authorization

An authorization is short-lived and bound to:

```text
agent
transaction
merchant
amount
currency
expiry
single-use
```

Authorization usage is reserved atomically in the database. The provider request uses the authorization ID as its provider-side idempotency key.

### 5. Provider-native autonomous settlement

Paari separates **protocol capability** from **provider entitlement**. The provider-facing `AgenticPaymentProvider` interface supports:

```text
validate mandate/instrument reference
        ↓
authorize one payment under bounded authorization
        ↓
capture provider-authorized payment
        ↓
direct provider read corroborates capture
        ↓
PAID
```

`app/providers/reference_autonomous.py` is a deterministic in-memory conformance
provider. It proves the protocol path without moving real money and is the default
for `scripts/autonomous_payment_e2e.py`. `RazorpayAgenticProvider` is the real
provider adapter seam: it is **fail-closed** until the deployment supplies the
provider's exact documented mandate/debit paths and an explicit capability
attestation. If that capability is unavailable, `PAARI_MODE=autonomous` never
fallbacks to an ordinary human-checkout order.

### 6. Provider Execution & Settlement

The provider layer is abstracted through `PaymentProvider`. Razorpay is the current provider implementation.

Paari only moves payment state from the provider boundary after authenticated provider truth:

```text
AUTHORIZED
  -> PROVIDER_SUBMITTED
  -> PROVIDER_AUTHORIZED      provider holds an authorisation, money not captured
  -> CAPTURED                 provider announced a capture, not yet corroborated
  -> PAID                     capture confirmed by a direct provider read
  or FAILED / DECLINED / EXPIRED / CANCELLED / PROVIDER_UNKNOWN
  and after PAID: REFUNDED / REVERSED
```

`PAID` requires two independent provider signals, not one. A signature-verified
webhook moves the row to `CAPTURED`; it becomes `PAID` only when
`app.reconcile.confirm_capture` corroborates the capture against the provider's
own API, with amount and currency matching the bounded authorization exactly. If
that read cannot be made, the row stays `CAPTURED` — a non-terminal state the
reconciliation worker keeps visiting — rather than being marked settled on a
single inbound message. The webhook handler has no path to `PAID` at all, and
`tests/test_phase9_state_machine.py` enforces that by reading the handler's own
event mapping.

`PROVIDER_UNKNOWN` is reconciled against provider state rather than guessed. `PAID` is terminal for the payment itself.

Webhook processing:

- verifies the raw request body with Razorpay HMAC
- derives a deterministic replay key when the provider payload has no event ID
- rejects provider amount/currency mismatches
- ignores duplicate events
- applies only legal transaction-state transitions

### 7. Audit & Accountability

Money-state and governance events are written to an append-only SHA-256 hash chain. Audit entries include the governance decision, reasons, authorization, provider submission, webhook/reconciliation state changes, and security actions.

### 8. Multi-tenancy

Organizations are first-class tenants. Tenant-scoped rows carry `org_id`; foreign keys prevent orphaned ownership. Non-default organizations use explicitly configured provider accounts and credentials. Paari must never silently fall back to another organization's payment credentials.

## Versioned protocol surface

The public protocol is defined in `docs/PROTOCOL.md` and the JSON schemas under `schemas/`.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/.well-known/paari` | Discover Paari v1 protocol capabilities and endpoints |
| POST | `/v1/agents/register` | Register an external agent with a signed parent delegation |
| GET | `/v1/agents/{agent_id}/card` | Fetch the Paari-signed Agent Card |
| POST | `/v1/auth/challenge` | Request agent key-possession challenge |
| POST | `/v1/auth/verify` | Verify challenge and issue short-lived session |
| POST | `/v1/payments/intent` | Submit a governed payment intent |
| POST | `/v1/payments/authorizations/{authorization_id}/consume` | Execute a single-use bounded authorization |
| POST | `/v1/payments/webhooks/razorpay` | Verified Razorpay settlement events |
| POST | `/v1/reconcile/{authorization_id}` | Reconcile provider truth after ambiguous/lost events |
| GET | `/v1/audit/{transaction_id}` | Retrieve owner-scoped audit trail |
| GET | `/v1/proof/{transaction_id}` | Retrieve the owner-scoped stage-output proof bundle (read-only) |
| POST | `/v1/agents/{agent_id}/rotate-key` | Rotate agent key with a fresh parent delegation |
| POST | `/v1/authorizations/{authorization_id}/revoke` | Revoke unused bounded authorization |
| POST | `/v1/parents/{parent_id}/rotate-key` | Rotate parent key (admin controlled) |
| POST | `/v1/parents/{parent_id}/kyb` | Record the external KYB verification reference |

Unversioned routes are retained as legacy compatibility surfaces. New external integrations should use `/v1`.

## Protocol objects

- **Parent Authority** — trusted delegator.
- **Delegation** — parent-signed grant for one agent public-key fingerprint, capabilities, limit, currency, and expiry.
- **Agent Card** — signed discovery/identity object; it does not itself grant payment authority.
- **Credential** — Paari-signed agent identity credential.
- **Session** — short-lived authenticated agent session.
- **Paari-Proof-JWT** — sender-constrained proof for protected HTTP requests.
- **Payment Intent** — requested money action.
- **Governance Decision** — ALLOW / REVIEW / DENY.
- **Bounded Authorization** — single-use authorization for one provider execution.
- **Provider Transaction** — authoritative Paari execution/settlement state.

## Institutional control plane (architecture v2)

Paari extends its existing signed agent-delegation and bounded-authorization protocol with organization-scoped principals, governed financial/data resources, time-bounded access grants, versioned policies and a durable SAFR-style decision for each intent. In strict mode, an authorization requires a current signed mandate, a unique active principal mapping, exactly one active source-resource binding, a matching resource, and both agent and principal `payment:execute` grants. Missing or ambiguous evidence fails closed.

The administrative API is under `/control/v1`; it issues organization-bound control keys, manages principals/resources/grants, and publishes policy versions. See [`docs/ARCHITECTURE_V2.md`](docs/ARCHITECTURE_V2.md) for the nine-layer map and endpoint inventory, [`docs/SAFR_CONTROL_PLANE.md`](docs/SAFR_CONTROL_PLANE.md) for disposition semantics, [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md) for the release gate, and [`docs/RELEASE_GATE_V2_4.md`](docs/RELEASE_GATE_V2_4.md) for reproducible acceptance commands.

**Open banking and stablecoin are governed resource types, not certified live rails in this version.** The current non-agentic execution adapter is Razorpay; autonomous settlement is unavailable unless a deployment wires and verifies a genuine provider-specific mandate/debit contract. Do not use test or reference adapters for live funds.

### Strict institutional mode

The shipped Docker Compose service forces `PAARI_CONTROL_PLANE_ENFORCEMENT=1` and `PAARI_REQUIRE_SIGNED_MANDATE=1`; its healthcheck uses `/health/ready`, which can be false even while `/health` reports that the process/database is alive. Set up an active principal, resource, both grants, provider binding and active policy before a payment can be authorized. `PAARI_ENV=prod`/`prod-live` is intentionally blocked by this release until a managed KMS/HSM signing adapter and trusted KYC/KYB identity-provider adapter are implemented and reviewed. Apply the full migration chain with `alembic upgrade head` before enabling strict mode:

```bash
alembic upgrade head
```

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
export PAARI_ADMIN_API_KEY='change-me'
alembic upgrade head
uvicorn app.main:app --reload
```

Default development storage is SQLite. Production should use PostgreSQL.

### Required payment secrets

```bash
RAZORPAY_KEY_ID
RAZORPAY_KEY_SECRET
RAZORPAY_WEBHOOK_SECRET
PAARI_ADMIN_API_KEY
PAARI_SIGNING_KEY_PATH
DATABASE_URL
```

When `PAARI_LIVE=1`, Paari refuses to boot without the webhook secret and admin credential. Provider credentials are server-side only.

## External-agent proof

`scripts/foreign_agent_proof.py` is intentionally written without importing `app.*`. It uses its own Ed25519 key pair and HTTP client to exercise the public protocol surface, proving that an independent client can:

```text
register -> authenticate -> read active user mandate -> propose payment
-> pass governance -> receive bounded authorization
-> consume through the configured provider path -> verify audit -> prove revocation
```

When a provider-native agentic adapter is configured, the consume step can end at
`PAID` with no browser checkout. When only ordinary Razorpay Test-Mode orders are
available, the proof correctly stops at `PROVIDER_SUBMITTED`; it does not call that
autonomous payment.

Run `python -m pytest -q` for the current suite. The repository also includes
`tests/test_razorpay_agentic.py` and autonomous-state regression tests for the
provider-native path.

## Security limitations outside the reference implementation

Paari's reference implementation intentionally leaves several production deployment concerns to the operator:

- real KYB/identity-provider integration for parent authorities
- KMS/HSM-backed Paari signing key management
- permanent HTTPS deployment and hardened webhook ingress
- production PostgreSQL operations and automated migration CI
- centralized secrets management
- production monitoring, alerting, backups, incident response, and disaster recovery

These are deployment/security operations, not reasons to give an AI agent standing payment credentials.

## Project status (v2.9 — strict provider governance gate)

v2.9 strengthens the final authorization-consumption boundary rather than claiming a completed production integration. With strict control-plane enforcement enabled, the provider-consume path rechecks the saved intent and one-time authorization, current payment policy version/disposition, transaction digest, active principal/resource, grants, and payment-instrument binding. When `PAARI_ENV` is `prod`/`prod-live` or `PAARI_LIVE=1`, the service refreshes principal identity status from the configured trusted identity adapter immediately before execution and requires an unexpired processed SAFR envelope bound to the exact intent, policy decision, context digest, and authorization. Successful consume marks the receipt consumed and emits audit evidence. Replay retains the protocol's `409 Authorization already used or revoked` response.

The new `POST /control/v1/principals/{principal_id}/verify` endpoint routes verification through the identity-provider contract. Verified results must be explicitly provider-pinned and bound to the tenant-scoped subject digest, verification purpose, jurisdiction, assurance level, evidence digest, and expiry. A module path or `VERIFIED` label alone is not trust. The bundled fake adapter exists only for tests. No live identity vendor adapter is included.

Migration `e6f7a8b9c0d1` adds identity verification metadata and exact envelope-to-execution binding. Run `python -m alembic upgrade head` before testing/deployment. `PAARI_REQUIRE_SAFR_ENVELOPE=1` is required in production posture; strict deployment also requires `PAARI_CONTROL_PLANE_ENFORCEMENT=1`, signed mandates, autonomous mode, managed KMS/HSM, a trusted healthy identity adapter, PostgreSQL, a real provider adapter and separately certified settlement behavior. The production readiness endpoint intentionally continues reporting blockers until these acceptance requirements are met.

Coverage added in this release includes identity-provider pinning, evidence/subject/purpose/expiry validation, principal verification persistence, fail-closed behavior when the provider is absent, and a 100-agent fleet-summary functional acceptance test. This does not constitute a concurrency/soak test, independent security audit, full SAFR certification, UAE regulatory approval, or successful strict live-provider settlement. The previously reported Razorpay PAID transaction was a standard-posture Razorpay **test-mode** payment, not a strict live-provider proof.

See [`docs/RELEASE_NOTES_V2_9_STRICT_PROVIDER_GOVERNANCE.md`](docs/RELEASE_NOTES_V2_9_STRICT_PROVIDER_GOVERNANCE.md) and [`docs/STRICT_PROVIDER_FLOW_ACCEPTANCE_V2_9.md`](docs/STRICT_PROVIDER_FLOW_ACCEPTANCE_V2_9.md). The v2.8 summary below is retained as historical release evidence.

## Project status (v2.8 — UAE-first SAFR sandbox milestone; historical baseline)

The project now frames Paari as an **agent management and runtime risk control plane** for enterprise financial actions. UAE (`AE`) is the default home-jurisdiction metadata, not a representation of licensing or rail availability. v2.8 adds processing of signed Governance Envelopes against saved payment decisions, a pre-authorization hook in the strict LLM sandbox, local simulated settlement with signed webhook/reconciliation/proof verification, fleet risk and emergency revocation endpoints, and destination-side portability staging with out-of-band issuer trust and local consent checks.

The envelope validate route remains deliberately **not an authorization route**. The new process route also does not mint a second authorization or execute a payment: it requires a saved payment intent/disposition, validates exact context binding, records the disposition/hold, and reports whether the existing one-time authorization can still be consumed. Data/API actions fail closed until their governed executors are registered.

The v2.5/v2.6 hardening and prior v2.4/v2.5 session reports remain historical evidence for earlier trees. Their test counts and live Razorpay test-mode settlement result do not automatically apply to v2.7. See [`docs/IMPLEMENTATION_VERIFICATION_V2_7.md`](docs/IMPLEMENTATION_VERIFICATION_V2_7.md) for the exact tests run on this tree. The complete repository suite did not finish in this environment and must be rerun in clean CI.

Production remains blocked until a concrete managed KMS/HSM signer and trusted KYC/KYB adapter are integrated, PostgreSQL concurrency/soak testing is complete, human review is operational, audit storage and operations are hardened, and independent security plus UAE legal/regulatory reviews and partner sign-off are complete.

## Paari v2 extension: user payment authority

The current codebase adds a provider-neutral **User Payment Mandate** layer on
top of parent delegation. A mandate is a cryptographically signed
authorization artifact: the canonical signed payload covers user/agent binding,
per-transaction, hourly, daily, per-merchant and per-category limits, currency,
optional merchant/category allowlists, review threshold and validity window. A
mandate's Ed25519 signature is verified **in the authorization path** (payment
intent) and again at execution time (consume) — a valid signature does not make
an expired mandate valid, and a mandate whose stored row was altered no longer
verifies.

Mandate resolution is a tri-state:

```text
NONE    - this agent never had a mandate; only PAARI_MODE=autonomous denies
LAPSED  - a mandate existed but is expired / revoked / out of window
          -> DENY in every mode (a lapsed grant is not an absent grant)
ACTIVE  - evaluate every active mandate; the tightest one governs
```

Spending windows are **rolling** (not calendar-boundary based) and clamped to
the mandate's own validity start. The active mandate is resolved server-side
and cannot be chosen by the LLM/client.

Governance posture is defined once, in `app.config.mandate_policy()`:

```text
PAARI_MODE=standard     (default) mandate enforced when one exists
PAARI_MODE=autonomous             an active mandate is REQUIRED
PAARI_REQUIRE_USER_MANDATE=1      legacy alias for autonomous
PAARI_REQUIRE_SIGNED_MANDATE=1    an unsigned mandate is refused
```

An unrecognised `PAARI_MODE` is rejected rather than downgraded, and the active
posture is reported on `GET /health` alongside `autonomous_settlement`.

### Autonomous settlement contract

The consume path now has a strict provider-native autonomous branch:
`PROVIDER_SUBMITTED → PROVIDER_AUTHORIZED → CAPTURED → PAID`. It does **not**
create an ordinary checkout order first, and `PAARI_MODE=autonomous` fails closed
when no provider-native adapter is capable. The adapter must validate a provider
mandate/instrument reference, authorize the exact bounded payment, report capture,
and allow an independent provider read to corroborate amount/currency/status.

`app/providers/reference_autonomous.py` provides a deterministic protocol-only
implementation for conformance and development; it moves no real money.
`app/providers/razorpay_agentic.py` is the production adapter seam and refuses to
claim autonomous capability until the real account is explicitly provisioned with
the provider's documented server-to-server mandate/debit contract.

`scripts/autonomous_payment_e2e.py --provider reference` therefore demonstrates a
complete autonomous **protocol** flow ending in `PAID` without human checkout.
`scripts/autonomous_payment_e2e.py --provider real-razorpay` is the live-provider
proof and fails closed when the account lacks the required provider capability.
The real-LLM variant is `scripts/llm_agent_e2e.py --with-server --require-mandate`.

### Causal audit attribution

`llm_run_id`, `llm_model`, `llm_tool_call_id` and `llm_tool_name` are
**client-asserted trace labels**, never conversation content or secrets. Paari
proves that the authenticated agent submitted them (they ride on the
sender-constrained `Paari-Proof-JWT`); it does not and cannot prove that a model
produced them, because the identifiers originate from the LLM. The
`llm_tool_call` audit event is written **only** when attribution was actually
claimed, and `PaymentIntent.llm_attributed` records the claim; payments with no
causal ids are marked `payment_proposed` instead.


## Clean release security note

This release archive intentionally excludes `.env`, private signing keys, local database files, Git history, checkout pages containing provider key identifiers, and runtime caches. Start in sandbox mode and supply credentials through environment variables or a secret manager.


## v2.5 signing interface and release checks

The Paari-issued JWTs and agent-card signing functions now use `app/signing_backends.py`. The default `local_pem` adapter is for sandbox/test; an actual managed provider must implement the documented client contract and return `KmsHsmSigningBackend`. This archive includes interface and fake-client tests, not a concrete cloud KMS/HSM integration. See `docs/KEY_MANAGEMENT_DESIGN_V2_5.md`, `docs/RELEASE_PLAN_V2_5.md` and `docs/IMPLEMENTATION_VERIFICATION_V2_5.md`.

The migration chain now has a follow-up revision `b3c4d5e6f7a8` to remove duplicated PostgreSQL unique constraints while retaining the matching unique indexes. Always run `alembic upgrade head`; do not pin the deployed schema to an older revision ID.

## v2.6 — strict persistent-service verification

The live settlement hand-off showed why a real provider capture and strict institutional enforcement must be proven separately. The v2.6 scripts make the running service report its actual posture and prevent the live E2E driver from creating an order when strict enforcement is off.

- Start a strict, persistent **sandbox-only** process with `python scripts/run_strict_sandbox_server.py` (or use the strict Docker Compose service).
- Verify its actual configuration using `python scripts/strict_service_gate.py`.
- Use `python scripts/strict_service_gate.py --require-trusted-identity-provider` to make the missing principal KYC/KYB adapter a blocking gate. It is expected to fail until that adapter is implemented.
- The default `scripts/live_e2e_test.py` refuses a positive strict live E2E while trusted principal identity is not configured. The optional `--signed-mandate-only-sandbox` mode is only for an isolated sandbox with control-plane enforcement disabled and is **not** a strict SAFR conformance proof.

See `docs/STRICT_LIVE_SERVICE_GATE_V2_6.md` and `docs/IMPLEMENTATION_VERIFICATION_V2_6.md`. Production startup remains blocked until the actual managed KMS/HSM and trusted identity adapters, concurrency/soak testing and independent security review are complete.


## v2.8 — SAFR end-to-end sandbox, fleet risk and governed portability

- Envelope schema: `schemas/paari-safr-governance-envelope.v1.schema.json`.
- Validate a signed envelope with an organization-scoped control key: `POST /control/v1/governance/envelopes/validate`. A success is `VALIDATED_ONLY`, not a policy decision or authorization.
- Export a signed agent identity/delegation package: `GET /control/v1/organizations/{org_id}/agents/{agent_id}/portability-export`. Trust the Paari issuer key out of band before running `python scripts/validate_agent_portability.py` against an exported package. Portability transfers no authority.
- SAFR matrix: `docs/SAFR_CONFORMANCE_MATRIX_V2_7.md`. UAE/global architecture: `docs/UAE_GLOBAL_SAFR_ARCHITECTURE_V2_7.md`. Candidate identity/KMS/Open Finance integration decision record: `docs/UAE_IDENTITY_KMS_AND_OPEN_FINANCE_V2_7.md`.
- UAE reference material: [CBUAE Open Finance Regulation](https://rulebook.centralbank.ae/en/rulebook/open-finance-regulation), [UAE PASS docs](https://docs.uaepass.ae/), [Sumsub business-verification docs](https://docs.sumsub.com/docs/verify-businesses), [AWS KMS CreateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html). These are evaluation references; none of these vendor adapters is included as a live integration in this release.
