# Paari v3.7.1 — Architecture, Data Flow & Component Analysis

**Tree:** `Paari_v3_7_1_Enterprise_Risk_Control_Plane` · **Analysed:** 2026-11-12
**Scope:** every Python module in `app/` (69 files, ~14.0k LOC), the SDK/harnesses, web front ends,
migrations, tests and deployment. Method: module docstrings + AST import graph + live OpenAPI
introspection of the running container + targeted source reading of every control-flow core.

---

## 1. What the system is

Paari is a **trust and governance layer between AI agents and payment infrastructure**. It does not
move money by itself and it is not a wallet. It decides, on the server side, whether an AI agent's
payment request is *authorised*, and it produces tamper-evident evidence for every decision.

Three ideas hold the whole design together:

1. **Authority is never client-asserted.** An agent's spending power comes from a *parent-signed
   delegation* plus an *active signed user mandate*, both verified server-side at request time.
2. **Every decision is evidence.** Each transition appends to a per-transaction hash-chained audit
   log (`app/audit.py`), independently anchored to WORM storage (`app/audit_anchor.py`).
3. **Nothing is settled until it is corroborated.** A provider webhook is attestation of an event;
   `PAID` requires a *second, independent* read of the provider (`app/reconcile.confirm_capture`).

Scope: v3.7.1 is a **backend-only, sandbox-grade release**. The two web front ends are first-party
demos of the same backend; there is no real rail settlement, no KYC/KYB, no managed key custody.

---

## 2. Runtime topology

| Layer | Process | Port | Persistence |
|---|---|---|---|
| Paari API (FastAPI/uvicorn) | Docker `app` container | 8000 (loopback) | Postgres `db` container, named volume |
| Test/host Postgres | Docker `local-postgres` | 5439 | `paari_demo`, `paari_demo_test` |
| Provider simulator | host process (`scripts/stub_razorpay.py`) | dynamic | in-memory / optional durable JSON |
| Reconciliation worker | thread inside the API process | — | same DB |
| Organization Portal / Paari Console | static HTML served by the API | `/organization`, `/console` | sessionStorage only |
| Cloudflare quick tunnel (optional) | `cloudflared` | — | — |

The API image runs `alembic upgrade head && uvicorn app.main:app` — tables are **never** created at
import (`app/main.py` lifespan; `app/database.py`).

---

## 3. Layer map

```
web/organization ─┐
web/internal ──────┴─► app.main ──► routers ──► control plane / v36 / v37 / federation / receivers
                        │                │
                        │                ├─► mandates + mandate_signing  (authority)
                        │                ├─► audit (+audit_anchor)       (evidence)
                        │                ├─► providers (razorpay/paypal/agentic) (execution)
                        │                ├─► reconcile (+worker)         (settlement)
                        │                └─► portability / proof_bundle  (evidence export)
                        └─► protocol (discovery, envelope, messages, errors)
```

Import-graph facts (AST-extracted, 170 intra-`app` edges):

* **Hot spots:** `app` (32 importers), `app.database` (17), `app.audit` (16), `app.mandate_signing` (6).
* **Orchestrators:** `app.routers.payments` imports 21 app modules — it is the single decision hub;
  `app.main` (16) is the composition root; `app.routers.v1` (11) and `app.v37.router` (11) are the
  other wide surfaces.

---

## 4. Complete module inventory (`app/`)

| Module | Purpose |
|---|---|
| `main.py` | Composition root: lifespan, router mount order, pure-ASGI security-header middleware, startup guards, `/health`, `/health/ready`, static portal routes. |
| `config.py` | **Single source of truth for governance posture.** `mandate_policy()` resolves `PAARI_MODE`; unknown modes raise (never default to permissive). |
| `database.py` | Engine/session wiring, `UTCDateTime` (tz-aware on SQLite *and* Postgres), `resolve_database_url()`, `assert_disposable_database_url()` (destructive-guard), SQLite FK pragma. |
| `models.py` | Core ORM: 31 entities (see §5). |
| `schemas.py` | Pydantic wire contracts for the legacy + v1 surfaces (`AgentCard`, `V1AgentCard`, `PaymentIntentRequest`, `V1PaymentIntentRequest`, `CreatePaymentMandateRequest`, …). |
| `security.py` | Signing backend selection, credential JWTs, **sender-constrained sessions**, `X-Paari-Proof` request proofs, agent-card signing/verification, admin-key auth. |
| `signing_backends.py` | Provider-neutral `SigningBackend`: `LocalPemSigningBackend` (dev) and `KmsHsmSigningBackend` (production posture; refuses to run without a KMS/HSM client). |
| `pqc_signing_backends.py` | ML-DSA-65 / SLH-DSA-128S backends (skipped without `liboqs-python`). |
| `crypto_utils.py` | Canonical JSON, key generation/fingerprints, Ed25519 + hybrid/PQC sign/verify. |
| `transitions.py` | **The** `ProviderTransaction.state` machine (§8). `IllegalTransitionError` on illegal jumps. |
| `audit.py` | Append-only hash-chained log (v1 and v2 hash formats), `record_audit()` (flush-only), `verify_chain()`, causal LLM-label carry-forward. |
| `audit_anchor.py` | WORM (S3 Object Lock COMPLIANCE) anchoring of chain heads; refuses unversioned/non-locked buckets and refuses to downgrade to a mutable copy. |
| `mandates.py` | Mandate policy evaluation: tri-state `NONE/LAPSED/ACTIVE`, rolling windows, per-merchant/per-category spend accounting, `require_review_above`. |
| `mandate_signing.py` | Mandate canonical payload + Ed25519 signature issuance/verification. |
| `governance.py` | `PolicyResult` / `GovernanceResult` — one structured verdict object instead of re-derived booleans. |
| `ratelimit.py` | Table-backed rate limits (shared across uvicorn workers). |
| `serialization.py` | Cross-dialect locking: `acquire_gate(s)` (mandate budget gate, may commit) vs `acquire_chain_lock` (audit chain, never commits). Both fail closed. |
| `proof_bundle.py` | Read-only assembly of the 14 stage artifacts + settlement provenance mapping (`provider|simulator|unattributed`). |
| `reconcile.py` | Reconciliation of missed webhooks / unknown executions; `confirm_capture()` — the only path that may mint `PAID`. |
| `reconcile_worker.py` | Background worker (thread) with interval, dead-letter count and alert sink. |
| `provider_accounts.py` | Strict per-org provider routing; secrets from org-tagged env vars, never from the DB. |
| `portability.py` | Signed, least-privilege Agent Card export/import (identity only — never keys, mandates, grants, credentials). |
| `trust.py` | Parent trust verification abstraction (`AdminApprovedTrustProvider`). |
| `portal_extension.py` | The two-workspace API facade: parent feeds + review queue, platform admin views/provisioning/revocation. |
| `protocol/` | Protocol v1.0 wire layer: `discovery.py` (the `/.well-known/paari` document), `envelope.py` (signed, TTL-bounded, replay-resistant message envelope), `messages.py` (typed message constructors), `errors.py` (structured error taxonomy + handler). |
| `providers/` | `base.py` (`PaymentProvider` ABC — one method per capability), `razorpay.py`, `paypal.py`, `razorpay_agentic.py`, `agentic.py` (autonomous boundary; `NotConfiguredAgenticProvider` refuses everything), `reference_autonomous.py`. |
| `control_plane/` | `engine.py` (deterministic SAFR-style disposition engine + risk score), `runtime.py` (DB-backed evaluation used by the payment hub), `router.py` (tenant-scoped admin API), `schemas.py` (strict contracts). |
| `safr/envelope.py` | Versioned SAFR Governance Envelope: action digest, signing payload, receipt persistence. |
| `v36/` | Onboarding + provider governance: `router.py` (register/approve/login/agents/providers/mandates), `provider_policy.py` (requirements enforcement at intent **and** execution), `security.py` (sandbox managed parent keys, identity digesting, parent tokens), `models.py`. |
| `v37/` | Enterprise: `risk.py` (treasury ceilings, per-agent limits, suspension/freeze), `router.py` (treasury, data grants/exports, rails, portability), `models.py`. |
| `federation/` | `contracts.py` (agreement claims), `policy.py` (three-role intersection, policy-digest binding, execution revalidation, context sealing), `router.py`. |
| `receivers/` | `policy.py` (`check_receiver` — fail-closed at intent and execution), `router.py` (institution/beneficiary lifecycle, attestations). |
| `identity_providers/` | Provider-neutral KYC/KYB **contract** only; `runtime.py` (trusted adapter loader + assurance validation), `contracts.py` (`SandboxIdentityVerificationProvider` never returns `VERIFIED`). |

---

## 5. Data model (31 entities, `app/models.py`)

| Domain | Entities |
|---|---|
| Tenancy & routing | `Organization`, `ProviderAccount`, `OrganizationAdminKey` (control_plane) |
| Identity & authority | `ParentAuthority`, `DelegationRecord`, `RevocationRecord`, `Agent`, `Credential`, `AuthNonce`, `RequestProof`, `RateBucket` |
| Payment authority | `UserPaymentMandate`, `PaymentInstrumentBinding`, `MFAChallenge` |
| Payment execution | `PaymentIntent`, `BoundedAuthorization`, `ProviderTransaction` |
| Evidence | `AuditEvent`, `PaymentContextEnvelope`, `ControlPlaneDecision`, `GovernanceEnvelopeReceipt` |
| Institutional governance | `PrincipalIdentity`, `GovernedResource`, `ResourceAccessGrant`, `PolicyBundle` |
| Federation & receiving | `FederationSigner`, `FederationAgreement`, `ReceiverInstitution`, `ReceiverBeneficiary`, `ReceiverAttestation` |
| Portability | `AgentPortabilityImport` |

`v36/models.py` and `v37/models.py` hold **additive** tables (`ParentAccount`, `PolicyAcceptance`,
`ManualApproval`, `AgentRegistration`, `ProviderApplication`, `ProviderRequirements`, `TreasuryPolicy`,
`AgentRiskRule`, `DataSet`, `DataGrant`, `DataExportLog`, `AgentMigration`, `RailSimulation`) so legacy
rows stay intact.

---

## 6. API surface (live introspection: **138 routes**)

| Prefix | Routes | Surface |
|---|---|---|
| `/control/v1` | 35 | Institutional control plane, SAFR envelopes, federation, receivers, portability |
| `/portal/v1` | 25 | Organization Portal + Paari Platform Console APIs |
| `/v1` | 23 | **Stable Protocol v1.0** (recommended for external agents) |
| `/v37/enterprise` | 18 | Treasury, data grants/exports, rails, portability |
| `/v36` | 13 | Onboarding, providers, parent mandates |
| `/payments` | 12 | Legacy payment surface (kept for compatibility) |
| `/parents`, `/agents`, `/auth`, `/health` | 11 | Legacy lifecycle + health/discovery |

Both web UIs call the **same** backend; the separation is presentation, while authentication and
authorisation are enforced server-side.

---

## 7. The end-to-end data flow, mapped to code

**Stage 1 — Parent registration** `app/v36/router.py::parent_register` → `ParentAuthority` (PENDING) +
`ParentAccount` + `PolicyAcceptance`. Identity is stored as an HMAC digest only (`v36/security.digest_identity`).

**Stage 2 — Admin approval** `POST /portal/v1/platform/parents/{id}/review` (`portal_extension.py`) →
status ACTIVE + `ManualApproval` row + `trust_tier=admin_approved`. Tenant provisioning is a
**separate** operation (`/portal/v1/platform/tenants/provision`) that creates `Organization` and binds
the parent; it fails closed if the parent isn't ACTIVE or already has agents.

**Stage 3 — Parent login** `/v36/parents/login` → bearer parent token (30 min) → `/portal/v1/parent/*`
feeds scoped to that parent only.

**Stage 4 — Agent registration** `/v36/agents/register` → parent re-signs the delegation with its
managed key → `DelegationRecord` (replay-protected) → `Agent` + `Credential` → **Agent Card** issued
and signed (`app/routers/agents.py::_build_agent_card`). The card proves *identity*, never authority.

**Stage 5 — Mandate** `/v36/mandates/create` (parent-signed) or `/v1/mandates` (payer-signed via the
admin bootstrap surface). Constraints: per-transaction, daily, hourly, per-merchant, per-category,
currency, `require_review_above`, validity window, Ed25519 signature.

**Stage 6 — Intent** `POST /v1/payments/intent` (agent session + one-time `X-Paari-Proof`).

**Stage 7 — Control plane & SAFR** `app/control_plane/runtime.py::evaluate_payment_control_plane` →
disposition `AUTO_EXECUTE | OBSERVE | ESCALATE | DENY`, persisted as `ControlPlaneDecision` with
evidence.

**Stage 8 — Parent review** `POST /portal/v1/parent/reviews/{intent_id}/decision` — password
re-authentication + reviewer note; approval re-runs `_review_release_preflight` (mandate, receiver,
federation, provider, treasury, fresh control-plane evaluation) before any authorization is minted.
The parent browser never receives the agent's authorization token; the agent retrieves it from
`GET /payments/intents/{id}/authorization` with its own session + proof.

**Stage 9 — Execution & settlement** consume → provider adapter → `ProviderTransaction` → signed
webhook → reconciliation → `PAID` only after corroboration → audit chain.

---

## 8. The payment decision pipeline (ordered checks, `app/routers/payments.py`)

1. Idempotency replay check (bounded change detection for receiver/payment fields).
2. Session resolution (`Authorization: Bearer` preferred; body token is compatibility only) + proof verification (method, exact path, token hash, JTI one-time).
3. Parent active? → 4. v3.6 provider policy (approved provider, requirements, loopback simulator, required context fields) → 5. v3.7 treasury risk (ceiling, daily/hourly, velocity, suspension/freeze) → 6. trust provider → 7. delegation not expired → 8. amount positive → 9. capability → 10. delegated limit → 11. currency → 12. receiver governance → 13. mandate resolution (`NONE`/`LAPSED`/`ACTIVE`) → 14. federation (signed agreement intersection) → 15. **control-plane disposition** → 16. step-up threshold (amount > 0.8 × delegated limit) → 17. velocity (intents in the last minute) → 18. decide `ALLOW` / `REVIEW` / `DENY`; mint `BoundedAuthorization` only on `ALLOW`.

`REVIEW` is **not** an approval: it means "held for a human". `DENY` never mints an authorization.

---

## 9. Provider transaction state machine (`app/transitions.py`)

```
AUTHORIZED ──► PROVIDER_SUBMITTED ──► PROVIDER_AUTHORIZED ──► CAPTURED ──► PAID ──► REFUNDED/REVERSED
     │                   │                        │              │
     └──► FAILED / EXPIRED / CANCELLED / PROVIDER_UNKNOWN ◄────┘
```

* `PAID` is **terminal** except for post-settlement exits.
* `CAPTURED` is deliberately **non-terminal** — it is the state the reconciler promotes.
* `DECLINED` is terminal (it was previously missing from `TERMINAL_STATES`, so declined rows were
  re-scanned forever).
* The **webhook handler cannot mint `PAID`** — only `app.reconcile.confirm_capture()` (an independent
  provider read whose amount/currency match the bounded authorization) can.
* Unknown provider outcomes become `PROVIDER_UNKNOWN` and are reconciled, never guessed.

---

## 10. Evidence: the audit chain

* `record_audit()` appends to a per-`transaction_id` chain; hash v2 covers `prev_hash + kind +
  agent/parent/org/transaction + created_at + detail` (v1 detail-only remains verifiable).
* Appends are serialized by `acquire_chain_lock` (Postgres advisory lock) so two concurrent requests
  sharing a client `transaction_id` cannot fork the chain.
* `verify_chain()` recomputes every link — any tampering returns `False`.
* `app/audit_anchor.py` anchors chain heads to S3 Object Lock (COMPLIANCE) with a future retention
  date, refusing buckets that are not versioned + object-locked, and refusing to overwrite an
  existing anchor that differs.
* `app/proof_bundle.py` exports the 14 stage artifacts with settlement provenance derived from the
  `ProviderTransaction` columns — never from a banner.

---

## 11. Control plane, SAFR, federation, receivers

* **Engine** (`control_plane/engine.py`): hard controls first, then evidence quality, then risk.
  Risk score is a documented, explainable function of *amount vs applicable limit* and *recent
  request count* — never an ML model and never client input. Thresholds live in the org's
  `PolicyBundle` (immutable versions; activation retires the previous one).
* **Runtime** (`control_plane/runtime.py`): resolves facts from Paari's own stores (org/parent
  status, principal mapping, grants, mandate, receiver context) and **denies on any ambiguity**
  (e.g. `PRINCIPAL_MISSING_INACTIVE_OR_AMBIGUOUS`).
* **SAFR envelope** (`safr/envelope.py`): a signed, TTL-bounded envelope bound to the exact intent
  (action digest over amount/currency/merchant/beneficiary/policy digest). Under
  `PAARI_REQUIRE_SAFR_ENVELOPE=1`, a consume is refused until a receipt for that intent exists —
  a fresh authorization is enforced, not assumed.
* **Federation** (`federation/policy.py`): three signed agreements must intersect — `SENDER_ORG`,
  `USER` (must be signed by the same key as the *governing mandate*), `RECEIVER` (must be the
  institution that owns the beneficiary) — and each is bound to the org's live policy digest.
* **Receivers** (`receivers/policy.py`): `check_receiver` is fail-closed at intent **and** execution;
  a blocked or unknown beneficiary denies. Attestations prove *acceptance*, never credit.
* **Identity providers** (`identity_providers/`): a contract only. The sandbox adapter can never
  return `VERIFIED`; assurance levels come from an explicitly trusted adapter, never from a request.

---

## 12. v3.7 enterprise risk (treasury)

`app/v37/risk.py` evaluates per-parent ceilings and per-agent limits, **reserving** exposure
conservatively at intent admission (non-denied intents count, including pending/unknown), so
unresolved transactions stay reserved. Emergency freeze is a parent-scoped state that denies
immediately. `AgentRiskRule` carries per-agent daily limit, hourly request limit and suspension.
`/v37/enterprise/treasury/exposure` and `/signals` are the fleet views used by the console.

---

## 13. Concurrency & cross-dialect semantics (`app/serialization.py`)

Two deliberately different locks:

| Lock | Used by | Transaction contract |
|---|---|---|
| `acquire_gate(s)` | Mandate budget aggregation | Starts a **write** transaction before the reads and holds it to commit (SQLite: `BEGIN IMMEDIATE`; Postgres: `pg_try_advisory_xact_lock` with timeout, fail-closed). |
| `acquire_chain_lock` | Audit chain appends | Advisory lock only — never commits or rolls back, because `record_audit` is flush-only. |

Both are no-ops where the database already serialises writers (SQLite) and fail closed when a gate
cannot be acquired.

---

## 14. Protocol layer (v1.0)

* `/.well-known/paari` publishes the discovery document: endpoints, security bindings, provider
  boundary, conformance links, Paari's public key and the protocol's own rules (private keys never
  sent to Paari; authority comes from signed delegation; authorization is single-use; settlement
  requires provider verification).
* `protocol/envelope.py` defines the signed message envelope (canonical JSON without the signature
  field), with clock-skew and TTL bounds (≤300 s) and replay-resistant message ids.
* `protocol/errors.py` is the structured error taxonomy (`PaariErrorCode` + `PaariHTTPException`),
  and `protocol/messages.py` holds typed constructors for the message set.
* `sdk/paari_agent/` is the reference external-agent client: it imports **nothing** from `app/`, owns
  its private key, and speaks only HTTP + the protocol primitives.

---

## 15. Multi-tenancy

`org_id` is carried on tenant rows (`agents`, `payment_intents`, `provider_transactions`,
`audit_events`, `control_plane_decisions`, receivers, federation, v37 records). Non-default orgs
resolve their own `ProviderAccount` and org-tagged credentials and **never** fall back to another
org's. Control-plane APIs are tenant-scoped through `X-Paari-Control-Key` + `X-Paari-Org`, with the
root admin key reserved for cross-tenant oversight.

---

## 16. External surfaces

| Surface | What it is |
|---|---|
| `sdk/paari_agent/` | Reference external-agent SDK (3 files): `client.py` (discover/register/card/authenticate/payment_intent/consume/reconcile/revoke/status/proof_bundle), `crypto.py` (Ed25519 + optional PQC, canonical JSON, request proofs, envelopes). |
| `llm_agent/` | Client-side LLM harness: `ChatModel` abstraction over an OpenAI-compatible endpoint + `PaariBroker` tool loop; imports nothing from `app/`. |
| `local_demo/`, `live_demo_mode/` | Headless demo apps: a guided policy/lifecycle demo API and a live-demo orchestration API (both require an explicit token; they expose no browser UI). |
| `web/organization/`, `web/internal/` | The two first-party front ends (static HTML + inline JS) for the Organization Portal and the Paari Platform Console. |

---

## 17. Verification harnesses (`scripts/`, 34 files)

| Script | Proves |
|---|---|
| `verify_local_demo.py` | Offline SAFR policy previews + lifecycle demos + (with `--full`) both provider E2Es. |
| `llm_agent_e2e.py` | Strict agent→payment workflow against a self-hosted stub: envelope, bounded order, replay rejection, over-limit denial. |
| `autonomous_payment_e2e.py` | Autonomous authorization protocol against the reference provider. |
| `safr_disposition_coverage.py` | All four dispositions live on real Postgres. |
| `golden_flow_e2e.py` | The strict end-to-end golden flow on Postgres (identity → mandate → envelope → AUTO_EXECUTE → PAID → verified audit) plus two strict gates. |
| `recovery_e2e.py` | Kills the server **and** the provider mid-flight, re-boots, and proves recovery to `PAID` with exactly one provider order. |
| `receiver_partner_sandbox.py` | Independent receiving-institution process issuing signed ACCEPTED/REJECTED only. |
| `stub_razorpay.py` | Provider simulator (orders/payments/capture/webhook signer). |
| `v37_treasury_100_agents_demo.py` | 100 synthetic agents enrolled under one treasury. |
| `ceo_demo_run.py`, `portal_walkthrough_check.py` | (added this session) the 12-scenario live rehearsal and the two-workspace walkthrough. |
| `start_live_demo.py`, `strict_service_gate.py` | Live local stack and the strict service gate. |

---

## 18. Deployment & migrations

* `Dockerfile`: two-stage (builder venv → runtime, non-root `paari`, `python:3.11-slim`), ships
  `app/ alembic/ alembic.ini schemas/ sdk/ web/`.
* `docker-compose.yml`: `app` + `db` (Postgres 16), strict enforcement flags on by default, secrets
  from `.env`; `docker-compose.local.yml`: a separate loopback Postgres for local/test use.
* Migrations: 34 revisions, head `f2a3b4c5d6e7`, covering schema additions for every phase
  (control plane, federation, receivers, PQC columns, provider routing, v3.7 portability).
  `alembic check` must print *No new upgrade operations detected* on **both** engines after any model
  change (no test asserts this — run it by hand).

---

## 19. Test topology

92 test modules / ~12.7k LOC. `tests/conftest.py` is order-critical: it loads `.env.test` at import,
clears ambient `DATABASE_URL`/`PAARI_LIVE`/provider credentials, then pins `PAARI_DATABASE_URL`
**before** `app.database` is imported (the engine freezes at import). It never reads `DATABASE_URL`,
because the client harness drops the public schema on whatever it is given — hence
`assert_disposable_database_url` gating.

---

## 20. Invariants catalogue (the non-negotiables, verified by tests and code)

1. Agent-requested capabilities/limits/currency are never authoritative — only parent-signed values.
2. Mandate resolution is tri-state; `LAPSED` denies in **every** mode.
3. Multiple active mandates **intersect**; the permissive one can never widen a stricter one.
4. Mandate signatures are verified in the authorisation path *and* again at consume.
5. Spending windows are rolling and clamped to the mandate's `valid_from`.
6. `X-Paari-Proof` binds to session hash + method + exact path + issue time + one-time JTI.
7. Authorisation usage is reserved atomically; provider idempotency is provider-specific.
8. A webhook cannot mint `PAID`; reconciliation must corroborate it.
9. `DECLINED` is terminal; unknown outcomes stay `PROVIDER_UNKNOWN`.
10. Provider provenance is a **column**, not a banner; `simulated`/`unknown` environments are never
    presented as provider settlement.
11. Tenants never fall back to another org's provider credentials.
12. Enterprise ceilings count conservatively reserved non-denied intents.
13. Portability never transfers keys, sessions, mandates, grants or bounded authorizations.
14. The sandbox identity provider can never return `VERIFIED`.
15. Unknown `PAARI_MODE` raises; production posture requires Postgres, real endpoints, `rzp_live_*`
    keys, control-plane/receiver/federation/SAFR enforcement, a managed KMS/HSM signer and a trusted
    KYC/KYB adapter.

---

## 21. Observations, risks and gaps (honest)

* **Two front ends, one backend, but the "backend-only" wording in AGENTS.md is stale** — the tree
  ships `web/` and serves it from `app/main.py`.
* **AGENTS.md now states no complete green suite run has been recorded.** In this session a full
  run *was* recorded on this tree: **506 passed, 22 skipped, 0 failed** (log: `test_sqlite_final.log`),
  plus the Postgres CI groups (2 + 13 passed). The statement should be reconciled with that evidence.
* **Deliberate narrow seams** that look like gaps but are intentional: `/v1/mandates` uses the admin
  key as the trusted-user bootstrap boundary; parent-managed signing keys are never exposed to the
  browser (so a USER federation agreement must be signed by a distinct payer keypair); the reference
  release path requires explicit org opt-in (`allow_signed_review_release`).
* **Concentration risk**: `app/routers/payments.py` (103 KB) is the decision hub; it is the file most
  likely to accumulate regressions.
* **Windows-specific friction**: SQLite scratch-file locks, `BEGIN IMMEDIATE` semantics, and file
  handle retention break harnesses that are clean on Linux/macOS.
* **Not verified here**: PQC paths (no `liboqs-python`), managed KMS/HSM signing, real provider rails,
  multi-institution federation, independent security audit, PostgreSQL serializable concurrency under
  production-like load.

---

## 22. Changes made in this session (for traceability)

| Area | Change |
|---|---|
| `docker-compose.yml` | Forward the v3.6/v3.7 secrets (onboarding returned 503 without them) |
| `Dockerfile` | Install `requirements-portal.txt` (Agent-Card QR returned 503 without `qrcode`) |
| `app/routers/agents.py` | Sign the **serialized** Agent Card; carry the tenant's `org_id` on the delegation record |
| `app/schemas.py`, `app/v36/provider_policy.py` | `provider_id` parity on the v1 intent model; the provider gate denies instead of raising HTTP 500 |
| `app/control_plane/{schemas,router}.py` | Expose the per-org opt-in for signed review release (`allow_signed_review_release`, default off) |
| `scripts/llm_agent_e2e.py` | Tolerate a locked scratch file on Windows (harness now exits 0) |
| `tests/test_backend_only_api.py` | Correct a stale assertion that `/console` must not exist |
| `tests/test_v371_portal_regressions.py` | New regression tests: card signature over serialized bytes; `/v1` provider gate denies instead of 500 |
| `web/{internal,organization}/index.html` | Administrator sign-in card layout; audit-evidence overflow containment (`.platform-event` grid floor + wrapping); tenant-management work-in-progress panel with the original markup preserved as a comment |
| `scripts/ceo_demo_run.py`, `scripts/portal_walkthrough_check.py` | The 12-scenario rehearsal and the two-workspace walkthrough; **portable `ROOT`**, valid synthetic GSTIN |
| `V371_LIVE_DEMO_REPORT.md`, `docs/ARCHITECTURE_V3_7_1.md` | Live demo evidence and this architecture analysis |

---

## 23. Core runtime — verified detail

### 23.1 Bootstrap and mount order (`app/main.py`, 499 lines)
Mount order is deterministic (`app/main.py:214-228`): legacy `/parents`, `/agents`, `/auth`, `/payments`
→ `/v1` → `/control/v1` (control plane) → `/control/v1/receivers` → `/v36` → `/v37/enterprise`
→ `/control/v1/federation` → `/portal/v1`. `/portal/v1/*` therefore precedes the static `/portal` document,
and the API wins on that prefix.

`startup_guards()` (`:45-155`) refuses a prod/`PAARI_LIVE=1` boot on 14 ordered grounds: SQLite, non-real
provider endpoints, unknown `PAARI_DEFAULT_PROVIDER`, missing receiver enforcement, short beneficiary secret,
non-autonomous posture, missing control-plane enforcement, missing signed-mandate requirement, short admin
key, non-`rzp_live_` keys, an unmanaged/unhealthy KMS-HSM signer, an untrusted/unhealthy identity provider,
or a missing SAFR-envelope requirement. `load_config()` (`app/config.py:78-123`) independently enforces the
non-sandbox variable set and raises.

`/health` is liveness (always 200, reports posture, enforcement flags, signing backend, identity-provider
status, agentic capability and provider provenance). `/health/ready` is the strict gate: 12 boolean checks
plus production launch blockers; it returns **503** until satisfied — a ready sandbox is explicitly not a
certification.

### 23.2 Security primitives (`app/security.py`, 388 lines)
TTLs: credential 90 d, session 15 min, auth nonce 2 min, **bounded authorization 2 min**, MFA challenge
5 min, request proof 90 s, clock skew 60 s. Token types: `paari_credential`, `paari_session` (carries
`cnf.jkt` = fingerprint of the key that actually authenticated — sender-constrained), and
`paari_bounded_authorization` (binds intent/txn/merchant/amount/currency/mandate, `max_usage=1`).
Request proofs (`X-Paari-Proof`) bind `htm`+`htu` exactly, carry `ath` = SHA-256 of the session token, and
burn their JTI in the `request_proofs` table. The managed-signing path cannot be faked: a plugin may not
self-assert `managed=True`, the key id must match `PAARI_SIGNING_KEY_ID`, and there is **no local
fallback** if the managed path fails.

### 23.3 Agent registration (`app/routers/agents.py`)
Parent ACTIVE → trust provider approves → parent signature over canonical delegation JSON → delegation
unexpired → delegation bound to *this* agent key → delegation not already consumed. The agent's
capabilities/limits/currency are taken **only** from the verified delegation. Revocation accepts either the
admin key or a parent-signed revocation document whose `issued_at` is within 300 s and whose
`revocation_id` is unused (one-time).

### 23.4 Consume path (`app/routers/payments.py:1288-1485`)
Session+proof → `_revalidate_execution` (agent/parent/credential/auth freshness, **mandate signature
re-verified**, limits/merchant/category) → `_strict_execution_evidence` → receiver revalidation →
federation revalidation → v3.6 provider-policy recheck (version-drift ⇒ 403) → v3.7 treasury recheck →
**atomic conditional `UPDATE` reserving usage before the provider is touched** → SAFR receipt burned →
provider dispatch. In every failure mode the authorization stays spent. Autonomous posture has **no**
fallback to human checkout (503 instead).

### 23.5 Audit event kinds observed
`challenge_verified`, `payment_proposed`, `llm_tool_call` (only when attribution was claimed),
`intent_decided`, `authorization_minted`, `authorization_consumed`, `order_submitted`, `provider_submitted`,
`agentic_settlement`, `webhook_applied`, `webhook_rejected_org_mismatch`, `webhook_rejected_value_mismatch`,
`human_review_approved`, `human_review_rejected`, `safr_envelope_consumed_for_execution`,
`control_plane_disposition`, `safr_governance_envelope_validated_only`, `user_mandate_created/revoked/expired`,
`delegation_consumed`, `credential_issued`, `key_rotated`, `parent_portal_review_note`, `reconciled`,
`settlement_confirmed`, `settlement_not_confirmed`, `reconcile_value_mismatch`, `reconcile_dead_letter`.

## 24. Governance layer — verified detail

### 24.1 The control-plane engine is pure (`app/control_plane/engine.py`)
15 hard controls, each with its own reason code, evaluated **before** any risk score; then evidence
quality, then risk. Missing evidence or risk **escalates** — it is never read as zero-risk. Risk is an
explainable function: `amount/limit ≥ 0.75` → +2500 bps, `≥ 0.50` → +1200, `intents_last_minute ≥ 4` →
+6500, `≥ 3` → +2500, `≥ 2` → +1000 (capped 10000). Evidence quality = **min(parent tier, principal
assurance)** — a strong parent cannot launder a weak principal.

### 24.2 The runtime resolves facts, never claims (`app/control_plane/runtime.py`)
Digest = SHA-256 over canonical JSON of {org, agent, mandate, txn, merchant, amount, currency, action,
purpose, category}. It then requires: an ACTIVE `payment_execution` policy; valid thresholds **and**
`require_signed_mandate is True`; ACTIVE org+parent; **exactly one** ACTIVE principal for the mandate's
`user_id`; a live provider instrument binding; an ACTIVE governed resource of a payment-source type with
matching provider/currency; **both** agent and principal grants carrying `payment:execute`; a valid
mandate signature; merchant/category/purpose scope; and an **intersection** applicable limit
`min(agent, mandate, binding)` — never the most permissive.

### 24.3 SAFR envelope
`action_digest` covers only authority/scope fields; the **signing payload** is the whole envelope minus
signature; `envelope_digest` is the receipt digest. TTL ≤ 300 s, strict expiry (skew forgives only a future
`issued_at`). `/validate` returns `VALIDATED_ONLY` — explicitly `policy_evaluated: False`,
`authorization_issued: False`, `execution_permitted: False`. `/process` binds to exactly one persisted
intent + decision; for non-payment actions it returns `DENY_NO_EXECUTOR` so a valid signature can never
produce an ungoverned side effect.

### 24.4 Federation
Signer enrolment covers `SENDER_ORG`/`USER` only — a **RECEIVER** agreement is verified against the
receiving institution's own pinned key. Every agreement is bound to the org's live **policy digest**, so
publishing a new policy version invalidates outstanding agreements by design. The USER agreement must be
signed by the same key as the governing mandate's `user_public_key_pem` — an operator cannot silently
substitute a different effective payer.

### 24.5 Receivers
`check_receiver` requires an ACTIVE beneficiary, an ACTIVE institution with `identity_assurance =
ADMIN_APPROVED`, a merchant↔alias match, a currency match and a within-limit amount — enforced at intent
admission **and** at consume (from the persisted intent, not the caller). Attestations are signed by the
receiver's pinned key, are freshness-bounded (5 min), replay-protected per `(receiver_id, event_id)`, and
are **evidence only** — `settlement_confirmed` is always `False` and no code path mutates the provider
transaction from an attestation.

### 24.6 v3.7 treasury
Per-parent `TreasuryPolicy` (one row, one currency, daily ceiling, `FROZEN` state, version bumped on every
mutation) and per-agent `AgentRiskRule` (daily limit, suspension, hourly request limit). Exposure counts
**non-denied intents** as reserved (conservative). Emergency freeze blocks intents, execution and data
exports, and only a root admin can unfreeze. Signals are explicitly advisory heuristics, never proof.

### 24.7 Portability — two competing models
* Control plane: `AgentPortabilityImport` — destination needs a non-synthetic, attested
  `substantial`/`high` principal **and** a destination-local grant; the issuer trust store must be pinned
  out of band (`PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON`), otherwise the route is 503.
* v3.7: `AgentMigration` — requires `confirm_identity_only`, a fresh destination agent **created after**
  staging with a **different** key and completed v3.6 onboarding; no assurance floor on the principal.
* Both record `authority_transferred: False` and the `never_exported` list (private keys, session tokens,
  credential JWTs, user mandates, resource grants, provider credentials/tokens, bounded authorizations,
  tenant private data).

## 25. Issue register (found during this analysis)

Severity is my judgement; "verified" means I reproduced it, the rest is from static reading with file:line anchors.

### Verified by execution
| # | Issue | Evidence | Impact |
|---|---|---|---|
| V1 | `app/routers/payments.py` uses `Sequence[...]` in `_record_intent` and `_deny` annotations but never imports `Sequence` | `typing.get_type_hints` → `NameError: name 'Sequence' is not defined` | Latent: any `get_type_hints()`/validator/static checker on those functions breaks. Harmless today only because `from __future__ import annotations` defers evaluation. **One-line fix.** |
| V2 | `crypto_utils.verify_signature` parses the Ed25519 PEM **outside** its try block | `verify_signature("not-a-pem", …)` → raises `ValueError` instead of returning `False` | A corrupted stored public key turns a governed DENY into an unhandled 500 in mandate-signature paths. Money-safe (blocks), but wrong shape. |
| V3 | The SAFR envelope gate is unreachable unless control-plane enforcement is on | `payments.py:917-920` returns `None` **before** the envelope-receipt check at `:996-1016` | `PAARI_REQUIRE_SAFR_ENVELOPE=1` alone is inert; prod is safe only because prod also forces `PAARI_CONTROL_PLANE_ENFORCEMENT=1`. A deployment enabling only the envelope flag gets **no** SAFR gate. |
| V4 | Delegation records were created without the tenant's `org_id` (column default `default`) | fixed this session in `app/routers/agents.py`; the SAFR ingress query is org-scoped | SAFR envelope ingress 409'd for every v3.6-onboarded agent in a provisioned tenant. |

### Design inconsistencies worth fixing (static reading)
| # | Issue | Anchor |
|---|---|---|
| D1 | `payment.create` is an escape hatch in the legacy capability check but **not** in the control plane's `action_authorized` → the same request is allowed by one layer and denied (`ACTION_NOT_AUTHORIZED`) by the other | `payments.py:384` vs `control_plane/runtime.py:170` |
| D2 | `ControlPlaneDecision` is documented as immutable per intent, but review release mutates `disposition` to `AUTO_EXECUTE` and appends reason codes in place | `models.py:718` vs `payments.py:878-880` |
| D3 | Two "daily" semantics coexist: mandate budgets roll (clamped to `valid_from`), the enterprise treasury ceiling resets at UTC midnight | `mandates.py:136-144` vs `v37/risk.py:63` |
| D4 | `allowed_purpose_codes` cannot be expressed through the API (metadata values are scalar), so the purpose allowlist is unusable or degenerates into a substring match | `control_plane/runtime.py:146-147` vs `control_plane/schemas.py:49` |
| D5 | Principal uniqueness differs between schema (org+provider+subject) and runtime (org+subject, denies if >1) → legitimate multi-IdP tenants hard-deny | `models.py:619-621` vs `runtime.py:84-89` |
| D6 | Jurisdiction for identity verification is per-request (default `AE`) but re-validation compares to `PAARI_HOME_JURISDICTION` → every prod refresh fails unless home jurisdiction is `AE` | `control_plane/router.py:232-237` vs `identity_providers/runtime.py:160` |
| D7 | `/governance/envelopes/process` cannot be retried with the same envelope (unique receipt ⇒ 409 + rollback) | `control_plane/router.py:649-663`, `:724` |
| D8 | The three "active grant with `payment:execute`" predicates are duplicated in three modules with different shapes; `_tenant` / `_trusted_portability_issuers` (private) are imported across modules and `_tenant` commits mid-request | `runtime.py:40-46`, `control_plane/router.py:593-598`, `payments.py:967-973` |
| D9 | Pre-control-plane denials persist a `ControlPlaneDecision` with `policy_version="missing"` and only a fallback reason → the institutional record loses which control failed | `control_plane/runtime.py:191-203` |
| D10 | `fleet_risk_summary` hardcodes risk thresholds (6000/2500) instead of the tenant's configurable policy thresholds | `control_plane/router.py:905-908` |
| D11 | Proof bundle never reads `ControlPlaneDecision` → the institutional disposition, risk score, evidence score and transaction digest are absent from the exported proof | `proof_bundle.py:328-339` |
| D12 | `v37` utilization is capped at 100 % while `remaining` floors at 0 → the over-cap amount is invisible in the fleet view | `v37/router.py:187-188` |
| D13 | A blocked beneficiary has no un-block path, and re-registering collides with the unique fingerprint constraint | `receivers/router.py:182`, `models.py:845` |
| D14 | v3.6 provider policy reads **process env** (`RAZORPAY_API_BASE`) while routing is per-tenant → a PayPal tenant is evaluated against a Razorpay loopback rule | `v36/provider_policy.py:25-30` |
| D15 | Two portability staging models with divergent destination assurance baselines | `models.py:771-798` vs `v37/models.py:78-91` |
| D16 | Dead duplicate `_OQS_MECHANISM_NAMES` definition; `asyncio.run()` fallback inside a sync webhook handler; `Sequence` annotation gap (V1) | `crypto_utils.py:53-65`, `payments.py:1633-1642` |
| D17 | `ControlFacts.consent_current` duplicates `mandate_active` under two names, so one fact is checked twice | `runtime.py:164`, `:176` |
| D18 | Currency comparison is case-sensitive in the control plane but uppercased elsewhere; the request model does not constrain currency | `runtime.py:173` vs `payments.py:1053` |

### Documentation drift
* `AGENTS.md` still says the tree is "backend-only" although `web/` is served from `app/main.py`.
* `AGENTS.md` states no complete green suite run exists on this tree; **this session recorded one**
  (506 passed / 22 skipped / 0 failed, `test_sqlite_final.log`) plus the Postgres CI groups (2 + 13).
* `docs/` holds 79 files, most of them dated release/verification reports; only `PROTOCOL.md`,
  `SECURITY.md`, `CONFORMANCE.md`, `PROVIDER_ADAPTERS.md`, `V36_API_GUIDE.md`, `V37_API_GUIDE.md` and
  `ORGANIZATION_PORTAL_PARENT_REVIEW.md` describe current behaviour.

## 26. Surfaces, harnesses and packaging (deep)

### 26.1 The SDK — `sdk/paari_agent/` (3 files, 351 LOC)
Imports only `httpx`, `PyJWT`, `cryptography` — **never `app.*`**, enforced by
`tests/test_sdk.py::test_sdk_has_no_server_app_dependency`. `client.py` exposes `discover`, `register`,
`get_card`, `authenticate`, `get_active_mandate`, `payment_intent`, `consume`, `reconcile`,
`revoke_authorization`, `get_payment_status`, `proof_bundle`; it verifies the returned Agent Card
signature locally before trusting it. `crypto.py` provides canonical JSON, Ed25519/PQC keygen, fingerprint,
`sign_delegation`, `build_envelope` (TTL clamped 1–300 s) and `build_request_proof` (claims `typ/sub/htm/
htu/iat/jti/ath`; `ath` = SHA-256 of the session token). The agent owns its private key; the server owns
the card signature, the credential, the session, and every governance decision.

### 26.2 The LLM harness — `llm_agent/`
`broker.py` is the key-custody boundary: the model only ever sees `execute(name, arguments)`; the
`PaariAgentClient` (and the private key behind `X-Paari-Proof`) is unreachable by anything the model
controls. `tools.py` validates **shape only** (unknown tool/argument, missing required, wrong type —
`bool` rejected for `int`), and caps are enforced by the broker, not the schema.
`loop.py::_authoritative_final_text` prevents model prose from outranking Paari's state: a claimed `PAID`
requires verified proof, terminal state, webhook verification, `settlement_source == "provider"` and a
`test|live` provider environment; otherwise the text is replaced by a deterministic status. `llm_agent`
imports nothing from `app/`.

### 26.3 Demo surfaces are separate applications
Neither `local_demo/` nor `live_demo_mode/` is mounted into `app.main`. `local_demo/portal.py` is a
loopback-only, token-gated API (`local_demo/core.py` runs the **real** engine and the **real**
`transition_txn` on an in-memory `_Txn` stand-in, and `EvidenceStore` is a SQLite hash-chained log with
UPDATE/DELETE blocked by triggers). `live_demo_mode/app.py` drives the live backend over HTTP with the
agent key in process RAM; `agent_worker.py` submits the real SDK-signed request from a **separate
process** reading its parameters from stdin.

### 26.4 Harnesses — 35 scripts, two families
*Release/acceptance gates*: `accept_v32/v33/v33_pipeline`, `regulatory_mvp_gate_v352` (fail-closed
NO-GO on missing infra/skips/xfails), `strict_service_gate`, `gate_a_service_probe`,
`dashboard_operator` (reads the persistent DB independently after driving the portal).
*Protocol/E2E*: `llm_agent_e2e`, `autonomous_payment_e2e`, `foreign_agent_proof` (black-box: importing
`app.*` aborts the run), `golden_flow_e2e`, `safr_disposition_coverage`, `recovery_e2e`,
`pg_e2e_workflow`, `refund_chargeback_e2e`, `live_e2e_test`, `webhook_listener` (mounts only the
webhook route; refuses to start without the webhook secret), plus provider/receiver simulators and ops
utilities.

### 26.5 Migrations — 33 revisions, single head `f2a3b4c5d6e7`
Baseline → provider provenance columns → audit `hash_version` → the **data-only** Phase-9 vocabulary
rewrite → institutional control plane → SAFR envelope + delegation portability → receiver tables →
federation tables → PQC column resizes → v3.6 onboarding → v3.7 enterprise → multi-provider routing →
head. `alembic/env.py` uses `render_as_batch=True` (SQLite cannot ALTER) and one narrow `compare_type`
exemption so a wide-enough `Enum` over `VARCHAR` is not SQLite drift. Migrations 29/30/33 build tables
from `Base.metadata` rather than hand-written DDL, so they must be regenerated if the models change.

### 26.6 Tests — 89 modules
`tests/conftest.py` is order-critical by design (see §19). 13 PQC skips, 8 Postgres-only skips, 1 Windows
POSIX skip. CI has two jobs (`test`, `postgres-migration`) and **no** linter, formatter, typechecker or
pre-commit anywhere in the tree.

### 26.7 Packaging
The Docker image ships `app/ alembic/ alembic.ini schemas/ sdk/ web/ README.md` — **not** `tests/`,
`scripts/`, `docs/`, `llm_agent/`, `local_demo/`, `live_demo_mode/`. The Compose deployment therefore
cannot run the demo services, E2E harnesses or the provider simulator; those are host-side tools.
`docker-compose.minio.yml` provides a local S3 (LocalStack) for the WORM anchor job.

## 27. Additional issue register (surfaces / harnesses / docs)

| # | Issue | Anchor | Note |
|---|---|---|---|
| S1 | **Hard-coded absolute Windows paths** in the two harnesses added this session (`ceo_demo_run.py`, `portal_walkthrough_check.py`) | — | **Fixed in this session** (`ROOT = Path(__file__).resolve().parents[1]`); re-verified 20/20. Every other script derives ROOT the same way. |
| S2 | The two web documents ship **each other's entire JavaScript**: 364 of 378 script lines are byte-identical and each file contains the other workspace's full function set; the org document keeps `loadDataGovernance`/`loadRailLab` with no DOM mounts (removed pages). `tests/test_separate_websites.py` checks **DOM IDs only**, so it cannot see the duplication | `web/{organization,internal}/index.html` | ~50 KB dead JS per file shipped into the image; shared code must be edited twice by hand; a stray call would throw on a null element. |
| S3 | The canonical user-mandate payload is re-implemented **six times** outside `app/`. Only `foreign_agent_proof.py` is pinned to the server form by a byte-equality test (`tests/test_proof_scripts.py`); the other five drift silently | `scripts/{foreign_agent_proof,golden_flow_e2e,autonomous_payment_e2e,pg_e2e_workflow,ceo_demo_run}.py`, `live_demo_mode/app.py` | `live_demo_mode/app.py` even hard-codes `org_id='default'`. |
| S4 | Docs reference files that do not exist: `docs/PRODUCT_PORTAL_INTEGRATION.md` names `web/paari_product_portal.html`, `app/portal_page.py`, `MAIN_PY_INTEGRATION.txt`; `docs/PAYMENT_TRACKER_FLOW.md` names `INTEGRATION_GUIDE.md`; `docker-compose.local.yml` names the retired `scripts/start_local_demo.py` | — | Stale v3.5.2-era integration text. |
| S5 | `BACKEND_TEST_RESULTS.md` asserts *"No `/console` route is registered"* — false since v3.7.1 (`app/main.py:295`); it also reports the Alembic head as `b9c0d1e2f3a4b` (now `f2a3b4c5d6e7`) | — | Documentation contradicts the code. |
| S6 | `live_demo_mode` does **not** enforce an inbound loopback host check (the comment says it was relaxed for shared-tunnel testing) while `local_demo` does | `live_demo_mode/app.py:199-205` vs `local_demo/portal.py:157-164` | Still requires a same-origin `Origin` + `X-Paari-Demo-Token`, so not open — but the asymmetry is real and is relevant for tunnel exposure. |
| S7 | `.env.test` — the suite's declared baseline — is **absent** from this tree; `conftest` tolerates it and falls back to inline defaults | `tests/conftest.py:30-48` | `.gitignore` whitelists it (`!.env.test`). |
| S8 | `local_demo/core.py` defines a miniature parallel model (`_Txn`) so the real `transition_txn` can run without a DB | `local_demo/core.py:126-132` | Deliberate and well-commented, but it is a second model in the tree. |
| S9 | The Docker image cannot run the demo services, E2E harnesses or the provider simulator (scripts/llm/local_demo/live_demo are not shipped) | `Dockerfile:35-41`, `.dockerignore` | Intentional ("do not ship pytest"), but the image is not self-verifying. |
| S10 | `API_ENDPOINTS.md` is titled *"v3.5.2 backend API route inventory"* while listing 87 current routes (the live surface is 138) | `API_ENDPOINTS.md` | Stale version label; regenerate from the app. |
| S11 | Stale local artefacts sit in the working tree (`.phase5_test.db`, `.phase5_isolation_child.db`, `_tmp_autonomous_e2e.db`, 190 KB `cloudflared.log`, `.agnes/recovery_stub_state.json`) | — | Gitignored, but noise for anyone reading the tree; `evidence/` (16 run dirs) is **not** gitignored. |
| S12 | The legacy combined portal `paari_product_portal.html` (186 KB) remains at the repo root as a development reference | `LEGACY_PORTAL_NOTE.md` | The Dockerfile correctly does not ship it; a test asserts that. |

* `docker-compose.yml` — forward the v3.6/v3.7 secrets (onboarding 503'd without them).
* `Dockerfile` — install `requirements-portal.txt` (Agent-Card QR 503'd without `qrcode`).
* `app/routers/agents.py` — sign the **serialized** Agent Card; carry the tenant's `org_id` on the
  delegation record.
* `app/schemas.py` + `app/v36/provider_policy.py` — `provider_id` parity on the v1 intent model; the
  provider gate now denies instead of raising HTTP 500.
* `app/control_plane/{schemas,router}.py` — expose the org opt-in for signed review release.
* `scripts/llm_agent_e2e.py` — tolerate a locked scratch file on Windows.
* `tests/test_backend_only_api.py` — corrected a stale assertion that `/console` must not exist.
* `tests/test_v371_portal_regressions.py` — regression tests for both card-signature and `/v1` defects.
* `web/{internal,organization}/index.html` — sign-in card layout, audit-evidence overflow containment,
  tenant-management work-in-progress panel (original markup preserved as a comment).
* `scripts/ceo_demo_run.py`, `scripts/portal_walkthrough_check.py`, `V371_LIVE_DEMO_REPORT.md`.
