# Paari — Technical Blueprint Report

**Version audited:** 3.7.1 (stability-fix tree) · **Audit date:** 2026-11-01
**Scope:** `D:\Visual code projects\Paari_v3_7_1_Stability_Fixes` — backend-only service, SDK, LLM agent harness, migrations, scripts, and deployment assets.
**Document status:** Source of Truth reference. Where this document and the code disagree, the code wins; update this document in the same change.

> **Coverage note (honest boundary):** this blueprint was produced by a full read of the core
> domain modules (`main`, `models`, `mandates`, `transitions`, `reconcile`, `reconcile_worker`,
> `security`, `config`, `database`, `serialization`, `audit`, `crypto_utils`, `governance`,
> `providers/*`, `control_plane/engine`, `safr/envelope`, `routers/v1`, `routers/payments`,
> `provider_accounts`, `sdk/paari_agent`, `llm_agent` entry points, Docker/Compose,
> requirements, env templates, and all 32 Alembic revision files). The v36/v37 routers,
> federation policy internals, receivers attestation flow, portability staging internals and
> the `scripts/` E2E harnesses were audited at the interface level, not line-by-line; those areas
> are flagged in §8 (Technical Debt Register) as "interface-audited".

---

## 1. Executive Summary

### 1.1 What Paari is

Paari is a **trust and governance layer that sits between AI agents and payment
infrastructure**. An AI agent never holds payment credentials and never "authorizes a
payment" on its own. Instead, the agent *proposes* a payment; Paari *validates its
authority* through a chain of independently-keyed, signed, bounded, and auditable
decisions, then executes it against a payment provider (Razorpay or PayPal) under strict
bounds.

The core business value, in one sentence: **an agent's ability to move money is always the
intersection of (a) what a parent authority delegated to it, (b) what a user consented via a
signed payment mandate, and (c) what institutional policy allows — and every step of that
decision is a durable, tamper-evident, per-transaction evidence artifact.**

### 1.2 The trust chain (the system in 30 seconds)

```
Parent Authority (Ed25519 key pair, never hands Paari its private key)
        | signs
        v
Delegation Document (capabilities + payment cap + expiry)
        | consumed exactly once
        v
Agent (its own key pair; registers public key + delegation)
        | is granted
        v
Credential JWT (90d)  ->  Session Token (15m) + DPoP-style request proofs (90s)
        | proposes
        v
Payment Intent -> Governance decision (ALLOW / REVIEW / DENY)
        | ALLOW mints
        v
Bounded Authorization (2-minute, single-use, signed JWT)
        | consume drives
        v
Provider execution (order create -> authorize -> capture)
        | settled only by
        v
Signature-verified webhook + independent provider read (reconciliation)
        | every step appended to
        v
Hash-chained, per-transaction Audit Chain
```

### 1.3 Technology stack overview

| Layer | Technology | Version (pinned) |
|---|---|---|
| Language | Python | 3.11 (3.13 compatible per focused runs) |
| Web framework | FastAPI + Starlette | 0.115.0 |
| ASGI server | Uvicorn (standard) | 0.30.6 |
| ORM | SQLAlchemy 2.0 (typed `Mapped` models) | 2.0.35 |
| Database | SQLite (dev) / PostgreSQL (prod), via Alembic | Alembic 1.13.3, psycopg (PG driver) |
| Validation | Pydantic | 2.9.2 |
| Tokens / signatures | PyJWT (Ed25519 "EdDSA"), `cryptography` | PyJWT 2.9.0, cryptography 43.0.1 |
| Post-quantum | Optional `liboqs-python` (ML-DSA-65, SLH-DSA) | not installed in default env; tests skip cleanly |
| HTTP client (outbound) | httpx | 0.27.2 |
| Testing | pytest + pytest-asyncio + respx | 8.3.3 / 0.24.0 / 0.21.1 |
| Packaging | Docker (multi-stage, non-root `paari` user), docker-compose (app + postgres:16-alpine) | — |

### 1.4 Positioning and explicit non-claims

Paari is deliberately honest about what it is **not**:

- No frontend, no real-money rail integration in the shipped tree.
- No certified KYC/KYB: the bundled identity-provider sandbox **never** returns
  `VERIFIED`; production launch is fail-closed until a trusted external adapter is wired.
- No managed KMS/HSM adapter is bundled; production signing is blocked without one.
- `PAARI_HOME_JURISDICTION=AE` is metadata only; it confers no licensing or rail status.
- A governance ALLOW, a bounded authorization, and a provider order are three *different*
  facts, all distinct from settlement. `PAID` requires a provider-confirmed capture.

---

## 2. Architectural Overview

### 2.1 System design patterns

| Pattern | Where | Why |
|---|---|---|
| **Layered composition root** | `app/main.py` mounts all routers; domain modules import-only, no side effects at import | Importing the app never touches the database (tables exist only after `alembic upgrade head`) |
| **State machine as single source of truth** | `app/transitions.py` `TRANSITION_TABLE`; every state write goes through `transition_txn()` | Illegal jumps (e.g. `AUTHORIZED -> PAID`) raise `IllegalTransitionError` instead of silently corrupting execution state |
| **Fail-closed policy by default** | `config.mandate_policy()`, `main.startup_guards()`, `providers/agentic.NotConfiguredAgenticProvider`, identity-provider gate | Unknown posture values *raise* instead of degrading to the permissive mode; missing capability refuses the operation instead of simulating it |
| **Dependency-injection seams** | `providers.base.get_provider()`, `provider_accounts.get_provider_for_org()`, `providers.agentic.get_agentic_provider(org_id)` | Routers never import a concrete adapter; per-tenant provider selection is data (`ProviderAccount.provider_name`), not code |
| **Pure-function policy engine** | `control_plane/engine.evaluate(ControlFacts, PolicyThresholds) -> Evaluation` | Deterministic, side-effect-free, unit-testable in isolation; HTTP/DB callers feed it authoritative facts only |
| **Append-only hash-chained log** | `app/audit.py` + `AuditEvent` table | Every security-relevant fact per `transaction_id` is chained (`prev_hash`/`event_hash`); tampering breaks `verify_chain()` |
| **Sender-constrained tokens (DPoP-style)** | `security.verify_request_proof` + `RequestProof` JTI table | Session tokens never ride in URLs; protected v1 requests carry a `X-Paari-Proof` JWT bound to session-hash, method, path, issue time, and a one-time JTI burned in the DB |
| **Boot-time guard rails** | `main.lifespan -> startup_guards()` | A deployment that would produce *silent* false evidence (simulator on prod DB, SQLite in prod, missing signed-mandate posture) refuses to start |
| **Two-tier health** | `/health` (liveness) vs `/health/ready` (readiness, HTTP 503 while any governance gate or credential is missing) | Load balancers must not admit payment traffic until readiness passes; liveness is not a readiness claim |

### 2.2 Directory structure

```
Paari_v3_7_1_Stability_Fixes/
├── app/                        # the service
│   ├── main.py                 # composition root, boot guards, /health, /health/ready, ASGI security-header middleware
│   ├── config.py               # PaariEnv + mandate_policy(): the ONE definition of governance posture
│   ├── database.py             # engine, UTCDateTime, resolve_database_url, disposable-DB guard, SQLite FK pragma
│   ├── models.py               # ~30 ORM tables (identity, governance, settlement, audit, control plane, receivers, federation)
│   ├── schemas.py              # Pydantic request/response models
│   ├── security.py             # Ed25519/PQC signing backends, credential/session/authorization JWTs, DPoP proofs, admin auth
│   ├── crypto_utils.py         # Ed25519 + optional ML-DSA/SLH-DSA dispatch, canonical JSON, key fingerprints
│   ├── mandate_signing.py      # user-mandate Ed25519 signature verification (authorization path)
│   ├── mandates.py             # tri-state mandate resolution, intersecting budgets, rolling windows, serialization gates
│   ├── transitions.py          # ProviderTransaction state machine (sole transition authority)
│   ├── reconcile.py            # corroborating provider reads; confirm_capture; missed-webhook recovery
│   ├── reconcile_worker.py     # background daemon thread; dead-letter + alert sink
│   ├── audit.py                # hash-chained audit appends/verification, per-transaction chain lock
│   ├── governance.py           # PolicyResult / GovernanceResult dataclasses
│   ├── ratelimit.py            # table-backed shared rate counters (RateBucket)
│   ├── provider_accounts.py    # strict per-tenant provider credential routing (env __TAG suffixes)
│   ├── trust.py                # trust-tier checks
│   ├── portability.py          # agent portability staging (never transfers keys/tokens/mandates)
│   ├── signing_backends.py     # LocalPemSigningBackend + managed KMS/HSM adapter interface
│   ├── pqc_signing_backends.py # post-quantum signing backend wiring
│   ├── proof_bundle.py         # per-transaction evidence package (discovery, identity, execution, provenance, audit)
│   ├── control_plane/          # principal/resource/policy/grant governance engine + /control/v1 router
│   ├── safr/                   # signed versioned Governance Envelope (validation-only receipts)
│   ├── protocol/               # envelope sign/verify, discovery document, structured errors
│   ├── providers/              # PaymentProvider ABC; razorpay.py; paypal.py; agentic.py; reference_autonomous.py; razorpay_agentic.py
│   ├── identity_providers/     # provider-neutral KYC/KYB contract + runtime (sandbox never VERIFIED)
│   ├── receivers/              # v3.4 receiving-institution control plane (beneficiaries, signed attestations)
│   ├── federation/             # v3.5 signed institutional agreements + federation signers
│   ├── v36/                    # onboarding, provider policy, consent-scoped data portability
│   ├── v37/                    # enterprise treasury fleet controls, data encryption, parent lockout
│   └── routers/                # HTTP surface: agents, auth, parents, payments (legacy + webhooks), v1 (stable protocol)
├── sdk/paari_agent/            # dependency-light external agent client (imports NO server modules; agent owns its private key)
├── llm_agent/                  # brokered LLM tool-calling harness (model, loop, broker, tools) + env resolution
├── live_demo_mode/             # operator-facing demo app + agent worker
├── local_demo/                 # three-service strict local demo (simulator + enforcing API + portal)
├── alembic/versions/           # 32 revisions; head = f1a2b3c4d5e6
├── schemas/                    # 19 JSON schemas (agent card, delegation, bounded authorization, envelope, proof bundle, ...)
├── scripts/                    # E2E harnesses (autonomous, LLM, live, strict gates, token minting, stub provider)
├── tests/                      # ~90 test modules; isolated disposable-DB fixture (conftest.py)
├── docs/                       # ~70 phase/release/security/verification documents
├── evidence/                   # timestamped E2E run manifests (hashes, not secrets)
├── docker-compose.yml / .local # app + postgres:16-alpine; loopback-only port; non-root; named volumes
└── .env.example / .env.test    # env templates (placeholders only; .env.test is the suite's versioned posture baseline)
```

### 2.3 Data flow: a payment attempt end to end

```
 [Agent SDK]                    [Paari API]                          [Domain]                       [Provider]
      |   POST /v1/agents/register (signed envelope)
      |-------------------------------------------------------------->|  verify envelope signature
      |                                                               |  verify parent delegation sig
      |                                                               |  anti-replay (DelegationRecord)
      |<--------------------------------------------------------------|  {agent_card, credential_jwt}
      |
      |   POST /v1/auth/challenge -> sign nonce -> /v1/auth/verify
      |-------------------------------------------------------------->|  credential + nonce signature
      |<--------------------------------------------------------------|  {session_token} (15m JWT)
      |
      |   POST /v1/payments/intent   (Bearer session + X-Paari-Proof)
      |-------------------------------------------------------------->|  _authenticate: JWT, agent ACTIVE,
      |                                                               |  credential live, parent ACTIVE,
      |                                                               |  delegation unexpired, proof JTI burn
      |                                                               |--- mandates.evaluate_mandate
      |                                                               |     (tri-state, intersect, rolling
      |                                                               |      windows, advisory-locked)
      |                                                               |--- control_plane.evaluate
      |                                                               |     (hard controls -> 4 dispositions)
      |                                                               |--- velocity gate (5 intents/min)
      |                                                               |    REVIEW parked w/ 5m TTL + MFA
      |                                                               |--- audit append (intent_decided)
      |<--------------------------------------------------------------|  {decision: ALLOW, authorization_id, token}
      |
      |   POST /v1/payments/authorizations/{id}/consume
      |-------------------------------------------------------------->|  revalidate execution (live trust)
      |                                                               |  single-use burn (conditional UPDATE)
      |                                                               |  provider.create_payment(authorization_id)
      |                                                               |--------------------------------------------------> create order (idempotent
      |                                                               |<-------------------------------------------------  by authorization_id)
      |                                                               |  txn -> PROVIDER_SUBMITTED -> ...
      |                                                               |  webhook (HMAC-verified) -> CAPTURED
      |                                                               |  confirm_capture reads provider:
      |                                                               |  status captured + exact amount/
      |                                                               |  currency match -> PAID
      |<--------------------------------------------------------------|  settlement result + proof bundle
```

---

## 3. Core Logic Analysis

### 3.1 Mandate evaluation (`app/mandates.py`) — the heart of user consent

Three invariants, each born from a concrete historical bug:

1. **`LAPSED ≠ NONE` (tri-state).** `resolve_state()` returns `MandateState.{NONE, LAPSED, ACTIVE}`.
   An agent whose mandate *expired* used to resolve to `None`, indistinguishable from "never had
   one" — so a lapsed spending cap silently became *no cap* and the payment was ALLOWed with
   `reasons: ["all checks passed"]`. Now `LAPSED` fails closed **in every posture mode**.
2. **TIGHTEST WINS (intersection).** Ordering used to be `expires_at DESC`, which selected the
   *longest-lived* mandate regardless of limits, letting a broad long mandate override a narrow
   short one. Now **all** active mandates are evaluated and the effective policy is their
   intersection; any denial denies.
3. **ROLLING WINDOWS.** Budgets used to reset at calendar boundaries, so a payment straddling
   midnight could spend a full daily budget twice in seconds. Windows are rolling 1h/24h,
   clamped to the mandate's own `valid_from` (a mandate is never charged for spend that
   predates it).

Other deliberate choices:

- **Denials never consume budget; ALLOW/REVIEW always do.** A fast agent cannot race a hundred
  pending approvals between governance and settlement.
- **Merchant/category dimensions are case-normalized** in both allowlists *and* spend
  aggregation — a case-sensitive aggregation would let `AMAZON` and `amazon` each start a fresh
  per-merchant budget while both passing the same allowlist entry.
- **The Ed25519 mandate signature is enforced on the authorization path, not just at creation**
  (`check_mandate_signature` is called from `evaluate_mandate` and re-verified at consume). A
  valid signature is never treated as a liveness signal.
- **Concurrent evaluation is serialized** with `acquire_all_mandate_gates()` — Postgres
  `pg_try_advisory_xact_lock` (sha256-derived signed-bigint keys), SQLite `BEGIN IMMEDIATE` —
  held from *before* the aggregation reads until the spend record commits, so a second evaluator
  necessarily observes the first. Deadlock-free via sorted acquisition; any failure denies.

**Analogy:** the mandate is a card with a fixed daily limit; the tri-state is the difference
between "no card on file" (NONE), "card expired" (LAPSED — you must be refused even if you'd
like to pay), and "card valid" (ACTIVE); the intersection rule means if you present two cards,
the bank applies the *stricter* of their limits.

### 3.2 Settlement state machine (`app/transitions.py`)

Phase-9 vocabulary (observed on real wire data — a live test-mode settlement delivered
`payment.authorized` and `payment.captured` as two separately-signed events):

```
AUTHORIZED -> PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID
```

Key structural decisions:

- **The webhook handler can never mint `PAID`.** A signed webhook is provider *attestation of an
  event*; `PAID` is Paari's own terminal confirmation requiring an independent provider read
  (`reconcile.confirm_capture`) whose amount and currency equal the bounded authorization. If
  the read fails, the row stays `CAPTURED` (non-terminal, so the reconciler keeps working on it)
  — never optimistically promoted.
- **`PROVIDER_SUBMITTED -> PAID` exists solely for reconciliation** of a missed webhook.
- **`DECLINED` is in `TERMINAL_STATES`.** Leaving a dead-end state out of that set makes the
  reconciler's `state not in TERMINAL_STATES` filter re-select it forever — an unbounded work
  queue of rows that can never resolve.
- **Unknown provider outcomes become `PROVIDER_UNKNOWN`** and require reconciliation; never a guess.
- `PAYMENT_PENDING` is retired (migration `c3d4e5f6a7b8` rewrote rows) but keeps legal exits so
  pre-migration rows and replays still move.

### 3.3 Reconciliation (`app/reconcile.py`, `app/reconcile_worker.py`)

- `reconcile_one()`: fetches the provider's view (by payment id, else order, else receipt lookup
  for `PROVIDER_UNKNOWN` rows) and advances the row only via `transition_txn`, auditing
  every move including `reconcile_value_mismatch` when the provider's amount/currency disagrees
  with the authorization.
- The worker is a **daemon thread** started in the app lifespan: ticks every
  `PAARI_RECONCILE_INTERVAL` (default 60s), dead-letters a row to `PROVIDER_UNKNOWN` after
  `PAARI_RECONCILE_DEAD_LETTER_AFTER` (default 5) failed attempts, and pushes alerts to
  `PAARI_RECONCILE_ALERT_WEBHOOK`.
- A past near-miss the code now guards against: the worker's `start()` used to be called with no
  argument and quietly run with `engine=None` — "started, logged, inert". It now defaults to the
  app's resolved `DATABASE_URL`.

### 3.4 Identity, tokens and request proofs (`app/security.py`)

- **Key discipline:** Paari signs protocol artifacts (agent cards, credentials, sessions,
  bounded authorizations) with an Ed25519 key from a pluggable `SigningBackend`
  (`local_pem` for sandbox; managed KMS/HSM interface for production, currently unmet — launch
  blocked fail-closed). Production **refuses to auto-generate** a signing key at boot.
- **Token family and TTLs:** credential 90d · session 15m · auth challenge 2m ·
  bounded authorization 2m · MFA challenge 5m · request proof 90s.
- **DPoP-style proofs:** protected v1 requests carry `X-Paari-Proof`, a sender-key-signed JWT
  binding the session-token SHA-256 (`ath`), exact method+path (`htm`/`htu`), issue time, and a
  one-time `jti` burned into `request_proofs`. Replays and cross-agent reuse fail.
- **Key rotation with grace:** `Agent.old_public_key_pem` + `key_sunset_at` (24h) keep in-flight
  clients working; after sunset, session key binding fails closed.
- **PQC path:** ML-DSA-65 / SLH-DSA-128S tokens use IETF JOSE `alg` identifiers; verification is
  manual re-sign-and-compare (PyJWT has no PQC algs). Ed25519 output remains byte-identical to
  the legacy encoder, so old tokens verify unchanged.

### 3.5 Institutional control plane (`app/control_plane/engine.py`)

A deterministic SAFR-style evaluator with exactly four dispositions: **DENY, ESCALATE,
AUTO_EXECUTE, OBSERVE**. Order of evaluation:

1. Threshold sanity + positive amount + amount ≤ limit, else DENY.
2. **Hard deny facts** (tenant match, agent/org/principal active, mandate active and signature
   valid, provider binding + source resource active, both access grants, action/currency/
   beneficiary/purpose authorized, consent current). Hard controls cannot be overridden by any
   risk-model output.
3. Evidence: unverified → DENY; unassessed or below `min_evidence_quality_bps` (default 8500) → ESCALATE.
4. Human-review flag → ESCALATE.
5. Risk score (default baseline: `calculate_rule_risk_score_bps` — an explainable rule, not an ML
   model): ≥9000 DENY · ≥6000 ESCALATE · ≥2500 OBSERVE (with monitoring) · else AUTO_EXECUTE.

An envelope validation receipt (`safr/envelope.py` + `GovernanceEnvelopeReceipt`) is
**validation-only** (`VALIDATED_ONLY`); it never itself authorizes execution.

### 3.6 Provider abstraction (`app/providers/*`)

- `PaymentProvider` ABC: one method per capability (`create_payment`, `get_payment`,
  `fetch_payments`, `fetch_order_by_receipt`, `verify_webhook`, `normalize_webhook`, `refund`,
  `reconcile`). Routers call `get_provider()` / `get_provider_for_org()`, never concrete modules.
- **Per-tenant isolation:** non-default orgs resolve `ProviderAccount.provider_name` and load
  `RAZORPAY_*__{TAG}` / `PAYPAL_*__{TAG}` env overrides; **no cross-tenant credential fallback** —
  missing tenant credentials raise, they never borrow another org's keys.
- **Provenance columns:** every `ProviderTransaction` is stamped at consume time with
  `provider_name`, `provider_environment` (`test`/`live`/`simulated`/`unknown`),
  `provider_key_id_prefix` and `provider_api_base` — so a settlement produced by the local
  simulator can never be indistinguishable from real provider settlement. `unknown`/`simulated`
  bundles must never be presented as provider settlement.
- **Agentic seam** (`providers/agentic.py`): `AgenticPaymentProvider` is the complete
  provider-native interface (mandate bind/validate, authorize, capture, webhook, revoke).
  Unconfigured deployments get `NotConfiguredAgenticProvider`, which *refuses every operation* —
  an intentional refusal, not a fake. `razorpay_agentic.py` implements the interface over
  Razorpay's recurring/token API; autonomous settlement requires `PAARI_AGENTIC_PROVIDER` naming
  a real adapter plus a provider-issued token from a first checkout payment.

### 3.7 Webhook settlement path (`routers/payments.py`)

1. Parse raw body; resolve the owning `ProviderTransaction` (via `razorpay_order_id`).
2. Verify signature: Razorpay HMAC-SHA256 over the raw body with the webhook secret
   (`x-razorpay-signature`); PayPal via PayPal's own `verify-webhook-signature` API with
   `PAYPAL_WEBHOOK_ID`.
3. Org guard: an `rzp_*` account id in the event that doesn't match the expected provider key →
   `403 WEBHOOK_ORG_MISMATCH` + audit record.
4. Replay: `webhook_event_id` (or body digest fallback) unique per org.
5. Value guard: event amount/currency must equal the bounded authorization or the event is
   audited as `webhook_rejected_value_mismatch` and ignored.
6. State move: `payment.authorized` → `PROVIDER_AUTHORIZED`; `payment.captured` → `CAPTURED`
   then `confirm_capture` corroborates (independent read, exact value match) → `PAID`.

### 3.8 Audit chain (`app/audit.py`)

Append-only rows keyed by `transaction_id`; `event_hash = SHA256(prev_hash ∥ kind ∥ agent ∥
parent ∥ org ∥ txn ∥ created_at ∥ detail)` (hash_version 2; v1 legacy detail-only supported on
read). Per-transaction **chain lock** (`acquire_chain_lock`: Postgres advisory xact lock, no-op
on SQLite where the writer is already serialized) prevents two concurrent requests from forking
the chain. `verify_chain()` recomputes every link; the LLM trace labels
(`causal_labels()`) are carried into settlement events **only when attribution was claimed** —
an unattributed payment stays unattributed all the way to settlement.

---

## 4. Visual Representations

### 4.1 Request/response lifecycle (protocol v1 agent)

```
 +------+                          +----------------------------------------------+
 | SDK  |                          |                 Paari API                    |
 +--+---+                          +----------------------------------------------+
    |  1. GET /.well-known/paari (discovery document, no auth)
    |-------------------------------------------------------->
    |  2. POST /v1/agents/register        agent-key-signed envelope carrying
    |     {envelope{sender, payload{name, agent key, delegation, delegation_sig}}}
    |-------------------------------------------------------->   verify: envelope sig, sender==agent key
    |    <------------------------------------------------     parent ACTIVE + delegation sig + anti-replay
    |     {agent_card (Paari-signed), credential_jwt, expiry}     rows: Agent, DelegationRecord, Credential
    |  3. POST /v1/auth/challenge {agent_id}
    |-------------------------------------------------------->   nonce minted (2m TTL, single use)
    |  4. POST /v1/auth/verify {nonce, agent sig, credential_jwt}
    |-------------------------------------------------------->   session_token (15m, key-bound via cnf.jkt)
    |  5. POST /v1/payments/intent        Bearer session + X-Paari-Proof (90s, one-time JTI)
    |-------------------------------------------------------->   governance pipeline (3.1 + 3.5 + velocity)
    |     {decision ALLOW, authorization_id, bounded_authorization{token,2m,single-use}}
    |  6. POST /v1/payments/authorizations/{id}/consume
    |-------------------------------------------------------->   burn (atomic), provider create/authorize, txn rows
    |     {result state}                                        webhook + reconcile drive CAPTURED -> PAID (4.2)
    |  7. GET /v1/audit/{txn} / GET /v1/proof/{txn}             evidence endpoints (sender-constrained)
```

### 4.2 Provider-transaction state machine

```
                        +------------------+
   mint (ALLOW) ------> |     AUTHORIZED   |
                        +--------+---------+
                           | consume: provider create
                           v
                        +-------------------+   failed       +--------+
                        | PROVIDER_SUBMITTED|-------------> | FAILED |
                        +---+----+----+----+                +---+----+
                  authed|    |    | captured                ^ |  (pre-capture failure;
                        |    |    |                         | |   money may still arrive)
                        v    |    +------------------------+ | |
             +---------------------+  +--------------+        | v
             | PROVIDER_AUTHORIZED |  | CAPTURED     |        | +----------+
             +----------+----------+  +------+-------+        | +   PAID   |
                        |            ^          |             | +----+----+
                        |            |          | provider says
                        |            |          | capture did not land
                        |            |          v
                        |            |   +------------------+
                        +----------->| PROVIDER_UNKNOWN      |<-----------+
                        (missed      +----------+------------+ (dead-letter,
                         webhook)     ^          |             reconciliation
                                        |          |
                              CANCELLED/EXPIRED via order read
                              DECLINED via decline codes
   terminal set: PAID REFUNDED REVERSED EXPIRED CANCELLED DECLINED
   (CAPTURED is deliberately NON-terminal: it is the reconciler's work queue)
```

### 4.3 Core data schema (entities and relationships, abridged)

```
 ORGANIZATION (tenant) 1--* every tenant-scoped row via org_id
        |
        +-- PROVIDER_ACCOUNT (tenant -> provider_name, marker row; secrets stay in env __TAG)
        |
 PARENT_AUTHORITY 1--* AGENT (parent_pk)      trust_tier: self_asserted|admin_approved|kyb_verified
        |                 |
        | (signs)         | 1--* CREDENTIAL (signed_jwt, rotation chain superseded_by)
        v                 |
 DELEGATION_RECORD        | 1--* AUTH_NONCE
 (anti-replay, consumed)  |
                          |
 USER_PAYMENT_MANDATE *--1 AGENT (per user+agent; budgets, allowlists, Ed25519 signature
                          |                  + user_public_key_pem stored at creation)
 PAYMENT_INSTRUMENT_BINDING *--1 USER_PAYMENT_MANDATE (opaque provider refs only, unique (provider, ref))
                          |
 PAYMENT_INTENT *--1 AGENT (decision, reasons[], velocity REVIEW TTL, client-asserted llm_* labels,
                          |   unique (agent_id, idempotency_key))
 MFA_CHALLENGE *--1 PAYMENT_INTENT (single-use nonce; signed by PARENT key, a distinct key holder)
                          |
 BOUNDED_AUTHORIZATION *--1 PAYMENT_INTENT (single-use, 2m JWT token, usage_count)
                          |
 PROVIDER_TRANSACTION *--1 BOUNDED_AUTHORIZATION (state, provider ids, provenance columns,
                          |   attempts, unique webhook_event_id / razorpay_order_id)
 AUDIT_EVENT (append-only hash chain per transaction_id; unique kind/detail/prev/event hash)
 REQUEST_PROOF (burned JTI table)   RATE_BUCKET (shared counters, unique (scope, window_start))

 CONTROL PLANE:  PRINCIPAL_IDENTITY *--1 ORGANIZATION (KYC/KYB evidence fields, digest-only)
                 GOVERNED_RESOURCE (opaque external refs only; owner_principal)
                 RESOURCE_ACCESS_GRANT (time-boxed, consent-referenced)
                 POLICY_BUNDLE (versioned; one ACTIVE per (org, policy_name) partial unique)
                 CONTROL_PLANE_DECISION (immutable per intent: disposition + versions + evidence)
                 GOVERNANCE_ENVELOPE_RECEIPT (VALIDATED_ONLY; optional bound_intent/authorization)

 RECEIVING SIDE (v3.4): RECEIVER_INSTITUTION 1--* RECEIVER_BENEFICIARY (salted account_fingerprint,
                 max_payment cap) ; RECEIVER_ATTESTATION (receiver-signed; unique (receiver, event))
 FEDERATION (v3.5): FEDERATION_SIGNER 1--* FEDERATION_AGREEMENT (PQC-sized signature columns)
 PORTABILITY: AGENT_PORTABILITY_IMPORT (staging only; destination re-authorizes everything)
 ADMIN: ORGANIZATION_ADMIN_KEY (hashed, revocable, org-scoped)
```

### 4.4 Component hierarchy

```
+=============================================================================+
| app.main  (FastAPI app, lifespan: startup_guards -> ReconciliationWorker)    |
|   pure-ASGI _SecurityResponseHeaders middleware (4 baseline response headers)|
+=============================================================================+
        mounts
 +-------+-------+--------+-----------+----------+----------+--------------+
 | parents     | agents | auth   | payments*  | v1 (stable| control_  | receivers  |
 | /parents    | /agents| /auth  | /payments  | protocol)| plane/v1  | +federation|
 +------+------+------+--------+-----+--------+ | mandates, | engine +  | v36,v37   |
        |          |           |                  | intents, | runtime   | routers    |
        |          |           +------+-----------+ consume, |           +-----+------+
        |          |                  |  webhooks, reconcile, audit, proof, rotate,
        |          |                  |  revoke, orgs ...
        v          v                  v
 +=======================================================+
 | domain services (imported by routers, no HTTP concerns)|
 |  mandates  transitions  reconcile  audit  security     |
 |  governance config crypto_utils signing_backends       |
 |  serialization ratelimit trust provider_accounts       |
 |  safr.envelope portability proof_bundle                 |
 +====================+==================================+
                      | DI seams
 +====================+==================================+
 | provider adapters:  PaymentProvider.get_provider()    |
 |   RazorpayAdapter / PayPalAdapter / reference stubs   |
 | AgenticPaymentProvider.get_agentic_provider(org)      |
 +================================+=======================+
                                  |
 +================================+=======================+
 | app.models (SQLAlchemy) + app.database                 |
 |  UTCDateTime, SQLite FK pragma, disposable-DB guards   |
 +==========================================+==============+
```
`*` legacy unversioned routes remain for compatibility; **new external integrations use `/v1`.**

---

## 5. Dependency & Environment Map

### 5.1 Libraries

| Package | Role | Pinned? |
|---|---|---|
| fastapi / uvicorn[standard] | HTTP API / ASGI server | 0.115.0 / 0.30.6 |
| sqlalchemy | ORM (SQLite + Postgres parity) | 2.0.35 |
| alembic | schema migrations (32 revisions) | 1.13.3 |
| pydantic | request/response validation | 2.9.2 |
| PyJWT + cryptography | Ed25519 JWTs, PEM handling | 2.9.0 / 43.0.1 |
| httpx | outbound provider + webhook calls | 0.27.2 |
| psycopg[binary] (requirements-postgres.txt) | Postgres driver | — |
| pytest / pytest-asyncio / respx | test suite | 8.3.3 / 0.24.0 / 0.21.1 |
| liboqs-python (**optional**) | ML-DSA-65 / SLH-DSA PQC signing | absent → PQC tests skip cleanly |

### 5.2 Third-party services

| Service | Used for | Config keys |
|---|---|---|
| Razorpay (test/live) | orders, webhooks (HMAC-SHA256), recurring/token for agentic path | `RAZORPAY_KEY_ID`, `_KEY_SECRET`, `_WEBHOOK_SECRET`, `_API_BASE` (+ `__{TAG}` per tenant) |
| PayPal (sandbox/live) | orders v2, webhook signature verification via its API | `PAYPAL_CLIENT_ID/_SECRET/_WEBHOOK_ID`, `PAYPAL_ENV`, `PAYPAL_API_BASE` (+ tags) |
| Managed KMS/HSM (operator-supplied) | production signing backend | `PAARI_SIGNING_BACKEND=kms|hsm`, `PAARI_SIGNING_ADAPTER`, `PAARI_SIGNING_KEY_ID` |
| Trusted KYC/KYB identity provider (external) | production principal verification | `PAARI_IDENTITY_PROVIDER_ADAPTER`, `PAARI_TRUSTED_IDENTITY_PROVIDER_IDS` |
| Cloudflare tunnel (or any public ingress) | expose webhook routes to provider callbacks | not a code dependency; ops concern |
| Alert sink (optional) | reconcile dead-letter alerts | `PAARI_RECONCILE_ALERT_WEBHOOK` |

### 5.3 Environment configuration (grouped)

| Group | Variables | Notes |
|---|---|---|
| Posture | `PAARI_ENV` (sandbox/test/prod/prod-live), `PAARI_MODE` (standard/autonomous), `PAARI_REQUIRE_USER_MANDATE`, `PAARI_REQUIRE_SIGNED_MANDATE`, `PAARI_LIVE` | **one definition**: `config.mandate_policy()`; unknown `PAARI_MODE` raises (500) instead of failing open |
| Database | `DATABASE_URL`, `PAARI_DATABASE_URL` (wins), `ALEMBIC_URL` | `PAARI_DATABASE_URL` override exists so tests never inherit the deployment DB; schema-destroying ops require a *disposable* URL (`*_test` suffix / scratch SQLite) |
| Signing | `PAARI_SIGNING_BACKEND`, `PAARI_SIGNING_KEY_PATH`, `PAARI_SIGNING_ADAPTER`, `PAARI_SIGNING_KEY_ID` | prod refuses auto-generated keys; file perms checked (0600) on POSIX |
| Strict gates | `PAARI_CONTROL_PLANE_ENFORCEMENT`, `PAARI_RECEIVER_ENFORCEMENT`, `PAARI_FEDERATION_ENFORCEMENT`, `PAARI_REQUIRE_SAFR_ENVELOPE` | all four required for prod/prod-live boot; compose defaults enable them |
| Admin | `PAARI_ADMIN_API_KEY` (≥32 chars in prod), `PAARI_ADMIN_ORG` | unset → ephemeral dev key printed (dev only) |
| Secrets (v3.6/v3.7) | `PAARI_BENEFICIARY_HASH_SECRET`, `PAARI_V36_KEY_ENCRYPTION_SECRET`, `PAARI_V36_PII_HMAC_SECRET`, `PAARI_V36_AUTH_SECRET`, `PAARI_V37_DATA_ENCRYPTION_SECRET`, `PAARI_POSTGRES_PASSWORD` | each independently generated, ≥32 chars; never shared |
| Provider selection | `PAARI_DEFAULT_PROVIDER` (razorpay\|paypal) | per-tenant override via `ProviderAccount` |
| Reconciliation | `PAARI_RECONCILE_INTERVAL` (60s), `PAARI_RECONCILE_DEAD_LETTER_AFTER` (5), `PAARI_RECONCILE_ALERT_WEBHOOK` | background worker |
| Home jurisdiction | `PAARI_HOME_JURISDICTION` (default `AE`) | metadata only |

**Boot-refusal semantics:** `PAARI_LIVE=1` enforces Postgres + provider-specific credentials at
boot. `PAARI_ENV=prod|prod-live` additionally refuses SQLite, any non-production provider API
base, non-autonomous posture, and (prod-live) the absence of managed signing and a healthy
trusted identity provider. `/health/ready` mirrors this as an HTTP gate (503 until cleared).

---

## 6. Security & Performance

### 6.1 Security properties (implemented)

- **No raw payment credentials anywhere** — provider adapters store references only
  (`payment_instrument_bindings` carries opaque provider refs; governed resources forbid
  account data by contract).
- **Fail-closed posture**: unknown mode raises; lapsed mandates deny; unverified identity
  refuses; unconfigured agentic adapters refuse; unprovisioned production signing refuses.
- **Sender-constrained, replay-burning request proofs** (JTI table), sessions bound to the
  agent's key fingerprint (`cnf.jkt`) so a stolen session token is useless after rotation.
- **Provenance columns** make "simulated settlement" audibly different from provider
  settlement on the durable record, not just on a banner.
- **Tamper-evident audit** (hash chain + chain lock) and **single-transition authority**
  (`transitions.py`) — both pinned by dedicated test modules.
- **Webhook hardening**: signature verification before any state move, org-mismatch audits,
  replay protection, amount/currency value guards, `VALIDATED_ONLY` envelope receipts that
  cannot authorize.
- **Response hardening**: pure-ASGI middleware sets `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cross-Origin-Resource-Policy: same-origin`,
  `Referrer-Policy: no-referrer` (pure ASGI deliberately, not `BaseHTTPMiddleware`, which is
  not safe under pytest-asyncio's per-test event-loop lifecycle).
- **Container hardening**: non-root `paari` user, loopback-only compose port binding,
  multi-stage image without the dev toolchain, secrets mounted from named volumes,
  `*.pem`/`.env` gitignored and package-scanned out of release archives.

### 6.2 Security considerations / residual risks

| Risk | Status |
|---|---|
| Production signing identity held in a PEM file | Accepted for sandbox only; managed KMS/HSM adapter **not bundled** — prod remains blocked by design until an operator wires `PAARI_SIGNING_ADAPTER` |
| No certified KYC/KYB | Contract + runtime exist; sandbox provider cannot return VERIFIED; launch gate enforces this |
| LLM trace labels are client-asserted | By design: `llm_*` fields are identifiers only, carried forward only when attribution was claimed; they are *not* causal proof |
| Webhook HMAC secret in env | Rotate on leak; the v3.7.1 reports found plaintext Razorpay test secrets in uploaded artifacts — **rotation is an operator action, not a code fix** |
| `PAARI_ADMIN_API_KEY` as trusted-surface boundary | Documented POC simplification; `POST /v1/mandates` represents the user-consent boundary with an admin key — a real user-facing consent flow is the intended upgrade path |

### 6.3 Performance profile & bottlenecks

| Area | Observation | Recommendation |
|---|---|---|
| Reconciler scan | `ReconciliationWorker._run_batch` selects **all** non-terminal transactions every tick (no `limit`), unlike `reconcile_pending(limit=100)` | Add a bounded batch + cursor so a large stuck backlog can't stall the tick; one process means one worker — no sharding today |
| Mandate evaluation | Intersecting evaluation runs one spend-aggregation query per active mandate per dimension (hourly, daily, per-merchant, per-category) | Index `payment_intents` on `(org_id, agent_id, currency, decision, created_at)`; batch the aggregations when an agent has many mandates |
| Provider calls | Synchronous httpx calls inside request handling (order create, capture reads) | Add explicit timeouts + circuit-breaker per provider; the reconcile path already records `last_error` |
| Audit verification | `verify_chain` is O(n) per transaction and re-reads every event | Fine today; for long chains consider periodic anchor snapshots (docs/AUDIT_IMMUTABILITY.md already points at external WORM anchoring) |
| SQLite dev mode | Single-writer; `BEGIN IMMEDIATE` gates; FK pragma per connection | Development only; any concurrency work must target Postgres |
| Multi-instance | In-process worker + advisory locks are transaction-scoped only | Two app instances would double-process the reconciler; run one worker instance (dedicated reconcile container) or add a DB-level job claim |
| Schemas/JSON | `detail` JSON columns hold unbounded event payloads | Cap detail sizes at the audit call sites for the high-frequency kinds |

### 6.4 Scalability notes

- **Horizontally scalable** for the API plane (stateless per request; shared Postgres;
  table-backed rate limits survive restarts).
- **Vertically limited** today for: the reconciliation worker (single daemon thread),
  in-process session state, and the SQLite dev path.
- The per-tenant provider routing (`__TAG` env suffixes) scales credentials, not
  connections; consider a secrets manager for >10 tenants.

---

## 7. Onboarding Guide

### 7.1 Local setup (SQLite dev loop)

```powershell
# 1. Environment
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt        # add: pip install -r requirements-postgres.txt for PG work
pip install pyyaml

# 2. Configuration (never commit)
copy .env.example .env
# Replace every "replace-with..." placeholder with independent 32+ char secrets.
# For a plain SQLite dev loop you can instead use:
#   $env:PAARI_ENV='sandbox'; $env:PAARI_DATABASE_URL='sqlite:///./paari.db'

# 3. Schema (tables are NEVER created at import)
python -m alembic upgrade head

# 4. Run
python -m uvicorn app.main:app --reload        # UI: http://127.0.0.1:8000/docs
# Unset PAARI_ADMIN_API_KEY -> an ephemeral key is printed (dev only).

# 5. Schema parity after ANY model change (both backends, by hand):
python -m alembic check        # SQLite, with PAARI_DATABASE_URL/ ALEMBIC_URL pointed at a scratch SQLite
python -m alembic check        # repeat against a disposable PostgreSQL DB named *_test
```

### 7.2 Testing protocol

```powershell
python -m pytest -q -rs          # full suite; SQLite default (.phase5_test.db scratch file)
python -m pytest -q tests/test_phase9_state_machine.py   # single module
# Postgres: set TEST_DATABASE_URL=postgresql+psycopg://user:pw@127.0.0.1:5432/some_test_db
#           (name MUST end in _test) and rerun; PG-only tests then execute.
```

**Rules of the repo:**
- **Never run two pytest processes at once** — they share `./.phase5_test.db` and the second
  can fail with a Windows file-lock `PermissionError` that looks like a real regression.
- `tests/conftest.py` builds an isolated DB via Alembic and pre-registers an authenticated
  agent; its DB source order is `TEST_DATABASE_URL` → `PAARI_DATABASE_URL` → scratch file, and
  it **never** reads `DATABASE_URL` (the deployment variable) — by design, so `pytest` can never
  destroy a live database.
- E2E harnesses: `scripts/autonomous_payment_e2e.py` (self-hosted simulator + temp SQLite, no
  network), `scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane
  --execute-stub` (deterministic model, local order test; the real-LLM variant needs `BYNARA_*`),
  `scripts/foreign_agent_proof.py` with `PAARI_PAY_TIMEOUT=0` against a running server
  (prints `MILESTONE PARTIAL` when settlement is skipped — that is not a passed settlement).

### 7.3 Local demos & strict service

```powershell
# Strict three-service local demo (provider simulator + control-plane-enforcing API + portal)
python scripts/start_live_demo.py --database-url <loopback paari_demo PostgreSQL>
# UI http://127.0.0.1:8770 ; API http://127.0.0.1:8120/docs ; simulator http://127.0.0.1:9911/v1
python scripts/verify_local_demo.py --full        # offline verification

# Strict persistent sandbox service + gate
python scripts/run_strict_sandbox_server.py       # pins autonomous posture + control-plane enforcement
python scripts/strict_service_gate.py --require-trusted-identity-provider
python scripts/live_e2e_test.py                  # NEVER starts/stops the service; default requires
                                                 # strict enforcement and stops before any order
                                                 # without a trusted identity provider
```

### 7.4 Docker / Compose

```powershell
Copy-Item .env.example .env      # fill every placeholder; PAARI_POSTGRES_PASSWORD must be URL-safe
docker compose up -d --build
Invoke-RestMethod http://127.0.0.1:8000/health        # liveness
Invoke-WebRequest http://127.0.0.1:8000/health/ready  # may correctly 503 until credentials exist
```
Compose ships strict autonomous defaults; the app runs as non-root, port binds to loopback, and
named volumes persist signing keys + data. **Do not `docker compose down -v`** unless you intend
to delete persistent data.

### 7.5 Contribution guidelines

- **New external integrations use `/v1`** (the stable protocol surface); legacy unversioned
  routes are compatibility-only.
- Every `ProviderTransaction.state` change goes through `transitions.transition_txn`;
  extend `TRANSITION_TABLE` in the same commit that needs a new edge, with a test pinning it.
- One definition of posture: never re-read `PAARI_MODE` from `os.environ` in a router —
  call `config.mandate_policy()`.
- Model changes: add an Alembic revision, then run `alembic check` on **both** SQLite and a
  disposable Postgres (the CI test suite does not assert schema parity — `tests/test_migrations.py`
  covers round-trips only; Postgres parity is the job of `tests/test_provider_provenance.py` and
  the Postgres CI job, plus your local check).
- Webhooks never mint `PAID`; settlement is corroborated (`reconcile.confirm_capture`).
  Keep that invariant pinned in `tests/test_phase9_state_machine.py`.
- Never commit `.env`, `*.pem`, `*.db`, or unredacted session reports; release packages are
  scanned for them (see `V371_FIX_REPORT.md` safety section).
- Keep test-count/capability claims in docs consistent with the tree they describe.

---

## 8. Technical Debt Register

| # | Area | Finding | Suggested refactor |
|---|---|---|---|
| TD-1 | `reconcile_worker.py` | `_run_batch` scans **all** non-terminal rows every tick (no limit) while the one-shot `reconcile_pending` has `limit=100` | Add `LIMIT` + last-processed cursor; make the worker shardable via a claim column |
| TD-2 | Signing backends | Managed KMS/HSM adapter not bundled; production is intentionally blocked | Ship at least one reference managed adapter (or an integration test harness against a mock KMS) |
| TD-3 | Identity providers | Only a neutral contract + never-VERIFIED sandbox; strict live path stops before any order | Integrate a real KYC/KYB adapter end-to-end and certify the four SAFR dispositions on it |
| TD-4 | Agentic settlement | `RazorpayAgenticProvider` implemented and typed, but **no live autonomous settlement demonstrated** (needs a provider token from a first checkout) | Record one demonstrable live token → authorize → capture → PAID run in `docs/PROVIDER_AUTONOMOUS_SETTLEMENT.md` |
| TD-5 | `v36/`, `v37/`, `federation/`, `receivers/` routers | Interface-audited in this blueprint, not line-audited | Mark with module-level "audit-level" docs; add the focused test pass to CI |
| TD-6 | Docs volume | ~70 docs with overlapping release/session notes; several are archived-but-unmarked | Add a `docs/INDEX.md` with supersession map (what to read first, what is archived) |
| TD-7 | `tests/` count | Counts vary between releases and are asserted in multiple doc files | Single source: CI writes `BACKEND_TEST_RESULTS.md`; docs link to it instead of copying numbers |
| TD-8 | SQLite dev path | FK enforcement depends on the connect-listener pragma; single writer | Document "Postgres is the only supported production backend" up front; add a `pytest`-style smoke test that a *fresh* SQLite engine enforces FKs |
| TD-9 | Multi-instance | In-process worker + transaction-scoped advisory locks don't coordinate two app instances | Dedicated single-instance reconcile worker, or a DB-level `worker_heartbeat` claim table |
| TD-10 | Webhook surface | Legacy `/payments/webhooks/*` and `/v1/payments/webhooks/*` both exist | Keep (compatibility) but mark legacy as deprecated in OpenAPI and route provider registrations to `/v1` only |

---

## 9. Cross-Reference Index

| Topic | Canonical document |
|---|---|
| Protocol surface & objects | `docs/PROTOCOL.md`, `schemas/` |
| Interoperability contract | `docs/CONFORMANCE.md` |
| Threat model | `docs/SECURITY.md` |
| Provider adapters | `docs/PROVIDER_ADAPTERS.md` |
| Autonomous settlement design | `docs/PROVIDER_AUTONOMOUS_SETTLEMENT.md` |
| Post-quantum plan | `docs/PQ_CRYPTO_MIGRATION_PLAN.md`, `docs/PQ_CRYPTO_EVALUATION.md` |
| Strict service gate | `docs/STRICT_LIVE_SERVICE_GATE_V2_6.md` |
| UAE SAFR architecture | `docs/UAE_GLOBAL_SAFR_ARCHITECTURE_V2_7.md` |
| Audit immutability | `docs/AUDIT_IMMUTABILITY.md` |
| Phase hardening notes | `docs/PHASE6_HARDENING.md`, `docs/PHASE7_8.md` |
| v3.7.1 stability fixes & verified results | `V371_FIX_REPORT.md`, `V371_SOURCE_SHA256.json` |

*End of blueprint.*
