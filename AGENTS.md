# AGENTS.md — Paari

Paari is a trust/governance layer between AI agents and payment infrastructure: FastAPI + SQLAlchemy + Pydantic + PyJWT with Ed25519 signing. Target Python 3.11 (CI and the Docker image pin 3.11). This tree is **v3.9.0**, backend API plus two local portal workspaces — sandbox integrations only, no production-certified real-money execution.

## Commands

- Install: `pip install -r requirements-dev.txt` (pulls runtime deps, adds `pytest`, `pytest-asyncio`, `respx`). Postgres driver: `-r requirements-postgres.txt`.
- Run: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`
- Migrate: `python -m alembic upgrade head` — **tables are never created at import**; the app 404s/500s on an unmigrated DB. Migrations read `ALEMBIC_URL`; `alembic.ini` holds only the placeholder `driver://user:pass@localhost/dbname`.
- Schema parity: `alembic check` must print `No new upgrade operations detected` on **both** SQLite and Postgres after any model change. No test asserts this, so run it by hand.
- Tests: `python -m pytest -q -rs` from the repo root (collect-only shows 549 tests on this tree). No complete green run has been recorded here — the suite has timed out before finishing (see `docs/V38_TEST_REPORT.md`). Run targeted groups and record results from the exact tree. Single module/test: `python -m pytest -q tests/test_foo.py[::test_name]`.
- **Never run two pytest processes at once.** They share `./.phase5_test.db`; the second one dies with a Windows `PermissionError` that looks like a real regression.
- E2E harnesses: `python scripts/autonomous_payment_e2e.py` (self-hosts uvicorn on a free loopback port with a throwaway SQLite DB — no external services), `python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub` (deterministic `ScriptedModel`; the real-LLM variant needs `PAARI_LLM_PROVIDER` + `KILO_*` / `OPENAI_COMPATIBLE_*` / legacy `BYNARA_*`), and `python scripts/foreign_agent_proof.py` against a running server. `PAARI_PAY_TIMEOUT=0` makes that last one skip the human-checkout and settlement steps and exit 2 (`MILESTONE PARTIAL`) — a skipped settlement is not a green one. `--execute-stub` reaches a local stub at `PROVIDER_SUBMITTED`; it never proves provider-native settlement.
- Offline release check: `python scripts/verify_local_demo.py` (fast) or `--full` (adds both HTTP E2Es).
- Local demo: `python scripts/start_live_demo.py --database-url postgresql+psycopg://…@127.0.0.1:5439/paari_demo` — launches provider stub (9911), API (8120), UI (8770). It refuses non-loopback hosts and any DB name other than `paari_demo`/`paari_demo_test`.
- Strict sandbox service: `python scripts/run_strict_sandbox_server.py`, gated by `python scripts/strict_service_gate.py` (`--require-trusted-identity-provider` to fail on missing KYC/KYB).
- There is **no** linter/formatter/typecheck/pre-commit config. CI = `.github/workflows/ci.yml`: `compileall` over `app sdk scripts tests alembic llm_agent local_demo`, then `verify_local_demo.py`, then `pytest -q`; a second job runs `test_postgres_migration.py`, `test_v31_resilience.py`, `test_v32_pg_hardening.py` against a `postgres:16` service via `TEST_DATABASE_URL`.

## Architecture

- `app/main.py` mounts, in order: legacy `/parents`, `/agents`, `/auth`, `/payments`; the versioned `app/routers/v1.py` (`/v1`); `/control/v1` (control plane, receivers, federation); `/v36` (onboarding); `/v37/enterprise`; `/portal/v1`; plus `/.well-known/paari` and `/portal`. **New external integrations use `/v1`**, not the legacy unversioned routes.
- Both surfaces are the same code path: `/v1/payments/intent` and `/payments/intent` delegate to `app/routers/payments.py::submit_payment_intent`, which runs v3.6 provider requirements (`app/v36/provider_policy.py`) and the v3.7 treasury risk gate (`app/v37/risk.py`) before any authorization exists. A payment fix belongs there, not in a router.
- `app/transitions.py` — sole source of truth for `ProviderTransaction.state`; illegal jumps raise `IllegalTransitionError`. Phase 9 vocabulary: `AUTHORIZED -> PROVIDER_SUBMITTED -> PROVIDER_AUTHORIZED -> CAPTURED -> PAID`. `PAYMENT_PENDING` is retired (rewritten by migration `c3d4e5f6a7b8`) but keeps legal exits so old rows still move.
- `app/database.py` — `UTCDateTime` keeps tz-aware UTC on both SQLite and Postgres (SQLite silently drops tzinfo). Owns `resolve_database_url()` (`PAARI_DATABASE_URL` overrides `DATABASE_URL`), `assert_disposable_database_url()`, and a `PRAGMA foreign_keys=ON` connect listener — without that pragma SQLite enforces **no** foreign keys at all.
- `app/config.py` — `mandate_policy()` is the **only** definition of governance posture, and it *raises* on an unknown `PAARI_MODE` rather than defaulting to permissive.
- `app/v37/risk.py` — per-parent treasury ceiling + per-agent daily/per-hour limits, enforced at intent admission and re-checked at consume (`enforce_execution`). Fails closed on FROZEN/suspended/cap/currency mismatch.
- `app/providers/` — `PaymentProvider` with Razorpay Orders and PayPal Orders v2 adapters, routed per tenant via `ProviderAccount.provider_name`. `app/providers/agentic.py` is the separate provider-native settlement seam: `NotConfiguredAgenticProvider` refuses every operation unless `PAARI_AGENTIC_PROVIDER` names a real adapter. That refusal is intentional.
- `app/control_plane/`, `app/receivers/`, `app/federation/`, `app/safr/`, `app/identity_providers/`, `app/portability.py` — institutional governance, beneficiary/partner enforcement, signed Governance Envelopes, a provider-neutral KYC/KYB *contract only*, and agent portability. No managed KMS/HSM adapter is bundled; production stays fail-closed. v3.9 adds Setu consent-to-signed-mandate binding, encrypted FI data snapshots and an optional Open Finance freshness gate; see `docs/V39_OPEN_FINANCE_GOVERNANCE.md`.
- `sdk/paari_agent/` — reference external-agent SDK (`pip install ./sdk/paari_agent`). Imports **no** server modules; the agent owns its private key. `llm_agent/` is the client-side LLM harness (custom `ChatModel` over an OpenAI-compatible endpoint + `PaariBroker` tool loop). It also imports nothing from `app/` — the trust layer stays a black box.
- `app/main.py::_SecurityResponseHeaders` must stay a **pure ASGI** middleware. It was a Starlette `BaseHTTPMiddleware`, which wraps every request in an anyio portal and raised `RuntimeError: … bound to a different event loop` under pytest-asyncio, breaking TestClient tests. Do not convert it back to `@app.middleware("http")`.

## Test harness

- `tests/conftest.py` is order-critical. It loads `.env.test` at import (the suite's declared baseline; `.gitignore` whitelists it, but it can be absent — conftest tolerates that and falls back to inline defaults), clears ambient `DATABASE_URL`/`PAARI_LIVE`/provider creds, then sets `PAARI_DATABASE_URL` **before** importing `app.database`, which freezes its global engine at import. An assertion in `isolate_test_environment` catches divergence. Don't "fix" a failing test by exporting env vars into your shell — the suite is supposed to ignore them.
- The suite's target is `TEST_DATABASE_URL` → else `PAARI_DATABASE_URL` → else `sqlite:///./.phase5_test.db`. It **never** reads `DATABASE_URL`, because `paari_client` runs `DROP SCHEMA public CASCADE` on whatever it is given.
- Destructive DB operations are gated by `assert_disposable_database_url`: SQLite scratch files, or server-side database names ending in `_test`. Point Postgres tests only at such a database.
- `paari_client` rebuilds the schema with `alembic upgrade head` per test, overrides `get_db`, pre-registers an active parent + authenticated agent, and awaits `ctx.client` / `ctx.session_token` / `ctx.agent_private` / `ctx.parent_private`.
- `tests/test_pqc_*.py` skip cleanly without the optional `liboqs-python`; Postgres-only tests skip without a Postgres `TEST_DATABASE_URL`. Skips are expected, not failures.

## Environment & deployment guards

- Start from `.env.example` (sandbox template). Every secret must be generated independently and at least 32 chars: `PAARI_ADMIN_API_KEY`, `PAARI_BENEFICIARY_HASH_SECRET`, `PAARI_V36_KEY_ENCRYPTION_SECRET`, `PAARI_V36_PII_HMAC_SECRET`, `PAARI_V36_AUTH_SECRET`, `PAARI_V37_DATA_ENCRYPTION_SECRET`.
- `PAARI_POSTGRES_PASSWORD` must be URL-safe — Compose interpolates it directly into the DSN.
- `load_config()` and `app.main.startup_guards()` refuse to boot a `prod`/`prod-live`/`PAARI_LIVE=1` deployment unless it has Postgres, real provider endpoints, `rzp_live_*` keys, autonomous posture, control-plane/receiver/federation/SAFR enforcement, a managed KMS/HSM signer, and a trusted KYC/KYB adapter. Expect those refusals; do not weaken them to make a local boot succeed.
- `/health` is liveness and reports the active posture plus provider provenance; `/health/ready` is the strict gate and legitimately returns 503 until credentials and enforcement are configured. A healthy `/health` does not mean ready.
- `PAARI_ADMIN_API_KEY` unset → an ephemeral key is generated and logged (dev only).
- `paari_signing_key.pem` is an **unencrypted Ed25519 private key**. It is gitignored along with `*.key`, `*.db`, `.env*` (except `.env.example`/`.env.test`), logs, `.agnes/`, `*_env.ps1`, `docker-compose.override.yml`. Never commit or package them; every token issued under a committed key stays forgeable forever.
- `docker-compose.local.yml` cannot rotate an existing Postgres role by changing the environment — rotate the password in the database. Never `docker compose down -v` unless deleting data is intended.

## Invariants you must not break

- Prefer `Authorization: Bearer <session>`; the legacy JSON `session_token` field is still accepted. **Never put session tokens in URLs.**
- Protected `/v1` payment requests require `X-Paari-Proof`: a sender-constrained JWT bound to the session-token hash, method, exact path, issue time, and a one-time JTI (replay is burned in the DB).
- Agent-requested capabilities/limits/currency are **never** authoritative — only parent-signed delegation values apply.
- **Mandate resolution is tri-state**: `NONE` / `LAPSED` / `ACTIVE`. `LAPSED` must DENY in *every* mode — a lapsed grant is not an absent grant. Multiple active mandates are enforced as an **intersection**; never let the permissive one widen a stricter one.
- The mandate Ed25519 signature is enforced **in the authorization path**, not just at creation: `app.mandates.check_mandate_signature` runs in `evaluate_mandate` and again in `_revalidate_execution` at consume. A valid signature is never evidence of liveness.
- Spending windows are **rolling** and clamped to the mandate's `valid_from`, never calendar-based. Merchant/category comparisons are case-normalized in allowlists *and* spend aggregation.
- `llm_*` fields are client-asserted trace labels. Write the `llm_tool_call` audit event only when attribution was claimed; never emit a causal marker for a request that asserted none.
- Authorization usage is reserved atomically (conditional UPDATE), not check-then-set. Provider idempotency is provider-specific: Razorpay Orders use the authorization ID as unique receipt; PayPal Orders use a stable `PayPal-Request-Id`.
- Settlement only from a signature-verified webhook or reconciliation — never from client claims. **A webhook cannot mint `PAID`**: `payment.authorized` → `PROVIDER_AUTHORIZED`, `payment.captured` → `CAPTURED`, and `PAID` only when `app.reconcile.confirm_capture` corroborates it with a direct provider read whose amount and currency match the bounded authorization. A failed read leaves the row `CAPTURED` (non-terminal) — never promoted optimistically.
- `DECLINED` belongs in `TERMINAL_STATES`. A dead-end state omitted there is re-selected by the reconciler's `notin_(TERMINAL_STATES)` filter forever.
- Unknown provider outcomes become `PROVIDER_UNKNOWN` and require reconciliation — never a guess.
- Multi-tenancy: tenant rows carry `org_id`; the `default` org row (`Default organization`) is seeded by migration `b8c9d0e1f2a3`, not at app import; non-default orgs use their own provider credentials and **never** fall back to another org's. Key rotation keeps `key_sunset_at` as a grace window for session binding.
- v3.7 treasury exposure is **conservatively reserved non-denied intents** (including pending/unknown), not settled balances — unresolved transactions stay reserved. Limits are per-parent, not a group-wide budget hierarchy.
- Provider provenance is a **column, not a banner**: `ProviderTransaction.provider_name` / `provider_environment` / `provider_key_id_prefix` / `provider_api_base` are stamped at consume time by the adapter that actually called out, and `app.proof_bundle._settlement_source` maps them to `provider|simulator|unattributed`. A bundle whose environment is `unknown` or `simulated` must never be presented as a provider settlement; `webhook_verified` only means a signature verified, not whose webhook it was.
- Proof harnesses read `mandate_mode`, `provider`, and `provider_environment` from the running server's `/health` — never from their own `os.environ` or CLI flags. Assert denial *reasons*, not just `decision == "deny"`: an over-cap probe with caps equal to the delegated limit proves the delegation check, not the mandate.
- A SAFR Governance Envelope receipt (`POST /control/v1/governance/envelopes/validate`) is `VALIDATED_ONLY` — never authorization. SAFR's outcomes are exactly `DENY`, `ESCALATE`, `AUTO_EXECUTE`, `OBSERVE`.
- Portability never transfers private keys, session tokens, mandates, resource grants, provider credentials, or bounded authorizations; the destination re-verifies and re-authorizes. Legacy delegation rows with no persisted signature must be reissued — never fabricate one. `PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON` must be pinned out of band; a key embedded in the package is not trust.
- The sandbox identity provider must never return `VERIFIED`. Synthetic fixtures are not KYC/KYB. `PAARI_HOME_JURISDICTION=AE` is metadata only and implies no licence or rail.
- v3.6 onboarding and v3.7 portability/data-export APIs are **blocked in production** until regulated identity, managed signing, and reviewed OAuth/MFA exist. Keep that gate.

## Claim discipline

- Say "the agent proposed a payment and Paari validated its authority", not "the agent autonomously paid". Governance ALLOW, a bounded authorization, a created provider order, and settlement are four different facts.
- Provider-native autonomous settlement is wired end-to-end but **no live autonomous settlement has been demonstrated** — the Razorpay recurring path needs a real token from a first checkout. Never claim `PAID` without a provider-confirmed capture.
- This is a **partially verified local development release**, not production-certified. Targeted groups pass, but the full suite has not completed in one run, and these remain unverified: PostgreSQL concurrency/serializable behaviour, complete strict multi-institution SAFR + three-party federation + receiver E2E, managed keys, admin MFA, real KYC/KYB, independent security audit. Migration `e8f901234567` (Postgres unique-constraint normalisation) has not been exercised against a real Postgres in every environment — run the `postgres-migration` CI job / `alembic check` before trusting it.
- Record test results from the exact tree you ran; a suite that timed out is not a pass. `docs/V371_FIX_REPORT.md` documents the remaining gaps.

## Docs

- Protocol & objects: `docs/PROTOCOL.md`, `docs/protocol-examples.md`, `schemas/`
- Conformance expectations: `docs/CONFORMANCE.md` · Security model: `docs/SECURITY.md`
- Providers: `docs/PROVIDER_ADAPTERS.md`, `docs/PROVIDER_AUTONOMOUS_SETTLEMENT.md`
- v3.6 / v3.7 APIs: `docs/V36_API_GUIDE.md`, `docs/V37_API_GUIDE.md`
- Current status: `docs/V37_ENHANCEMENTS.md`, `docs/V37_TEST_REPORT.md`, `docs/V38_TEST_REPORT.md`, `docs/V371_FIX_REPORT.md`
- `docs/` also holds dozens of dated verification/release reports for older versions. Treat them as historical evidence, not current truth — verify against the code and tests.
