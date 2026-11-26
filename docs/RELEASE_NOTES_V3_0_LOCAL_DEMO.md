# Paari v3.0 — Local Demonstration Release (26 October 2026)

**Release type:** development/demo milestone, built from corrected v2.9.
No public production certification, real provider license or official SAFR
conformance claim. Original v2.9 backend and payment-governance checks remain.

## New

- One-command local startup: `scripts/start_local_demo.py`, plus PowerShell
  and Bash wrappers that prepare a `.venv`.
- Persistent localhost Paari API (SQLite by default), Alembic migrations
  and separate responsive SAFR capabilities portal on `127.0.0.1:8765`.
- Eight signed-envelope demonstrations using the actual Paari deterministic
  engine: Deny, Escalate, Auto-Execute and Observe, plus tamper/authority controls.
- Local reviewer queue with explicit independent reviewer code, timeout
  fail-closed policy and review event hash-chain; no payment authorization.
- Two executable real Paari API E2E scenarios: institution-control simulated
  checkout and autonomous reference-provider settlement; clearly distinct modes.
- Append-only demonstration audit storage with SHA256 chain verification;
  malicious DB administrators can replace/delete the file, so it is not WORM.
- API sandbox enforced: no public bind, no arbitrary shell commands, no
  credential carry-over from `.env`, CSRF+Origin protection on mutating routes,
  SQLite allowed only at the project local demo file, PostgreSQL only at the
  `paari_demo` DB on loopback.
- Optional Docker Compose **database-only** service on loopback port 5439.
- SAFR white-paper page-to-feature mapping at `docs/SAFR_LOCAL_CONFORMANCE_V3_0.md`.
- `tests/test_local_demo_v3.py` negative and positive regression suite.

## Security boundaries

- Do not expose the local portal publicly or run it behind a public reverse proxy.
- Do not reuse demo signing keys or identity fixtures with production applications.
- The portal's 'AUTO_EXECUTE' decision is **only a policy preview**.
- Human review approval is an `approved_preview` record, not authorization.
- Demo audits, keys and database files live in gitignored `data/local_demo/`.
- The existing `/health/ready` may be 503 when real provider secrets/trust
  integrations are intentionally absent. In sandbox, `/health` is used for liveness.

## Quick start

```powershell
./start-local-demo.ps1
# http://127.0.0.1:8765
```

or `./start-local-demo.sh` on macOS/Linux; or `python scripts/start_local_demo.py`
if dependencies are already installed.

To use local Docker PostgreSQL:

```shell
docker compose -f docker-compose.local.yml up -d
python -m pip install -r requirements-postgres.txt
python scripts/start_local_demo.py --database-url "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo"
```

To verify PostgreSQL-specific migration behavior against the disposable DB created
by `docker/local_postgres_init.sql` on first volume initialization:

```powershell
$env:TEST_DATABASE_URL="postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test"
python -m pytest -q -rs tests/test_postgres_migration.py
Remove-Item Env:TEST_DATABASE_URL
```

These two tests are intentionally skipped in a SQLite-only test run. Docker and
PostgreSQL are not installed in the package-building environment, so the
PostgreSQL-specific path could not be independently exercised there. To reset
all local PostgreSQL demo data, stop the portal first and run
`docker compose -f docker-compose.local.yml down -v` (DELETES that demo DB).

Restart reuses the same local database. Browser audit ledger is separate from
Paari's actual protocol audit stream. E2E scenario runners use disposable DBs.

## Package validation (Python 3.11 / SQLite environment)

- `python -m compileall -q app sdk scripts tests alembic llm_agent local_demo` — passed.
- `python -m pytest -vv -rs` — **355 passed, 2 skipped, 0 failed**; the
  skipped cases require a disposable PostgreSQL test database.
- Real server local launcher — passed; persistent SQLite migrated to Alembic
  head; localhost portal and `/health` responded correctly.
- Portal policy preview, append-only evidence hash verification and
  unauthorized POST rejection — passed.
- Live-from-portal E2E 1: strict institutional control plane with local signed
  mandate, simulated provider capture, webhook, replay and over-cap denial — passed.
- Live-from-portal E2E 2: autonomous reference provider with signed mandate,
  bounded authorization, simulated `PAID`, replay rejection and audit — passed.
- Reviewer queue: invalid reviewer code rejected, authorized local decision
  created `approved_preview` (never actual authorization) — passed.
- PostgreSQL container startup, full persistent Postgres E2E and independent
  SAFR production conformance — **not run or claimed**.

## Known limitations / unresolved controls

See `docs/SAFR_LOCAL_CONFORMANCE_V3_0.md`. Demonstration milestone does **not**
indicate complete SAFR conformance, certified production readiness, independent
security assessment, a real identity provider or real managed KMS/HSM.
