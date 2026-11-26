# Paari v4.0.0 — Release notes and validation boundary

## Release purpose

v4.0 consolidates the v3.9 Open Finance context governance foundation with the next architecture milestones: shared treasury reservations, receiver-side signed verification, resilient provider reconciliation and a production-oriented multi-tenant SaaS/PaaS deployment reference.

## Added and strengthened

### Treasury and concurrent authorization controls

- Organization/currency/period budget policies.
- Period buckets and a per-authorization reservation ledger.
- Conditional SQL counter update for atomic exposure reservation.
- Authorization creation and treasury reservation participate in the same database transaction.
- `PAID` commits reserved exposure to spent; definitive decline/expiry/cancellation releases it.
- `FAILED` and `PROVIDER_UNKNOWN` retain exposure until provider evidence resolves the ambiguity.
- Tenant-scoped budget configuration, summary and reservation inspection APIs.
- `PAARI_REQUIRE_TREASURY_BUDGET=1` makes missing budgets fail closed.

### Receiver-side verified payment workflow

- Receiver may sign `ACCEPTED` or `REJECTED` for the exact payment intent before execution.
- Optional strict execution gate: `PAARI_REQUIRE_RECEIVER_PRECHECK=1` requires a valid signed acceptance.
- Any receiver rejection for an intent blocks execution even if an acceptance is also present.
- `CREDIT_ATTESTED` stays post-capture evidence and cannot mutate provider settlement state.
- Production reference environment enables receiver precheck.

### Provider lifecycle and reconciliation

- Added durable reconciliation attempt count, due time, last-attempt time, dead-letter marker and stable provider idempotency reference to provider transactions.
- Worker claims due work with a lease and PostgreSQL `SKIP LOCKED` behavior, retries with bounded exponential backoff and dead-letters unresolved cases.
- API replicas no longer run schema migrations at startup.
- Reconciliation worker can run as a separate service, avoiding one reconciliation loop per API replica.
- Existing provider adapter recovery contracts remain in use: authorization-derived stable references, provider lookup after ambiguous submission and exact amount/currency corroboration before `PAID`.

### Hosted SaaS/PaaS foundations

- Consolidated architecture and client-product model documented.
- Tenant-scoped control-plane APIs for treasury.
- Production-oriented PostgreSQL + API + migration job + dedicated reconciliation worker Compose profile.
- Environment template and deployment guide identify external TLS/WAF, secret manager, managed KMS/HSM and identity-provider requirements.

## Configuration

Local sandbox defaults preserve backward compatibility:

```dotenv
PAARI_REQUIRE_TREASURY_BUDGET=0
PAARI_REQUIRE_RECEIVER_PRECHECK=0
```

For production posture, enable both:

```dotenv
PAARI_REQUIRE_TREASURY_BUDGET=1
PAARI_REQUIRE_RECEIVER_PRECHECK=1
```

A budget must be configured for each tenant/currency before that tenant can obtain a payment authorization in strict mode. The receiver must be registered, approved, and able to sign an intent-bound acceptance before execution in strict mode.

## Database migration

The v4.0 Alembic migration adds treasury policy, bucket and reservation tables and durable reconciliation metadata to provider transactions. Apply using:

```bash
python -m alembic upgrade head
python -m alembic check
```

The production Compose topology runs migrations as a one-off migration service; do not run Alembic independently in each API replica.

## Validation performed for this package

- Python compilation: passed.
- v4.0 treasury + receiver precheck + reconciliation + state/provider transaction regression batch: **25 passed**.
- Provider contract/interface/provenance/Razorpay regression batch: **34 passed**.
- Control-plane API/engine, identity-provider runtime, trust and receiver regression batch: **30 passed**.
- Setu persistence/binding/normalizer/governance/router and Mastercard normalizer plus mandate regressions: **36 passed**.
- Optional PostgreSQL atomic-counter race test: **skipped** because `PAARI_TEST_POSTGRES_URL` was not configured.
- Fresh SQLite Alembic upgrade: passed.
- Alembic model/schema drift check: no new upgrade operations detected.

The combined long regression invocation exceeded the execution time limit, so the relevant test groups were run individually. The Setu HTTP-client/lifecycle and Mastercard HTTP-client test modules could not be collected in this environment because the `respx` test dependency was absent and package installation was unavailable. Install `requirements-dev.txt` and rerun those modules in the local development environment. PostgreSQL was not available here; true database-level concurrent overspend prevention is therefore not represented as independently tested.

## Known limitations and production gates

- PostgreSQL concurrency and load tests must be run against the exact supported PostgreSQL version and deployment topology.
- Provider idempotency and reconciliation behavior must be verified against each live provider contract, including timeout-after-submit and late webhooks.
- Setu AA is an account-information/context integration. It does not itself initiate a payment. Complete sandbox consent lifecycle still depends on valid Setu tenant configuration and UAT availability.
- Autonomous provider-native real-money settlement is not proven by local simulation, standard checkout or adapter scaffolding.
- Managed KMS/HSM signing adapter and key lifecycle are not supplied as a turnkey cloud integration.
- Trusted KYC/KYB provider, independent receiver institution verification and external certifications remain to be integrated and validated.
- External security assessment, penetration test, backup/restore, disaster recovery, monitoring/alerting, privacy/legal assessment and applicable licensing/regulatory review remain mandatory before live financial use.
- SaaS billing/metering, SSO/SAML, SCIM, multi-region operation, customer support processes and tenant-specific managed key isolation are not delivered in this source archive.

## Release status

**v4.0.0 is a locally runnable development/sandbox release with production-oriented architecture and deployment foundations. It is not a hosted production service or a certification of live-money readiness.**
