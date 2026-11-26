# Paari v3.7 — Verification Report (29 October 2026)

**Release posture:** `LOCAL_DEVELOPMENT_PARTIALLY_VERIFIED`.

## Completed evidence on this edited source

| Verification command | Result |
|---|---|
| `pytest -q tests/test_v37_enterprise.py tests/test_v36_onboarding.py tests/test_backend_only_api.py tests/test_mandate_hardening.py` | **24 passed, 0 failed** (after login/velocity changes; recheck after final data-proof change below) |
| `pytest -q tests/test_v35_regulatory_review.py tests/test_v34_receivers.py` | **11 passed, 0 failed** |
| `pytest -q tests/test_v37_fleet_100.py` | **1 passed, 0 failed**, 100 new organization-owned agents registered via API and counted in fleet exposure |
| `pytest -q tests/test_v37_enterprise.py tests/test_v37_fleet_100.py` | **8 passed, 0 failed** following mandatory data-export proof validation |
| Alembic migration `d7e8f9012345` | Passed on disposable SQLite via the test fixture |
| `compileall` of new modules | Passed |

These are **overlapping test runs**. The union of independently identified focused test cases is **36 distinct passing cases** (7 new enterprise + 1 fleet + 3 v3.6 onboarding + 3 backend-only + 11 mandate + 6 regulatory review + 5 receiver). The focused 24-test command should be rerun after any subsequent edits.

### Positive/negative scenarios verified

- Parent's manual approval and login; password lockout after five invalid logins.
- Two authorized agents under the same parent share a UTC-day reserved-exposure ceiling; next request is denied when exceeded.
- Parent emergency freeze stops new payments and blocks already-approved execution; admin-unfreeze requires authorized administrator key.
- Per-agent suspension blocks intents; hourly request-velocity cap blocks repeated admissions.
- Dataset registration rejects account-number/PAN-like arbitrary fields; grant limits export fields and purpose/destination; agent request-proof is mandatory; grant revocation prevents export; export signature verifies; dataset purge revokes grants and clears live ciphertext.
- Tampered portability packages are rejected; out-of-band issuer trust is required; package replay is denied; identity link uses a newly registered destination agent and fresh key; payment mandate is **not** transferred.
- API registration and fleet policy management for 100 treasury agents, with 5 agents suspended in a synthetic organizational fleet.
- Existing signed mandate, backend-only, regulatory reviewer and receiver security controls pass their selected regressions.

## Incomplete or unverified gates

- Full legacy suite **not completed**: broad combined test runs timed out/stalled after several dozen tests. Do not infer full-suite success from the passing subsets.
- No PostgreSQL server was available in this execution environment. Per-parent row locks and atomic concurrent budget admission **require a real PostgreSQL race test** before asserting strict concurrency safety.
- No full strict simultaneous SAFR + three-party federation + receiver + recoverable provider simulator E2E run on PostgreSQL was completed.
- No production KYC/KYB, managed KMS/HSM, security penetration test, actual bank/funds settlement, post-quantum optional `oqs` verification, or regulated open-finance/cross-border/stablecoin integration verified.
- No independent consent/legal assessment of data export, production encrypted delivery to an institution, online cross-platform source revocation attestation, or institutional trust certification.

**Verdict:** The additive enterprise feature set is functional within the tested **local sandbox scope**. Not production-ready, not regulatory-approved, not certified for real financial execution or real financial-data portability.
