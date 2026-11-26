# Paari v2.5 — Managed Signing Foundation and Release Hygiene

**Status:** production-oriented release candidate; not authorized for live-money use.

## Main changes

1. **Provider-neutral signing boundary:** Paari-issued credential, session, bounded-authorization JWTs and agent-card signatures use `app/signing_backends.py`. The development/local PEM backend remains non-managed and must never be represented as production-ready.
2. **Managed key integration contract:** `KmsHsmSigningBackend` wraps an injected provider client, checks Ed25519 public-key type, verifies each returned signature, resolves verification keys by `kid`, exposes health status, and has negative/fake-client contract tests. A concrete AWS/GCP/Azure/PKCS#11/bank adapter is not included.
3. **Fail-closed production guard:** an environment variable cannot self-certify KMS/HSM. The loaded backend must be the expected managed wrapper and healthy. Trusted KYC/KYB remains a separate production hard blocker.
4. **v2.4 session-report fixes carried forward:** PostgreSQL unique-constraint normalization migration; pytest collection and environment isolation; Docker secret/data directory ownership; placeholder credential detection in readiness; single-head/migration checks.
5. **Release hygiene:** `.env` and private-key/local-database/runtime artifacts are excluded from this ZIP. Temporary Compose override files are ignored.
6. **Operational documentation:** added release plan, key-management lifecycle and threat contract, secret-rotation runbook, and exact-tree verification report.

## Verification performed in this workspace

- Compilation passed.
- Focused tests: 43 passed; environment isolation: 6 passed; protocol/security/SDK/key-rotation group: 29 passed; provider/reconciliation/webhook group: 49 passed.
- Strict local-stub control-plane E2E passed, including signed-mandate requirement, persisted `AUTO_EXECUTE` and `DENY`, replayed authorization rejection, 20x over-cap rejection, and accurate `PROVIDER_SUBMITTED` status wording.
- A fresh SQLite database migrated to head `b3c4d5e6f7a8`; `alembic check` reported no new upgrade operations.
- The full repository suite did not complete with a clean process exit in this workspace. A wider batch printed `73 passed` but its outer command timed out. Docker/PostgreSQL services were unavailable here; Kilo/Razorpay was not contacted for a fresh v2.5 live run. See `IMPLEMENTATION_VERIFICATION_V2_5.md`.

## Mandatory operator action

Rotate the test credentials, Paari admin key, and webhook secret exposed in the previously shared session report. The rotation must be performed in the relevant dashboards/deployment secret stores; this release does not and cannot rotate remote credentials. Do not redistribute the unredacted report.

## Still blocked

- Provider-specific managed KMS/HSM adapter and key lifecycle validation.
- Trusted KYC/KYB provider wired into decisions.
- PostgreSQL concurrency/soak and failure-injection testing.
- Operational monitoring, incident response, backup/recovery validation.
- Independent security review and financial partner/provider sign-off.

Do not bypass `PAARI_ENV=prod` / `prod-live` startup guards to work around these gates.
