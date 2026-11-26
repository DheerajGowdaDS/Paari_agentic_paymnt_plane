# Paari v2.6 — Strict Live-Service Gate

## Why

The v2.5 live E2E report recorded `require_signed_mandate=true` but `control_plane_enforcement=false` on the persistent service used for test-mode settlement. The settlement evidence remains valid for the signed-mandate path, but it must not be presented as a payment authorized under the full institutional SAFR control plane.

## Changes

- Added a persistent strict sandbox launcher that pins autonomous mandate posture, signed mandates and institutional control-plane enforcement.
- Added a non-mutating strict service gate to check health/readiness, the active governance posture, test-mode Razorpay provenance and signing backend health without displaying secrets.
- Exposed explicit principal identity-provider status in `/health`; the current build reports that the trusted principal KYC/KYB adapter is not configured.
- Changed the live E2E script to use an externally managed, persistent service; it no longer stops a server before asynchronous webhooks can arrive.
- Made strict mode the default for live E2E. With no trusted principal identity provider, the script stops before creating an order rather than fabricating assurance.
- Preserved the prior signed-mandate-only sandbox test behind an explicit opt-in that clearly disclaims strict SAFR control-plane proof.
- Added an optional wait that verifies final `PAID`, provider-sourced settlement, test environment, verified webhook and audit-chain integrity from Paari's proof bundle.
- Pinned the Docker Compose service to autonomous mode with mandatory user mandates, strict control-plane enforcement and signed mandates.
- Added regression tests for the launch posture, limited mode, trusted identity gate and persistent server lifecycle.

## Verification notes

Focused test groups and the strict local-stub E2E passed in this environment. PostgreSQL-only tests require a disposable `TEST_DATABASE_URL`; Docker build and fresh provider-side settlement were not performed here. Do not read the prior live-settlement report as a new v2.6 external run.

## Live-money gates unchanged

No concrete KMS/HSM provider adapter or trusted principal identity provider has been installed. Production boot guards must remain active. Multi-worker concurrency/soak tests, operational recovery, independent security review and partner sign-off remain mandatory.
