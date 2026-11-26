# Strict control-plane E2E validation — 2026-10-21

## Command

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub
```

## Result

**PASS** — local, deterministic integration test on a throwaway SQLite database and the local Razorpay-compatible stub. No Kilo endpoint, real Razorpay endpoint, or money movement was involved.

Validated in the run:

- The running server's health response reported `control_plane_enforcement=true` and `require_signed_mandate=true`.
- A mandate-less payment attempt was denied by the strict payment path.
- Parent/agent registration, parent-signed delegation and proof-of-possession authentication completed over the HTTP API.
- The control-plane APIs created a tenant-scoped principal, governed source resource, agent and principal access grants, and active versioned policy.
- The signed user mandate was verified and bound to the source resource.
- The positive intent persisted an `AUTO_EXECUTE` decision for the expected policy, principal and resource; its hash-chained audit proof verified.
- One local-stub order was created and reached `PROVIDER_SUBMITTED`.
- A repeat consume of that same bounded authorization returned HTTP 409 (`Authorization already used or revoked`).
- A separate server-level proposal of `10,000,000` minor units was rejected against a `500,000` minor-unit agent cap; no bounded authorization was returned. Its tenant-scoped control-plane disposition persisted as `DENY`.

## Identity assurance limitation

This disposable test seeds the *synthetic test result* for parent approval and principal high assurance directly into the local SQLite fixture because a production-trusted identity/KYB adapter is not included. The fixture is explicitly labeled in runtime output and documentation. This is a test of the enforcement path, **not** verification of a person's identity or an organization's KYB status.

## Separate test results

The focused LLM client/configuration, control-plane API, health, state-machine, consume-replay, audit and deployment-guard batch passed **52 tests**. Python compilation passed. A full single-process run of all 289 collected tests did not complete within the allotted time: it reached the MFA auth module after earlier tests passed, while that same MFA module passes independently. Full CI regression remains a release gate.

## What this does not prove

It does not prove Kilo availability/reliability, real Razorpay test-order creation, real-money settlement, production identity proofing, PostgreSQL multi-worker concurrency, KMS/HSM behavior, live provider webhook certification or regulatory readiness. Configure actual gateway/test-provider credentials locally and run the documented real-model sandbox command for those integration checks.
