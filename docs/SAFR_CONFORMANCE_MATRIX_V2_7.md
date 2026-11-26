# Paari SAFR Conformance Matrix — v2.8 sandbox update

**Assessment type:** repository feature mapping and focused test evidence for the v2.8 sandbox update, not official SAFR certification or an independent security audit.

## Status legend

- **Implemented primitive:** code and tests cover the primitive, but this does not prove it is deployed across every relevant runtime path.
- **Partial:** some code exists; integration, semantics or coverage remain incomplete.
- **Open:** not implemented or not evidenced.

| SAFR concept / control | Paari v2.7 mapping | Status | Evidence / next gate |
|---|---|---|---|
| Governance Envelope schema | `app/safr/envelope.py`; `schemas/paari-safr-governance-envelope.v1.schema.json` | Implemented primitive | Strict validation, digest/signature/freshness and payment-context tests. |
| Per-action integrity binding | `compute_action_digest`, Ed25519 signature verification | Implemented primitive | Altered action context, expired and long-TTL tests. Need schema/version interoperability and fuzzing. |
| Agent Identity | Paari registry, active key, parent-signed delegation checked at envelope ingress | Partial | Runtime verifies registered records; external registry resolution and production KYA adapter remain. |
| Controls Repository | Tenant-scoped policy bundles, grants, signed mandates and risk controls; payment envelope processing binds to the persisted runtime decision | Implemented for sandbox payment path | The envelope processor does not accept agent-provided policy facts. Data/API actions remain denied until a governed executor is registered. |
| Disposition Engine | `app/control_plane/engine.py` persists `DENY`, `ESCALATE`, `AUTO_EXECUTE`, `OBSERVE`; `/governance/envelopes/process` binds a signed payment envelope to the saved decision | Implemented for sandbox payment path | Unit conformance tests cover all four dispositions. E2E rehearsal proves `AUTO_EXECUTE` through authorization consumption and stub settlement; full reviewer workflow, timeouts and production operations still need qualification. |
| Audit Log | Envelope validation receipt plus disposition/escalation-hold audit events; existing hash-linked audit and transaction proof bundle | Implemented for sandbox evidence | Reconstruct a payment with `GET /v1/proof/{transaction_id}` and/or `GET /v1/audit/{transaction_id}`. Independent WORM storage, signed checkpoints and retention controls remain. |
| Evidence quality | Envelope references are recorded by digest and explicitly untrusted until independently checked | Partial | Vendor/provider verifier and telemetry/trust adapters remain; claims from agent trace must not be accepted as ground truth. |
| Human escalation | Persisted `ESCALATE` disposition is recorded as a hold; it issues no bounded authorization | Partial | The envelope processor will not execute or mint authority for a hold. Reviewer RBAC, authority separation, deadlines, notification and timeout worker still need complete operational tests. |
| Authorization before execution | Existing signed mandate, policy, bounded authorization, single-use consume and provider interface | Partial-to-strong for payment path | Strict local E2E validates replay/over-limit behavior; persistent live service must report strict control plane enabled and be re-tested. |
| Every consequential action is governed | `POST /control/v1/governance/envelopes/process` binds payment envelopes to saved decisions; all non-payment actions are denied without a registered governed executor | Partial, fail-closed | Sandbox LLM hook runs this step before exposing a bounded authorization. Data/API execution gateway registration and route-level mandatory enforcement are not included yet. |
| Tenant/resource isolation | tenant-scoped record lookup, active resource grants and principal/agent grants | Partial | Existing probes/tests cover some cases; full cross-tenant coverage across caches, evidence, audit and provider routes needed. |
| Exposure and rate limiting | `GET /control/v1/organizations/{org_id}/fleet/risk-summary` reports per-agent recent risk, counts and aggregate outstanding exposure by currency; emergency revoke invalidates credentials/grants and unconsumed authorizations | Implemented for tenant-scoped sandbox administration | Exposure reflects outstanding authorizations and unsettled provider transactions in a 24-hour decision window; multi-worker atomicity and load/soak verification remain. |
| Provider outcome and reconciliation | Razorpay adapter, signed webhook checks, idempotency and reconciliation state machine | Demonstrated in test mode from prior report | Capture/webhook/reconciliation path reported to reach `PAID` in test mode; do not equate this with live-money readiness. |
| Agent portability | Signed export plus `/portability/import/validate` and import readback; trust anchor loaded out-of-band via `PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON` | Implemented for sandbox staging | Destination parent, attested principal, active resource and consent grant are revalidated. Import only stages metadata; destination registration, fresh credentials/mandates/grants and new authorization remain required. |
| Trusted legal identity / KYB | Provider-neutral `IdentityVerificationProvider` contract and sandbox test double | Open for production | Production startup remains blocked without a genuine trusted identity/KYB adapter that verifies identity evidence, provider callbacks, provenance, expiry and revocation. |
| Managed KMS/HSM | Signing-provider boundary and boot health checks | Open for production | No managed KMS/HSM adapter is bundled or falsely simulated. Production startup must remain blocked until the real adapter passes acceptance/health tests. |

## Four dispositions — required semantics

- `DENY`: no authorization minted, execution blocked and reason recorded.
- `ESCALATE`: execution remains on hold until authorised human resolution; no authorization while pending. Modification requires a new policy decision.
- `AUTO_EXECUTE`: issue one short-lived authorization bound to the exact, canonical action only after all mandatory checks pass.
- `OBSERVE`: permit only within existing authority and record monitorable evidence. It is not a bypass and cannot confer authority on the next step.

## v2.8 sandbox evidence added

- `POST /control/v1/governance/envelopes/process` reuses signed-envelope ingress checks, binds a payment envelope to the exact persisted intent/decision digest, and reports whether the existing bounded authorization is still consumable. It does not execute a payment itself.
- The strict LLM rehearsal installs a governance hook so the agent cannot receive the existing bounded authorization until the signed envelope has been processed.
- Fleet risk summary and emergency revocation are tenant-scoped; revocation invalidates active credentials, agent resource grants and pending one-time authorizations.
- Portability staging requires a separately configured issuer trust pin and destination-local parent, principal, resource and consent. It never imports credentials, mandates, grants or authorizations.
- Targeted tests cover fail-closed non-payment executor behavior, fleet revocation and destination portability staging. See `docs/SAFR_SANDBOX_MILESTONE_V2_8.md` for the runnable demonstration.

## Required release tests

1. Invalid/untrusted envelope key, changed action digest, expired envelope, replayed envelope and wrong tenant.
2. Revoked agent/parent/key/mandate, wrong principal, cross-tenant resource, missing grant and stale resource binding.
3. Every disposition and transitions; ESCALATE remains blocked under timeout, reviewer without authority and changed action.
4. Parallel authorization consumption and exposure-limit updates across multiple PostgreSQL workers.
5. Direct provider bypass, provider timeout/unknown state, forged/duplicate/out-of-order webhooks and reconciliation mismatch.
6. Independent audit reconstruction for all four outcomes, including policy version, evidence provenance, reasons, timings and provider outcome.
7. Portability import using an out-of-band Paari issuer trust anchor; tamper and stale/revoked claims fail; destination creates its own grants and mandate.

SAFR is used here as an industry reference approach. This matrix is an engineering assessment and must not be represented as official certification.
