# Release notes — Paari v2.8 SAFR sandbox milestone

## Added

- End-to-end strict control-plane rehearsal that processes an agent-signed Governance Envelope before the LLM loop can receive the existing bounded authorization.
- Governance Envelope processing binds payment context to one saved payment intent and policy decision, records the disposition in audit evidence, preserves escalation holds, and never consumes or executes payment authorization itself.
- Fail-closed behavior for non-payment envelope action classes until governed data/API executors are registered.
- Tenant-scoped treasury fleet risk/exposure summary and emergency agent revocation that closes credentials, grants and outstanding authorizations.
- Destination-side portability import staging backed by out-of-band issuer pins and destination-local parent/principal/resource/consent checks.
- Database migration and tests for import staging; documentation of the milestone demo and production prerequisites.

## Validation

The intended sandbox rehearsal is:

```bash
python scripts/llm_agent_e2e.py --with-server --rehearse --strict-control-plane --execute-stub --settle
```

It uses synthetic fixtures and a local stub only. Full-suite/test results are recorded in the delivered repository validation report; production KMS/HSM and trusted KYB integrations remain explicit blockers.
