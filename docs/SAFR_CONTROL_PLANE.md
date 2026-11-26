# SAFR-style governance mapping

This is an implementation mapping, not a claim of SAFR certification.

| SAFR-oriented control | Paari implementation |
|---|---|
| Agent Identity | Existing registered agent, signed parent delegation, key binding, credential/card and proof-of-possession session |
| Controls Repository | Tenant-scoped versioned `PolicyBundle`, governed resources, `ResourceAccessGrant`, signed user mandate and provider binding |
| Disposition Engine | `app/control_plane/engine.py` with deterministic `DENY`, `ESCALATE`, `AUTO_EXECUTE`, `OBSERVE` dispositions |
| Audit Log | `ControlPlaneDecision`, existing `AuditEvent` chain, payment state history and reconciliation evidence |
| Governance Envelope | Transaction digest plus agent, policy name/version, reason codes, resource/principal, risk and evidence scores recorded for each disposition |
| Authorization control | Agent delegation ∩ signed mandate ∩ provider-binding cap ∩ principal and agent resource grants |
| Evidence quality | Server-derived parent trust tier, independently verified principal assurance and cryptographically checked mandate; organization attestation stays at low assurance and weak evidence escalates |
| Exposure/velocity | Amount cap intersection and Paari-side intent velocity baseline; partner-side exposure and rate limits should also be applied |
| Revocation and replay | Existing delegation/revocation/JTI protections, mandate status checks, key/resource-grant revocation, single-use bounded authorization |
| Human escalation | Existing review and parent-signed step-up flow; production operations still need an assigned reviewer service, role separation, SLA/timeouts and alerting |

## Disposition precedence

1. **Hard deny** for tenant mismatch, inactive identity/authority/mandate/binding/resource, signature failure, missing grant, unauthorized action/beneficiary/purpose/currency or exceeded amount limit.
2. **Deny** if required evidence is explicitly unverified or the risk/policy values are invalid.
3. **Escalate** if evidence quality or risk assessment is unavailable, evidence falls below threshold, an existing mandate demands review, or risk crosses the escalation threshold.
4. **Deny** at/above the configured risk deny threshold.
5. **Observe** at/above the observation threshold and below escalation; durable audit is written.
6. **Auto-execute** only when all required controls pass and risk stays below the observation threshold.

The LLM, the agent and their declared action traces never set `evidence_verified`, `risk_score_bps`, tenant identity, resource-grant status or policy version. Those facts are resolved by Paari. The included scoring function is a transparent baseline; do not use it as the sole fraud or AML control.
