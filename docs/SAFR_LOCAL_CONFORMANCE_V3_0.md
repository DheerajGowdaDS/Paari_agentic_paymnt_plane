# Paari v3.0 — SAFR Local Demonstration Alignment and Gaps

## Reference and scope

Reference: **Safeguards for Agentic Finance at Runtime (SAFR)**, BuildFin.ai white paper,
version 1.0, July 2026, supplied by project owner. This document is an implementation
mapping, **not** an official SAFR certification, MAS endorsement, or regulatory guidance.
SAFR itself is an industry reference approach, not a settlement scheme or compliance engine.

**Boundary:** `local_demo/` is a synthetic laboratory using the actual Paari
`GovernanceEnvelope`, cryptographic validation and `control_plane.engine.evaluate`.
It DOES NOT confer authorization, dispense real KYC evidence, or authorize live money.
The two E2E runner scripts exercise existing Paari HTTP endpoints against local
simulators, but their test postures are different and cannot be combined into a
single claim of end-to-end institutional autonomous production readiness.

## SAFR framework mapping

| SAFR paper | Component | Local implementation | Scope / limitation |
|---|---|---|---|
| p.8 Agent Identity | registered agent, verify before policy | signed v1 GovernanceEnvelope; local scenario identity matched to pinned local fixture; Paari's production API retains separate registry/auth | Fixture registry only in the policy lab; test keys generated for each synthetic agent action |
| pp.10-11 Controls Repository | institution policy and bounded mandates | Actual `ControlFacts`, `PolicyThresholds`, and `evaluate`; existing org, mandate, principal/resource/grant APIs in the underlying Paari backend | Policy lab facts are fixed fixtures, not trustable provider attestations |
| pp.11-12 Disposition Engine | DENY / ESCALATE / AUTO_EXECUTE / OBSERVE | Eight policy scenarios cover all four outputs, risk/evidence and hard-deny precedence | `AUTO_EXECUTE` in preview means eligible for execution, not paid |
| pp.8-9 Governance Envelope | action + trace + metadata + origin integrity | Signed versioned `GovernanceEnvelope`; SHA256 binding; signature, freshness and origin check; tamper case | Trace is synthetic and not independently corroborated; third-party origin assurance not supplied |
| pp.12-13 Audit Log | append-only decision records | SQLite append-only trigger and SHA256 chain, verifiable in dashboard, includes reason and scenario digest | No WORM storage, external notarization or independent replication |
| pp.13-14 Per-action gate | fresh decision each action, no authority carries forward | Each scenario creates a fresh signed envelope; existing payment E2Es verify authorization replay rejection | Policy lab cannot execute a payment and therefore cannot prove race resistance |
| p.14 SAFR before financial rails | gate distinct from settlement | Policy preview and provider E2Es visibly separate; settlement comes from signed simulated provider flow | Real PSP/KMS/KYC integrations deferred |
| pp.16-17 Human escalation | reviewer authority and expiry | Local review queue requiring terminal-only reviewer code, 120s expiration, signed audit records, no payment execution on reviewer approval | Single demo operator; not full reviewer hierarchy, business calendar, dual control or incident escalation |
| pp.16-17 Rate/exposure/evidence | bounded controls | Engine enforces amount, evidence and risk thresholds; original Paari backend handles rate/velocity | Rate limit demonstration remains in backend tests; portal does not simulate all enterprise operational workflows |
| pp.15-16 Native and gateway patterns | instrumented agent or interception | Native signed-envelope path in existing Paari; a separate real-gateway implementation is **not** delivered | No transparent third-party legacy gateway interceptor |

## Local acceptance evidence

1. `python scripts/start_local_demo.py` performs Alembic migrations and starts a
   persistent SQLite-backed Paari API + loopback portal.
2. Dashboard policy cases use the *actual* envelope validator, signature binding,
   actual `evaluate()` logic, and file-persistent tamper-evident demo ledger.
3. Escalations remain pending with explicit timeout and a demo-specific reviewer code.
   Even a reviewer 'approve' yields `approved_preview`, **not** payment authority.
4. E2E scenarios execute Paari's existing real HTTP flows against disposable local
   simulators and show raw proof/negative controls.
5. `pytest tests/test_local_demo_v3.py` covers controls, timeouts, signatures,
   tamper detection, CSRF and sandbox environment isolation.

## Acceptance work still outstanding

- Run **actual PostgreSQL** migrations, read/write parity, concurrency and soak checks
  in the user's Docker environment. The verification runner cannot claim this if
  Docker/Postgres is absent.
- Run independent institution-scaled agent load and audit WORM operational tests.
- Provide a transparent outbound SAFR gateway for agents that cannot emit envelopes.
- Add a live structured reviewer roster, approvals and escalation timeouts bound
  atomically to institutional authorization (current queue is DEMO ONLY).
- Validate original agent instruction / tool trace against independently captured origin evidence.
- Validate real trusted KYC/KYB, managed signer and strict live-provider execution;
  complete penetration, partner, and UAE legal/regulatory assessments.

**No real-money claims:** An E2E reaching `PAID` through the reference provider
or Razorpay stub proves the simulated protocol transitions only. The original
Paari production launch guards remain unchanged and fail closed.
