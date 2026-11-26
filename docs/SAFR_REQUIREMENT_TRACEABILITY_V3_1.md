# Paari v3.1 — SAFR Requirement-to-Test Traceability Matrix

Every SAFR capability in the white paper and every one of the eight local
acceptance scenarios is mapped to the code that implements it and the test that
pins it. "Covered" means a deterministic test or local demonstration asserts the
behaviour on this machine. This is traceability for the *local* milestone; it
does not certify a real provider, real identity, or SAFR conformance.

## A. SAFR framework capabilities

| SAFR capability | Implementation | Covering tests / demos |
|---|---|---|
| **Agent Identity** — verified identity, valid delegation, revoked-identity rejection | `app/protocol/envelope.py` (signed envelope), `app/routers/v1.py` register + card verification, `app/control_plane/engine.py` `agent_active`/`mandate_signature_valid` hard controls | `test_protocol_security_final`, `test_governance_attacks`, `test_phase8_security`, scenario `deny_identity` (→DENY `AGENT_NOT_ACTIVE`) |
| **Controls Repository** — permitted actions, amount/rate limits, mandate conditions, risk thresholds | `app/control_plane/{engine,runtime,schemas}.py`, `app/mandates.py`, `app/ratelimit.py` | `test_control_plane_engine`, `test_control_plane_api`, `test_mandate_hardening`, scenario `deny_limit` (→DENY `FINANCIAL_LIMIT_EXCEEDED`) |
| **Governance Envelope** — authenticated action, trace, originating identity, policy context | `app/safr/envelope.py` (signed, versioned, TTL, digest-bound), `schemas/paari-safr-governance-envelope.v1.schema.json` | `test_safr_portability_v27`, `test_schemas`, `test_evidence_hardening`, scenario `deny_signature` (→DENY `ENVELOPE_ORIGIN_OR_INTEGRITY_INVALID`) |
| **Disposition Engine** — deterministic DENY/ESCALATE/AUTO_EXECUTE/OBSERVE + reason codes | `app/control_plane/engine.evaluate` | `test_control_plane_engine`, all ten `decision_preview` scenarios in `local_demo/core.py` + `verify_local_demo.py` |
| **Human escalation** — authorized reviewer, deadline, approval/denial history, fail-closed timeout | `local_demo/reviews.py` (reviewer code, 120s TTL, `approved_preview`≠authority), `app/routers/payments.py` re-checks on execute | `test_local_demo_v3` (`test_structured_review_requires_authority_and_times_out`, `test_reviewer_timeout_never_allows_payment`) |
| **Audit Log** — append-only, hash-chained, traceable, tamper-detecting | `app/audit.py` (server hash chain), `local_demo/core.EvidenceStore` (portal SHA-256 chain + triggers) | `test_audit`, `test_proof_chain`, `test_audit_chain_intact_after_consume_and_reconcile`, `test_local_demo_v3` (append-only chain detects forged rows) |

## B. The eight local acceptance scenarios

| # | Acceptance scenario | Expected | Implementation | Covering test / demo |
|---|---|---|---|---|
| 1 | Authorized payment | AUTO_EXECUTE → simulated PAID | `decision_preview("auto_execute")` + strict E2E simulator | `verify_local_demo.py`; `test_local_demo_v3`; E2E `strict_payment` |
| 2 | Suspicious but permitted | OBSERVE → logged + simulated execution | `decision_preview("observe")` | `verify_local_demo.py` (`RISK_OBSERVATION_THRESHOLD`) |
| 3 | High-risk transaction | ESCALATE → pending human review | `decision_preview("escalate")` + `local_demo/reviews` | `verify_local_demo.py`; `test_local_demo_v3` review flow |
| 4 | Payment over hard limit | DENY → no execution | `decision_preview("deny_limit")` | `verify_local_demo.py` (`FINANCIAL_LIMIT_EXCEEDED`) |
| 5 | Expired / revoked mandate | DENY → no execution | **NEW** `decision_preview("deny_mandate_expired" / "deny_mandate_revoked")` | `verify_local_demo.py` (`MANDATE_NOT_ACTIVE`); `test_mandate_hardening` |
| 6 | Duplicate authorization | Rejected → no duplicate execution | **NEW** `local_demo/core._reserve_single_use` + real atomic update | **NEW** `test_double_consume_http_second_is_rejected`, `test_concurrent_reservations_cannot_exceed_limit` |
| 7 | Provider timeout | Uncertain state → reconciliation | **NEW** `local_demo/core._provider_timeout_reconciliation` + `app/reconcile.py` | **NEW** `test_timeout_uncertain_state_reconciles_to_paid`, `test_uncertain_provider_amount_mismatch_is_not_settled` |
| 8 | Service restart | Recover state, preserve audit | **NEW** `local_demo/core._service_restart_recovery` + persisted DB/audit | **NEW** `test_audit_chain_intact_after_consume_and_reconcile` + PostgreSQL restart-persistence check (§ Phase 1) |

**Bold = added in v3.1.** Before v3.1, scenarios 5, 6, 7 and 8 were not demonstrated
as local, repeatable checks; they are now wired into the portal, the offline verifier
and the test suite.

## C. Critical design rule (invariant, asserted)

> SAFR policy preview and reviewer approval stay **separate from spend authority.**
> An approval produces an `approved_preview` record, never a directly-executable
> payment; execution still requires the fresh authenticated authorization checks.

Pinned by `test_local_demo_v3` (`approval_confers_payment_authority == False`,
expired/hard-deny reviews resolve to denial, not execution) and by the portal's
`annotation` + reviewer-code gate. The lifecycle demos in `local_demo/core.py` all
report `provider_executed: False` and move no money.

## D. v3.2 hardening & full-workflow-acceptance additions (bold)

| # | v3.2 capability / gap closed | Expected | Implementation | Covering test / demo |
|---|---|---|---|---|
| D1 | **Postgres-first concurrency** — 16 real connections / 8 real HTTP workers race a single-use authorization; at most one wins | **NEW** invariant holds under Postgres multi-worker load | `tests/test_v32_pg_hardening.py` (reuses the atomic conditional update + `tests/test_v31_resilience.py` fakes); `scripts/pg_e2e_workflow.py` step 10 (HTTP) | **NEW** `test_concurrent_reservations_capped_under_postgres`; **NEW** `test_single_use_reservation_admits_exactly_one_under_postgres`; E2E check `10.` |
| D2 | **Duplicate webhook idempotency on Postgres** | **NEW** no double settlement under the durable backend | `tests/test_v32_pg_hardening.py` (wraps the v3.1 duplicate-webhook test on the PG target) | **NEW** `test_duplicate_webhook_idempotent_under_postgres`; E2E check `6b.` (`duplicate_ignored`) |
| D3 | **Persistent recovery without duplicate execution** | **NEW** state + hash-chained audit survive an engine/service rebuild | `tests/test_v32_pg_hardening.py` (dispose + rebuild engine, re-read row/audit); `scripts/recovery_e2e.py` (two real boots, service kill at `PROVIDER_SUBMITTED`, durable provider stub via `STUB_STATE_FILE`) | **NEW** `test_state_and_audit_persist_across_engine_recreation`; E2E `B2/B2b/B2c` (one txn, order id unchanged, one `order_submitted` event, chain intact) |
| D4 | **Complete SAFR workflow driven from the dashboard** | **NEW** onboarding → mandate → all four dispositions → execution preview → settlement lifecycle → audit proof, in one run | **NEW** `local_demo/portal.py` `POST /api/full_workflow` (composes `decision_preview` + `lifecycle_preview` + `EvidenceStore.verify`) | **NEW** `tests/test_v32_local_workflows.py` (`test_full_workflow_walks_all_stages_and_appends_audit`); `scripts/verify_local_demo.py` guided-workflow check |
| D5 | **Human-escalation lifecycle** — missing authority, single resolve, approve vs deny, fail-closed expiry | **NEW** approval never confers payment authority | **NEW** `local_demo/portal.py` `POST /api/escalation/simulate` over `local_demo/reviews.py`; scenario edges from `local_demo/core` | **NEW** `tests/test_v32_local_workflows.py` (`test_escalation_simulate_covers_authority_and_fail_closed`) |
| D6 | **Reproducible release** — version-controlled source, CI, clean-install + Windows teardown, one-command acceptance | **NEW** deterministic one-command local gate | `scripts/accept_v32.py`; `.github/workflows/ci.yml` Postgres-gated step; `EvidenceStore`/`ReviewQueue` now close SQLite handles; `.gitignore` v3.2 block; git baseline `4f78d1a` | one-command `PAARI v3.2 ACCEPTANCE GREEN`; verifier exits with no `PermissionError` |

**Bold = added in v3.2.** D1/D2/D3 close the two High gaps in the v3.1 report
(ungated Postgres concurrency; stand-in recovery vs real service failure).
D4/D5 close the "complete SAFR workflow + human escalation through the dashboard"
gap. D6 closes the "reproducible release" gap. Every D-row keeps the critical
design rule intact: preview/approval is not spend authority, and no settlement in
any D-row is claimed from a real provider (`settlement_source == "simulator"`).
