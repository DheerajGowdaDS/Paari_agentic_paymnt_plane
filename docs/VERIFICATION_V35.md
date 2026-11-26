# Paari v3.5 — Verification Results (2026-10-28)

Verified directly against the package source in a disposable SQLite environment:

| Targeted suite | Result |
|---|---|
| `test_v35_federated_governance.py`, `test_v34_receivers.py`, `test_audit.py`, `test_safr_portability_v27.py`, `test_control_plane_engine.py` | **37 passed** |
| `test_user_mandates.py`, `test_mandate_hardening.py`, `test_reconcile.py`, `test_reconcile_worker.py`, `test_protocol_security_final.py`, `test_v33_acceptance_integrity.py` | **37 passed** |
| `test_v34_ui_surface.py`, `test_control_plane_api.py`, `test_audit_hardening.py`, `test_phase8_security.py` | **17 passed** |

Total **91 targeted test executions passed** in these non-overlapping groups. (This is **not** a full-suite result.)

The new v3.5-specific tests demonstrate actual signed role intersection, missing agreements fail closed, forged receiver signature refusal, user consent revocation before authorization consumption, policy drift invalidation, signed payment-context tamper resistance and org isolation.

- Alembic head `f8a9b0c1d2e3`; clean SQLite migrations applied by fixtures.
- JS syntax and Python compile checks passed.
- Headless Chromium checked actual desktop Overview, Federation & Consent and Payment Tracker navigation, and mobile federation layout. No JavaScript page errors or 390px horizontal overflow.
- A full-suite attempt was **inconclusive** after an initial expected audit-event-order incompatibility (subsequently resolved) and an overlapping test process caused disposable SQLite database interference. It is **not** claimed that the entire project passed full final regression.
- PostgreSQL migrations, exact v3.3.1 commit comparison, external provider sandbox, human review-to-execution, independent cross-org HTTP execution and live-money production compliance **not yet verified**.

Use a dedicated disposable PostgreSQL `_test` database for next acceptance work. Never run the test harness against an operational database.
