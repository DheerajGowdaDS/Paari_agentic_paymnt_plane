# Paari v2.9 — corrected source archive and verification hand-off

**Patch date:** 26 October 2026. **Scope:** correct the v2.9 source ZIP, add regression tests and keep external production blockers explicit. This is a **source-code/testing patch**, **not** a managed-KMS/KYC vendor integration, certification, or production deployment.

## Why this patch exists

The separately supplied `SESSION_SUMMARY_V2_9_LIVE.md` reported a later working tree with a corrected SAFR schema, a repaired live payment driver, 333 passing tests and one Razorpay test-mode payment settled to `PAID` on PostgreSQL. The **supplied ZIP did not contain** the schema/driver fixes, so the report was **not evidence that the original ZIP itself was the corrected tested artifact**. This patch closes that packaging mismatch at the source-code level.

## Changes in this ZIP

1. **`schemas/paari-safr-governance-envelope.v1.schema.json`:** replaced raw Pydantic-export metadata with the repo-supported hand-maintained JSON Schema form (`$schema`, `type`, `examples`, nested definitions inlined, optional nullable types). Unlike the earlier proposed simplification, this patch **retains both** the envelope's 32-element `evidence_refs` limit and the 9 quadrillion minor-unit `amount_minor_units` ceiling in the distributable schema. Stronger cross-field integrity, time awareness/TTL, signatures and authorization checks continue to be enforced by runtime code.
2. **`tests/_schema_validator.py`:** implements `maximum` and `maxItems` to enforce those schema limits instead of silently dropping them.
3. **`scripts/live_e2e_test.py`:** uses SDK PKCS8 PEM key generation/signing; generates fresh per-request `X-Paari-Proof` JWTs for all protected calls (intent, consume, audit, proof and settlement polling); sends `json={}` to consume; refuses strict-provider trials/preflight unless the live service reports a healthy explicitly trusted identity integration, a healthy managed signing backend, and `PAARI_REQUIRE_SAFR_ENVELOPE=1` in the operator environment. The explicitly limited standard-posture `--signed-mandate-only-sandbox` demonstration remains clearly non-strict.
4. **`tests/test_v29_release_regressions.py`:** adds network-free regression checks for schema/runtime alignment and limits, private-key/signature interoperability, sender-bound JWT claims and fresh JTIs, the full sandbox driver protected-call sequence/required JSON body, and fail-closed strict trial/preflight gates.
5. **CI:** expands Python compilation scope to include the test suite, migration files and LLM agent code. Existing PostgreSQL migration CI job remains enabled.

## Quick verification (run from the extracted repository root)

```bash
python -m pip install -r requirements-dev.txt
python -m compileall -q app sdk scripts tests alembic llm_agent
python -m pytest -q tests/test_schemas.py tests/test_live_service_gate.py tests/test_v29_release_regressions.py
python -m pytest -q -rs
```

If full-suite execution stalls in a constrained runner, **do not claim full-suite success**; inspect the last started test using `python -m pytest -vv` and rerun in a clean target Python 3.11 CI environment. For migration parity on actual PostgreSQL, run the repository's existing PostgreSQL CI job and `python -m alembic check` after migrations against a disposable database. Do not run migrations against a live financial database without a backup/change plan.

## Verified result for this patched source tree

- `python -m compileall -q app sdk scripts tests alembic llm_agent`: **passed**.
- Focused release gate (`tests/test_schemas.py`, `tests/test_live_service_gate.py`, `tests/test_v29_release_regressions.py`): **21 passed**.
- Complete local pytest (`python -m pytest -q -rs`): **341 passed, 2 skipped, 0 failed, 117.81 seconds**. The two skipped cases are the PostgreSQL-only migration tests; this run targeted SQLite. It is not a PostgreSQL parity, concurrency, or provider-live validation.
- No actual Razorpay transaction, managed cloud signer, KYC/KYB vendor or live-control-plane payment was executed for this patch.

## Strict runtime gate and limits

`python scripts/live_e2e_test.py --preflight-only` tests the actual service posture without requesting an order. The strict path **fails preflight** unless trusted integrations and the SAFR flag are present. These checks are necessary, **not sufficient** for institutional production signoff. A test passing with an allowlisted adapter name is not evidence that the adapter is legally trusted, audited, or backed by a real vendor.

**Still external/blocked:** a production-grade KYC/KYB vendor adapter with contracts and assurance validation; an actual cloud-managed KMS/HSM Ed25519 client, key versioning and operational recovery; an institutionally provisioned strict governance payment through the real provider, verified end to end; PostgreSQL multi-process races and fleet soak; WORM/immutable audit storage and retention, escalation operations, independent penetration/security review, UAE legal/regulatory review, payment-partner certification and formal approval. The repo's fake identity adapter remains **test-only**.

The historical Razorpay `PAID` proof in `SESSION_SUMMARY_V2_9_LIVE.md` was **test money and standard posture with local PEM**, not a rerun using this patched package. No real provider was contacted and no live-payment confirmation is asserted by this change log.

## Operator security and release hygiene

- Rotate historical Razorpay sandbox secrets and the Paari admin key described in the original hand-off report before any deployment. Never include `.env`, private keys, runtime databases, full payment logs, or generated checkouts in the released ZIP.
- Do not promote `local_pem` or the bundled fake identity provider as a production implementation.
- Audit and pin real external adapter dependencies before enabling them, and verify their reported health with independent tests.
- The corrected archive is versioned as a patched **v2.9 source ZIP**; it does not introduce a new protocol version or require a database migration beyond existing head `e6f7a8b9c0d1`.
