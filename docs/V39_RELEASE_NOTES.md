# Paari v3.9.0 — Open Finance Context Governance

## Included

- Organization-scoped Setu consent-to-payment-mandate binding API.
- Signed-mandate verification by default at binding, data-session retrieval and context access.
- Completed/partial Setu FI data-session normalization, with source timestamps and completeness checks.
- AES-256-GCM encrypted raw-payload snapshots with digest, tenant/consent/session provenance, freshness and completeness metadata.
- Organization-scoped normalized financial-context retrieval; raw FI payloads are not returned by this endpoint.
- Binding and consent revocation propagation to snapshots. Local access is revoked before the external provider call; provider outages leave a retry-pending signal rather than restoring local access.
- `open_finance_context` payment-policy evidence with OBSERVE-by-default posture.
- Optional `PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT=1` fail-closed gate at payment admission, review release and provider-consumption time.
- v3.9 integration guide, placeholder-only `.env.example`, and clean distributable packaging.

## Validation in this packaging environment

The following targeted checks passed:

- `python -m compileall -q app tests` — passed (including the final packaging pass).
- v3.9 Setu governance, binding, persistence and normalizer tests — **9 passed**.
- Stage 1 gateway/KYB and control-plane engine tests — **23 passed**.
- v2 governance, mandate hardening and user-mandate tests — **36 passed**.
- v3.7 enterprise tests — **10 passed**.
- Control-plane API and engine tests — **15 passed** (the engine test module overlaps with the 23-test batch above).
- LLM broker and webhook value-guard tests — **27 passed**.
- v2.9 release regression tests — **7 passed**.
- Fresh SQLite Alembic upgrade to head — passed; `alembic check` reported no model/schema drift.

Limitations:

- The complete `tests/setu` group could not be collected because `respx` is not installed in the environment; package installation was unavailable. The 9-test v3.9 focused group does not require `respx`.
- A larger cross-module regression batch exceeded the execution time limit before pytest produced a final summary. It is not counted as passed.
- PostgreSQL concurrency/recovery tests and the complete repository suite were not verified in this packaging environment.
- Tests ran under Python 3.13.5. The project recommends Python 3.11; a target-runtime validation remains required.

## Integration and configuration notes

- `SETU_AA_REQUIRE_SIGNED_MANDATE` defaults to `1`; Setu consent binding requires an active, same-organization/user mandate with a valid signature.
- `PAARI_REQUIRE_FRESH_FINANCIAL_CONTEXT` defaults to `0`, so the new policy contributes OBSERVE evidence without changing existing local payment demonstrations. Set it to `1` to require a fresh, complete, bound Setu context.
- `PAARI_FINANCIAL_CONTEXT_MAX_AGE_HOURS` defaults to 24 hours when the strict gate is enabled. Freshness is based on provider source timestamps, not local retrieval time.
- `PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET` should be an independently generated 32+-character secret. The legacy `PAARI_V37_DATA_ENCRYPTION_SECRET` is accepted only as a sandbox compatibility fallback.
- No new Alembic migration was necessary because the required Setu binding/session/snapshot tables already existed in the v3.8 baseline.

## Not included / not claimed

- No real-money payment execution, Setu payment initiation or settlement.
- No Mastercard/Finicity external sandbox success; the existing Mastercard adapter remains a separately configured connector scaffold.
- No regulator approval, certified KYC/KYB, production KMS/HSM, external penetration test or compliance certification.
- Setu Account Aggregator consent and financial-information retrieval are not payment authority. A separately authorized payment provider remains responsible for payment execution.
