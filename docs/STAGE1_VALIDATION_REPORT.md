# Paari v3.8.1 Stage 1 — Strong binding and sandbox validation report

**Validation date:** 2026-11-19  
**Repository baseline:** Paari v3.7.1  
**Package version:** `3.8.1-stage1-strong-binding`  
**Runtime used for this validation:** Python 3.13.5

## Scope implemented

1. Dedicated mTLS payment-ingress middleware and Nginx reference listener; trusted-proxy CIDR validation; local CA, gateway and agent certificate tooling; certificate-to-Agent-Card subject/SAN/EKU binding; per-request registry, Agent Card, parent-state and revocation checks.
2. Separate security-ingress audit events for rejected certificates. They explicitly record that no payment intent or authorization was created.
3. Opt-in sandbox KYB scenario provider with simulated pass, exception-review, reject and unavailable/retry journeys. All simulation records are marked `sandbox_only=true` and `legal_identity_verified=false`.
4. Versioned reason-code catalogue and structured evidence persisted on payment intents and strict institutional control-plane decisions, returned through API schemas and shown in Paari Console payment details.
5. Organization Portal and Paari Console updates for sandbox-only onboarding choices, exception status and structured decision evidence. Sandbox selectors are hidden unless the API reports the simulator enabled.
6. Stage 1 end-to-end security and regression tests.

## Revalidation performed during this packaging pass

The following checks were re-run against the packaged working tree:

| Check | Result |
|---|---:|
| `tests/test_stage1_gateway_kyb.py` | 12 passed |
| Combined Stage 1, onboarding, identity-provider, control-plane, portal and health regression selection (including the 12 Stage 1 tests) | 52 passed |
| `python -m compileall -q app scripts alembic tests` | passed |
| `python scripts/verify_local_demo.py` | 17/17 local demonstration checks passed; the verifier labels itself non-certification |

An additional broader governance/E2E regression batch was attempted with a 180-second limit but did not complete and produced no final pytest summary. It is not counted as a pass. The selected 137-test run noted below was recorded in the earlier Stage 1 validation session; it was not fully reproduced in this packaging pass.

## Previously recorded selected validation set

An earlier Stage 1 validation session recorded the following selected test results. These are retained as prior run evidence and are not presented as a fresh rerun in the packaging pass above.


| Check | Result |
|---|---:|
| Stage 1 gateway/KYB/evidence tests | 12 passed |
| Stage 1 + onboarding + identity provider + control plane + portal + health regression set | 54 passed |
| v3.7 enterprise tests | 10 passed |
| Transition, audit, audit-hardening and mandate-hardening tests | 23 passed |
| Governance attack tests | 3 passed |
| Phase 8 security tests | 8 passed |
| Phase 9 state-machine tests | 14 passed |
| User mandate tests | 10 passed |
| MVP end-to-end acceptance tests | 15 passed |
| **Total across the selected, separately executed test set** | **137 passed** |

Additional verification:

- `python -m compileall -q app scripts alembic tests` — passed.
- `python scripts/verify_local_demo.py` — 17/17 local demonstration checks passed; 13-entry SAFR audit chain and 6-entry guided-workflow audit chain verified. The verifier itself states that it is not production certification.
- Fresh SQLite migration through Alembic head `f3b4c5d6e7f8` — passed in the current packaging pass.
- `alembic check` against that migrated SQLite database — `No new upgrade operations detected` in the current packaging pass.
- Local PKI `init` and `issue-client` — exercised by the Stage 1 test suite; agent certificate registration and revocation assertions passed.
- Both portal JavaScript bundles — `node --check` passed after the disclaimer updates in the current packaging pass.
- `docker-compose.yml` and `docker-compose.mtls.yml` — YAML syntax parsed successfully in the earlier validation session. This is not a substitute for Docker Compose schema validation or container startup.
- Live Uvicorn smoke test against a fresh migrated SQLite database — recorded in the earlier validation session; `/health`, `/organization` and `/console` returned successfully; sandbox KYB health flag was true when explicitly enabled.

## Checks not completed / limitations

- The complete pytest suite has not been verified as passing. An earlier attempt collected approximately 530 tests but exceeded its execution window before a final summary. A further broader governance/E2E selection in the current packaging pass also exceeded its 180-second limit without a final summary. Neither attempt is counted as a pass. The 137-test result above is historical selected-run evidence only; the current freshly rerun selected set is 52 passing tests.
- Docker is not installed in the build environment. The optional `docker-compose.mtls.yml` + Nginx deployment profile was therefore not launched or validated with `docker compose config`/container execution.
- The local schema check used SQLite. PostgreSQL migrations, concurrency, multi-worker behavior, backup/restore and failover were not validated in this environment.
- No real ACRA, MCA or third-party KYB/KYC provider was connected. The KYB workflow is synthetic and local only.
- No live bank/PSP execution, settlement certification, external penetration test, independent audit, formal legal review or regulator approval was performed.

## Release interpretation

This package is a **locally runnable Stage 1 security and governance demonstrator**. It is appropriate to demonstrate the intended architecture, local certificate enrollment and revocation, sandbox KYB exception journeys, and versioned decision evidence, with the limitations above stated clearly.

It is **not production-ready, certified, or regulator-approved**. Do not use the local CA, simulator, local SQLite database or file-based sandbox keys for production. Production launch gates are listed in `STAGE1_REGULATORY_PITCH_BOUNDARIES.md` and `STAGE1_ZERO_TRUST_GATEWAY.md`.


## v3.8.1 strong Agent Card binding increment

- mTLS certificate registration now requires a proof-of-possession signature from the private key corresponding to the Agent Card public key. The canonical domain-separated payload binds agent ID, organization ID, certificate SHA-256 fingerprint, serial number, validity interval and Agent Card key fingerprint.
- The certificate registry stores the Agent Card key fingerprint. Every protected payment-intent ingress checks that the registered Agent Card key version is still current, or is still inside its explicit old-key grace period. A legacy certificate row without a key fingerprint is rejected and must be re-registered.
- Strict certificate profile validation now requires an exact CN, exactly one URI SAN, sole `clientAuth` EKU, `CA=false`, digital-signature KeyUsage, valid certificate lifetime and supported leaf public-key strength. The configured CA is checked for current validity, CA constraints, keyCertSign and self-signature.
- Added migration `f4c5d6e7f8a9` for the Agent Card key fingerprint.
- Added `scripts/paari_sandbox.py` for local sandbox preflight and Compose lifecycle, and `scripts/run_stage1_sandbox_checks.py` for repeatable Stage 1 checks. Compose now passes the KYB simulation toggle into the app container.
- Added focused regression coverage for proof-of-possession, cross-organization proof rejection, Agent Card key rotation grace/expiry, strict SAN handling, legacy binding fail-closed behavior, narrow proxy CIDRs and sandbox preflight.
- Executed the actual `mtls_pki.py issue-client` CLI with a generated Agent Card keypair; confirmed that the registration JSON contains only the client certificate PEM and proof signature, not either private key.
- Simulated upgrade from an existing v3.8.0/f3 schema without the new key-fingerprint column; the new migration added the required NOT NULL column with a fail-closed empty sentinel.

### Fresh verification in the v3.8.1 work pass (2026-11-19)

| Check | Result |
|---|---:|
| `tests/test_stage1_gateway_kyb.py` + `tests/test_stage1_sandbox_tooling.py` | 17 passed |
| Selected onboarding, identity, control-plane, portal, security and migration regression set | 52 passed |
| `scripts/verify_local_demo.py` | 17/17 checks passed |
| Python compilation (`app`, `scripts`, `alembic`, `tests`) | passed |
| Fresh SQLite migration to Alembic head `f4c5d6e7f8a9` | passed |
| SQLite `alembic check` | no new upgrade operations detected |

The 69 pytest tests above are from two disjoint selected groups. The 17 local-demo checks are a separate verifier, not pytest tests. The complete repository suite and Docker/Nginx ingress deployment were not run. PostgreSQL concurrency, live KYB, real-money provider execution, penetration testing and regulatory approval remain outstanding.
