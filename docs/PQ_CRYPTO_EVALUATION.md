# Post-Quantum Signature Evaluation — ML-DSA (FIPS 204) vs SLH-DSA (FIPS 205)

Status: research summary grounded in NIST FIPS 204/205 (published Aug 2024), IETF RFCs/drafts, QNSI benchmarks, Mysten signature zoo, AWS KMS ML-DSA GA (June 2025), liboqs-python.

## 1. Executive summary

| Criterion | Winner | Rationale |
|-----------|--------|-----------|
| General-purpose digital signatures (agent cards, mandates, SAFR envelopes, portability) | **ML-DSA-65** | Best balance: fast sign/verify (~0.2ms sign, ~0.05ms verify), moderate key (1952B) and signature (3309B) sizes, NIST Level 3, AWS KMS GA support, X.509/CMS alg IDs standardized (RFC 9881/9882). |
| Certificate roots / long-lived anchors where size is not a bottleneck | **SLH-DSA-SHA2-128s/256s** | Most conservative security (hash functions only, no new lattice assumptions), tiny public keys (32–64B), standardized X.509 (RFC 9909). Signing is slow (seconds for `s` variants) and signatures are large (7.9–29.8KB) — acceptable for infrequent root issuance. |
| Software signing (infrequent, long-lived artifacts) | **ML-DSA-65** preferred; SLH-DSA acceptable | ML-DSA fast enough for CI/pipeline signing; SLH-DSA ok if conservative security matters more than size/speed. |
| API authentication / per-request sender proofs (Paari `X-Paari-Proof`, session tokens) | **ML-DSA-65** | SLH-DSA signing latency (seconds) and signature size (17–50KB) make it impractical for per-request proof JWTs and HTTP headers. ML-DSA verify (~0.05ms) keeps API auth fast. |
| Hybrid / backward-compatible migration | **Ed25519 + ML-DSA composite** | Ed25519 remains trusted and fast; pair with ML-DSA during migration so existing keys still verify while PQC keys are phased in. |

**Bottom-line recommendation for Paari:** adopt **ML-DSA-65 (FIPS 204, NIST Level 3)** as the primary post-quantum signature algorithm for agent/parent keys, delegation signatures, JWTs/Agent Cards, SAFR envelopes, and portability packages. Use **SLH-DSA-SHA2-128s (FIPS 205)** only for long-lived audit-chain anchors and optional root material where conservative hash-based security outweighs size/speed cost. Keep **Ed25519** as the legacy default with a hybrid verification path during migration.

## 2. Algorithm profiles

### ML-DSA (FIPS 204) — Module-Lattice-Based Digital Signature Standard
- Formerly CRYSTALS-Dilithium. Security basis: Module-LWE / Module-SIS (structured lattices).
- Parameter sets: ML-DSA-44 (Level 2), ML-DSA-65 (Level 3, recommended), ML-DSA-87 (Level 5).
- Stateless, no per-signature state to manage (unlike XMSS/LMS).
- Supports "pure" and "pre-hash" modes; CMS/X.509 specs standardize pure mode only (RFC 9881/9882).
- JOSE/COSE alg identifiers registered: `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` (draft-ietf-cose-dilithium).
- New hardness assumptions — considered sound but less battle-tested than hash-based schemes; hypothetical cryptanalytic advances against lattices would affect it.

### SLH-DSA (FIPS 205) — Stateless Hash-Based Digital Signature Standard
- Derived from SPHINCS+. Security basis: underlying hash function security only (SHA-256/SHAKE-256).
- Parameter matrix: hash family {SHA2, SHAKE} × level {128, 192, 256} × speed variant {s small, f fast} = 12 parameter sets.
- `s` variants: smaller signatures, slower signing. `f` variants: faster signing, larger signatures.
- Public keys tiny (32/48/64B); signatures very large (7,856–49,856B).
- X.509 alg IDs standardized (RFC 9909): e.g. `id-slh-dsa-sha2-128s`. JOSE alg: `SLH-DSA-SHA2-128s` etc. (draft-ietf-cose-sphincs-plus).
- Most conservative security — no new assumptions beyond hash functions. Recommended hedge against future lattice breaks.
- Signing can take seconds (`s` variants); verification ~1–5ms.

## 3. Research-based comparison

Sizes (bytes):

| Scheme | Level | Public key | Signature | pk + sig |
|--------|-------|------------|-----------|----------|
| Ed25519 (baseline) | — | 32 | 64 | 96 |
| ML-DSA-44 | 2 | 1,312 | 2,420 | 3,732 |
| ML-DSA-65 | 3 | 1,952 | 3,309 | 5,261 |
| ML-DSA-87 | 5 | 2,592 | 4,627 | 7,219 |
| SLH-DSA-SHA2-128s | 1 | 32 | 7,856 | 7,888 |
| SLH-DSA-SHA2-128f | 1 | 32 | 17,088 | 17,120 |
| SLH-DSA-SHA2-192s | 3 | 48 | 16,224 | 16,272 |
| SLH-DSA-SHA2-256s | 5 | 64 | 29,792 | 29,856 |

Performance (QNSI benchmarks, 179-byte message; Mysten zoo server-side verify):

| Scheme | Sign | Verify | Verify ops/s |
|--------|------|--------|--------------|
| Ed25519 | ~0.05ms | ~0.05–0.11ms | high |
| ML-DSA-44 | 0.116ms | 0.035ms | ~29k/s |
| ML-DSA-65 | 0.189ms | 0.053ms | ~18k/s |
| ML-DSA-87 | 0.247ms | 0.092ms | ~11k/s |
| SLH-DSA-SHA2-128s | ~1.6s | ~0.9–1.3ms | ~1k/s |
| SLH-DSA-SHA2-256f | 37.7ms | ~1ms | ~1k/s |

Relative to Ed25519 (Mysten): ML-DSA-65 sign ~36x slower, verify ~0.9x (comparable); SLH-DSA-SHA2-128s sign ~31,000x slower, verify ~17x slower.

Impact ratios vs Ed25519:
- Signature size: ML-DSA ~50x larger; SLH-DSA ~120x larger.
- Public key size: ML-DSA ~61x larger; SLH-DSA same as Ed25519.
- DB storage per agent: ~26–40x larger for ML-DSA/SLH-DSA.

## 4. Suitability by Paari use case

### Digital signatures (mandates, delegation, SAFR envelopes)
- Verified on every payment/agent registration → verify speed critical. ML-DSA-65 (~0.05ms verify) fits; SLH-DSA (~1ms) acceptable but slower.
- Signed once by parent/user → sign speed less critical, but ML-DSA still fast.
- Signature embedded in JWTs/HTTP headers → ML-DSA's 3.3KB sig is large but manageable; SLH-DSA's 17–50KB sig is impractical for headers.
- **Recommendation: ML-DSA-65.**

### Certificate management (agent cards, trust anchors, portability issuer keys)
- Agent cards / end-entity certs: ML-DSA-65 (smaller certs than SLH-DSA, fast verify).
- Root/intermediate trust anchors issued rarely: SLH-DSA-SHA2-128s (tiny 32B keys, conservative hash security, large sigs acceptable).
- X.509 alg IDs exist for both (RFC 9881 ML-DSA, RFC 9909 SLH-DSA).
- **Recommendation: ML-DSA-65 for end-entity; SLH-DSA-SHA2-128s for roots.**

### Software signing (artifact/signing utility `scripts/v35_sign_agreement.py`, CI)
- Infrequent, one-off signing → sign latency tolerable.
- Signatures stored/transmitted as artifacts → size less critical than for API headers.
- ML-DSA-65 fast enough; SLH-DSA acceptable if conservative security preferred.
- **Recommendation: ML-DSA-65 (default), SLH-DSA optional.**

### API authentication (Paari sender-constrained proof JWTs, session tokens, bounded authorizations)
- Per-request proof generation and verification → sign+verify must be fast and compact.
- SLH-DSA signing (seconds) and 17–50KB signatures are impractical for per-request proof JWTs and `X-Paari-Proof` headers.
- ML-DSA-65 verify ~0.05ms keeps API auth throughput high; 3.3KB sig increases header size but is workable.
- **Recommendation: ML-DSA-65 only; do not use SLH-DSA for per-request API auth.**

## 5. Library / ecosystem assessment

| Library | ML-DSA | SLH-DSA | Maturity | Notes |
|---------|--------|---------|----------|-------|
| `liboqs-python` (wraps liboqs C) | ✅ | ✅ | Beta | Primary reference implementation. C bindings; Windows MSVC build warns about non-constant-time behavior. |
| `pqcrypto` | ✅ | ✅ | Beta | Pure Python + C; simpler API. |
| `cryptography` (pyca) | ❌ planned | ❌ planned | — | v43.0.1 has no ML-DSA/SLH-DSA. Monitor for native support. |
| AWS KMS | ✅ (GA) | — | Production | ML-DSA keys via CreateKey/Sign/Verify (limited regions initially). |
| OpenSSL | in progress | in progress | — | PQC in OpenSSL 3.x drafts; not yet stable. |

**Environment constraint (2025 baseline):** `cryptography` 43.0.1 does not implement PQC; PQC sign/verify requires an installed PQC backend. **Updated 2026-10-29:** `liboqs-python` IS installed in this tree's test environment — real ML-DSA-65 (and, where enabled in the liboqs build, SLH-DSA SHAKE-128S) sign/verify executes and all PQC tests pass (45 PQC tests across 7 files; SLH-DSA `s`-variant signing is build-dependent in speed and, on some builds, the SHA2 pure variant fails verify, so `SLH_DSA_128S` maps to `SLH_DSA_PURE_SHAKE_128S`). The abstraction layer is designed so Ed25519 works via `cryptography` regardless, and PQC backends activate only when `liboqs` imports and the mechanism is available (`PQCBackendUnavailable` otherwise — fail-closed).

## 6. Key risks

1. **Signature size bloat** — ML-DSA ~50x, SLH-DSA ~120x larger than Ed25519. JWTs, HTTP headers (`X-Paari-Proof`), and DB columns must be resized (PEM → VARCHAR(8000), signature → VARCHAR(8000)).
2. **Verification throughput** — at 1,000 payments/sec ML-DSA adds ~50ms total verify vs ~50ms Ed25519; may need caching/batching. SLH-DSA far worse.
3. **Library maturity** — liboqs/pqcrypto are beta, not externally audited. Open Quantum Safe advises caution in production.
4. **No standard PEM/SPKI for PQC yet** — X.509/PKIX extensions (RFC 9370) in progress; key portability across toolchains is immature.
5. **New lattice assumptions** — ML-DSA security rests on MLWE/MSIS; hypothetical breaks would compromise it. SLH-DSA is the conservative hedge.
6. **Offline build constraints** — Windows/MSVC builds of liboqs warn about non-constant-time behavior on unsupported toolchains.

## 7. Recommendation

- **Primary PQC algorithm: ML-DSA-65** (FIPS 204, Level 3) for agent/parent keys, delegation signatures, JWTs/Agent Cards, SAFR envelopes, portability packages, and API proof JWTs.
- **Conservative anchor: SLH-DSA-SHA2-128s** (FIPS 205, Level 1) for audit-chain signatures and optional root trust anchors.
- **Keep Ed25519** as legacy default with hybrid (Ed25519 + ML-DSA) verification during migration.
- **Defer production PQC rollout** until `liboqs-python` (or `cryptography` native PQC) is installable and audited in the target environment; keep the abstraction layer ready.

## 8. Implementation status (as of 2026-10-29)

All seven migration phases in `PQ_CRYPTO_MIGRATION_PLAN.md` are now implemented and tested on this tree (Phases 1–3 pre-existing; Phases 2b/4/5/6/7 completed 2026-10-29). See that plan's Status section for per-phase detail and the PQC test files (`tests/test_pq_crypto.py`, `tests/test_pqc_signing_backend.py`, `tests/test_pqc_schema.py`, `tests/test_pqc_jwt.py`, `tests/test_pqc_federation.py`, `tests/test_pqc_sdk.py`, `tests/test_pqc_hybrid.py`). Full verification evidence: `python -m pytest -q -rs` → 469 passed, 8 skipped (7 Postgres-only + 1 Windows-permission), 1 xfailed, 0 failures; `alembic check` clean on SQLite; `compileall` clean. The Postgres migration job for `b9c0d1e2f3a4b` still needs a manual run against a disposable `*_test` PostgreSQL database before production use.
