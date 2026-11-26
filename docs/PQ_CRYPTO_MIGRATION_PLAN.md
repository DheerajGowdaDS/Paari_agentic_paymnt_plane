# Post-Quantum Cryptography Migration Plan

## Status
- **Evaluation:** `docs/PQ_CRYPTO_EVALUATION.md` — research-based comparison of ML-DSA (FIPS 204) vs SLH-DSA (FIPS 205) across digital signatures, certificate management, software signing, and API authentication. Superseded/extended by the 2025-2026 standards review (RFC 9881 / RFC 9909 / draft-ietf-lamps-pq-composite-sigs) in `docs/PQ_CRYPTO_MIGRATION_PLAN.md` §1 and the deep-research report.
- **Phase 1 (algorithm abstraction layer): IMPLEMENTED** in `app/crypto_utils.py` — `Algorithm` enum (ED25519/ML_DSA_65/SLH_DSA_128S), `PQCBackendUnavailable`, algorithm-dispatched `sign_with_private_key`/`verify_signature`/`generate_keypair`, algorithm-prefixed `public_key_fingerprint` (Ed25519 plain-hex preserved for backward compatibility), and `verify_hybrid_signature` (Phase 7). Uses liboqs-python (ML-DSA-65 + SLH-DSA pure SHAKE-128S; SHA2 pure variants fail verify on this build). Tests: `tests/test_pq_crypto.py` (7) + `tests/test_pqc_hybrid.py` (5).
- **Phase 2 (database schema updates): IMPLEMENTED** — new migration `b9c0d1e2f3a4_pq_crypto_phase2.py` adds `public_key_algorithm`/`old_public_key_algorithm`/`signing_algorithm`/`delegation_algorithm`/`signature_algorithm` columns and resizes key/signature columns to 8000. Idempotent (re-runnable). `alembic check` clean on SQLite. Tests: `tests/test_migrations.py` + `test_phase9_state_machine.py` passing.
- **Phase 2b (federation/context PQC-sized schema): IMPLEMENTED** — migration `b9c0d1e2f3a4b_pq_phase2b_federation_schema.py` resizes `federation_agreements.signature_b64` → 8000 and `signer_fingerprint` → 128, adds `federation_signers.public_key_algorithm`, resizes `payment_context_envelopes.signature_b64` → 8000 and adds `payment_context_envelopes.signature_algorithm`. All additive with `default='ed25519'`; downgrade drops columns only (never truncates stored PQC data). `SignedAgreement.signature_b64` widened to 8000. Tests: `tests/test_pqc_schema.py` (3).
- **Phase 3 (signing backend abstraction): IMPLEMENTED** — `app/pqc_signing_backends.py` (`MlDsaSigningBackend`, `SlhDsaSigningBackend`) implementing the `SigningBackend` protocol over liboqs; `algorithm` property added to the protocol and `LocalPemSigningBackend`. Tests: `tests/test_pqc_signing_backend.py` (6).
- **Phase 4 (JWT migration): IMPLEMENTED** — `app/security.py` `encode_jwt`/`decode_jwt` build a JWS manually (the signing input is `header.payload` exactly as the backend signs it) and dispatch on the header `alg`: `EdDSA` stays on PyJWT, `ML-DSA-65`/`SLH-DSA-SHA2-128S` verify via `crypto_utils.verify_signature`. All `issue_*` token functions now emit the algorithm-aware header; all `decode_*` read the `alg` header and branch — legacy `EdDSA` tokens verify byte-for-byte unchanged. `verify_request_proof` accepts PQC `X-Paari-Proof` alongside Ed25519. `KmsHsmClient`/`encode_ed25519_jwt` Ed25519 path preserved. Tests: `tests/test_pqc_jwt.py` (9).
- **Phase 5 (verification paths): IMPLEMENTED** — algorithm-aware verification threaded through `app/routers/agents.py`, `app/routers/v1.py` (register + rotate), `app/mandate_signing.py`, `app/receivers/router.py`, `app/safr/envelope.py`, `app/protocol/envelope.py`, `app/portability.py` **and now** `app/federation/policy.py` (`verify_agreement` returns a 4-tuple and verifies under the signer row's stored algorithm), `app/federation/router.py` (`enroll_signer` accepts PQC public keys), `app/federation/policy.py::verify_context` / `app/security.py::verify_agent_card` (algorithm-aware context/agent-card verification). PQC fingerprints (`ml-dsa-65:<sha256>`) are stored in the widened `signer_fingerprint` column. Tests: `tests/test_pqc_federation.py` (9).
- **Phase 6 (SDK updates): IMPLEMENTED** — `sdk/paari_agent/crypto.py` `generate_keypair`/`sign_text`/`verify_signature`/`build_envelope`/`build_request_proof`/`verify_paari_card` accept an `algorithm` argument (default `ed25519`, unchanged); PQC keys are raw-bytes base64. `scripts/v35_sign_agreement.py` gained `--algorithm {ed25519,ml-dsa-65,slh-dsa-sha2-128s}` and emits `signature_algorithm` in the output. PQC keys use `crypto_utils`/liboqs (server) or `oqs` (SDK, self-contained). Tests: `tests/test_pqc_sdk.py` (6, of which the PQC cases skip cleanly if the mechanism is disabled).
- **Phase 7 (testing/benchmarks/hybrid): IMPLEMENTED** — `crypto_utils.verify_hybrid_signature` (Model A dual-algorithm, fail-closed `require_any` window/cutover semantics) + Ed25519 backward-compat regression. Tests: `tests/test_pqc_hybrid.py` (5). NIST FIPS 204/205 golden vectors and a signed/verify throughput benchmark remain the next increment (liboqs build-dependent); round-trip + cross-algorithm rejection is covered across `test_pq_crypto.py`, `test_pqc_federation.py`, `test_pqc_hybrid.py`.

## ML-DSA (FIPS 204) vs SLH-DSA (FIPS 205) for Paari

### 1. Research-Based Comparison

#### 1.1 Algorithm Overview

| Property | ML-DSA (FIPS 204) | SLH-DSA (FIPS 205) |
|----------|-------------------|-------------------|
| **Type** | Lattice-based (Module-LWE) | Hash-based (Merkle trees) |
| **Security basis** | Module-LWE hardness | Hash function security (SHA-256/SHAKE) |
| **NIST level** | 2, 3, 5 (ML-DSA-44/65/87) | 1, 3, 5 (SLH-DSA-SHA2-128s/192s/256s) |
| **Signature size** | 2,420 / 3,309 / 4,627 bytes | 7,856 / 17,088 / 29,792 bytes (small) or 17,408 / 35,664 / 49,856 bytes (fast) |
| **Public key size** | 1,312 / 1,952 / 2,592 bytes | 32 / 48 / 64 bytes |
| **Private key size** | 2,560 / 4,032 / 4,896 bytes | 64 / 96 / 128 bytes |
| **Signing speed** | ~0.5 ms (fast) | ~10-50 ms (slow, hash-based) |
| **Verification speed** | ~0.3 ms (fast) | ~1-5 ms (moderate) |
| **Maturity** | New (2024 standard) | Conservative (hash-based, well-understood) |

#### 1.2 Suitability for Paari Use Cases

| Use Case | Recommended Algorithm | Rationale |
|----------|----------------------|-----------|
| **Agent/parent key registration** | ML-DSA-65 (Level 3) | Fast verification, moderate key size. Agents sign frequently; verifiers (Paari) need fast verification. |
| **Delegation signatures** | ML-DSA-65 | Parent signs once per delegation; Paari verifies on every agent registration. Speed matters. |
| **Paari-issued JWTs/Agent Cards** | ML-DSA-65 or Ed25519→ML-DSA hybrid | Paari signs frequently; tokens must be compact enough for HTTP headers. |
| **Audit chain signatures** | SLH-DSA-SHA2-128s (Level 1) | Audit records are long-lived; hash-based security is conservative and well-understood. Signing is infrequent. |
| **Mandate signatures (user → agent)** | ML-DSA-65 | Users sign mandates; Paari verifies on every payment. Fast verification critical. |
| **Webhook verification (HMAC)** | N/A (keep HMAC-SHA256) | Webhooks use shared secrets, not PKI. No quantum threat to symmetric crypto with 256-bit keys. |
| **SAFR envelope signatures** | ML-DSA-65 | Envelopes are signed by agents; Paari verifies before policy evaluation. |
| **Portability packages** | SLH-DSA-SHA2-128s | Long-lived identity packages; conservative security preferred. |

#### 1.3 Performance Impact Assessment

| Metric | Current (Ed25519) | ML-DSA-65 | SLH-DSA-128s | Impact |
|--------|-------------------|-----------|-------------|--------|
| Signature size | 64 bytes | 3,309 bytes | 7,856 bytes | **50x / 120x larger** |
| Public key size | 32 bytes | 1,952 bytes | 32 bytes | **61x / same** |
| Sign time | ~0.05 ms | ~0.5 ms | ~20 ms | **10x / 400x slower** |
| Verify time | ~0.05 ms | ~0.3 ms | ~2 ms | **6x / 40x slower** |
| DB storage (per agent) | ~200 bytes | ~5,300 bytes | ~7,900 bytes | **26x / 40x larger** |

#### 1.4 Key Risks
- **Signature size**: ML-DSA signatures are ~50x larger than Ed25519. HTTP headers, JWTs, and database columns must be resized.
- **Verification throughput**: At 1000 payments/sec, ML-DSA verification adds ~300ms total (vs 50ms for Ed25519). May require caching or batching.
- **Library maturity**: `liboqs` and `pqcrypto` are the primary Python bindings. `cryptography` library does not yet support ML-DSA/SLH-DSA (as of 2025).
- **Interoperability**: No standard PEM/SPKI format for PQC keys yet. X.509/PKIX extensions (RFC 9370) are in progress but not widely deployed.

---

### 2. Step-by-Step Implementation Roadmap

#### Phase 0: Preparation (Weeks 1-2)
- [ ] Install `liboqs-python` and `pqcrypto` in a virtual environment
- [ ] Benchmark ML-DSA-65 and SLH-DSA-SHA2-128s on target hardware
- [ ] Verify `cryptography` library roadmap for native PQC support
- [ ] Create a feature branch: `feat/pq-crypto-migration`

#### Phase 1: Algorithm Abstraction Layer (Weeks 3-4)
**Impact areas:**
- `app/crypto_utils.py` — Add `Algorithm` enum (ED25519, ML_DSA_65, SLH_DSA_128S)
- `app/crypto_utils.py` — Abstract `sign_with_private_key` and `verify_signature` to dispatch by algorithm
- `app/crypto_utils.py` — Add `generate_keypair(algorithm)` returning algorithm-tagged keys
- `app/crypto_utils.py` — Add `public_key_fingerprint` that includes algorithm prefix

**New code:**
```python
class Algorithm(str, Enum):
    ED25519 = "ed25519"
    ML_DSA_65 = "ml-dsa-65"
    SLH_DSA_128S = "slh-dsa-sha2-128s"

def sign_with_private_key(private_pem: str, message: str, algorithm: Algorithm = Algorithm.ED25519) -> str:
    ...

def verify_signature(public_pem: str, message: str, signature_b64: str, algorithm: Algorithm = Algorithm.ED25519) -> bool:
    ...
```

#### Phase 2: Database Schema Updates (Weeks 5-6)
**Impact areas:**
- `alembic/versions/` — New migration to add `algorithm` column to:
  - `parent_authorities.public_key_algorithm` (default: ed25519)
  - `agents.public_key_algorithm` (default: ed25519)
  - `receivers.public_key_algorithm` (default: ed25519)
  - `user_payment_mandates.signing_key_id` → add `signing_algorithm`
  - `delegation_records` → add `delegation_algorithm`
- Increase column sizes:
  - `public_key_pem`: 2000 → 8000 (ML-DSA-65 public key is 1952 bytes in PEM)
  - `signature_b64`: 500 → 8000 (ML-DSA-65 signature is 3309 bytes → ~4412 base64)
  - `signature_b64` for mandates: 500 → 8000

#### Phase 3: Signing Backend Abstraction (Weeks 7-8)
**Impact areas:**
- `app/signing_backends.py` — Add `algorithm` property to `SigningBackend` protocol
- `app/signing_backends.py` — Create `MlDsaSigningBackend` and `SlhDsaSigningBackend`
- `app/signing_backends.py` — KMS/HSM client protocol: add `sign_ml_dsa`, `sign_slh_dsa` methods
- `app/security.py` — Paari's own signing key: support algorithm selection via env var

#### Phase 4: JWT and Token Migration (Weeks 9-10)
**Impact areas:**
- `app/security.py` — `encode_ed25519_jwt` → `encode_jwt(payload, algorithm)` with alg header `ML-DSA-65` or `SLH-DSA-SHA2-128s`
- JWT `alg` header: `EdDSA` → `ML-DSA-65` / `SLH-DSA-SHA2-128s`
- Session tokens, bounded authorizations, MFA challenges, request proofs
- `sdk/paari_agent/crypto.py` — Agent-side signing with algorithm selection

#### Phase 5: Verification Path Updates (Weeks 11-12)
**Impact areas:**
- `app/routers/agents.py` — Delegation signature verification with algorithm from parent record
- `app/routers/v1.py` — Mandate signature verification with algorithm from mandate record
- `app/marketplace.py` or policy evaluation — SAFR envelope signature verification
- `app/portability.py` — Portability package signature verification
- `app/safr/envelope.py` — Envelope signature verification

#### Phase 6: SDK and Client Updates (Weeks 13-14)
**Impact areas:**
- `sdk/paari_agent/crypto.py` — Add ML-DSA/SLH-DSA key generation and signing
- `sdk/paari_agent/client.py` — Algorithm-aware signing
- `scripts/v35_sign_agreement.py` — Support `--algorithm` flag
- `demo_client.py` — Update to use new algorithms

#### Phase 7: Testing and Validation (Weeks 15-16)
- [ ] Unit tests for each algorithm (sign/verify round-trip)
- [ ] Cross-algorithm rejection tests (ML-DSA sig rejected by SLH-DSA verifier)
- [ ] Performance benchmarks (sign/verify throughput)
- [ ] Database migration tests on both SQLite and PostgreSQL
- [ ] Backward compatibility tests (Ed25519 keys still verify)
- [ ] Hybrid signature tests (Ed25519 + ML-DSA)

---

### 3. Methodology for Seamless Transition

#### 3.1 Test-First Approach (TDD)
Following the TDD skill, every change must:
1. Write a failing test first (e.g., "ML-DSA-65 signature verifies correctly")
2. Implement minimal code to pass
3. Refactor while keeping tests green
4. Never modify production code without a failing test

#### 3.2 Regression Prevention
- **Golden test vectors**: Use NIST-provided test vectors for ML-DSA and SLH-DSA to validate implementations
- **Cross-algorithm tests**: Ensure a signature from algorithm A is rejected by verifier B
- **Database migration tests**: Run `alembic check` on both SQLite and PostgreSQL after every schema change
- **Backward compat tests**: Existing Ed25519 keys must still verify after migration
- **Performance regression tests**: Sign/verify throughput must not degrade beyond 2x from baseline

#### 3.3 Rollout Strategy
1. **Phase 1-2**: Deploy schema changes (additive only, no breaking changes)
2. **Phase 3-4**: Deploy new signing backends behind feature flag (`PAARI_PQ_ALGORITHM=ml-dsa-65`)
3. **Phase 5-6**: Deploy verification path updates (algorithm-aware)
4. **Phase 7**: Enable PQC for new keys only (existing keys remain Ed25519)
5. **Phase 8**: Migrate existing keys (re-register with PQC keys)
6. **Phase 9**: Deprecate Ed25519 (with sunset window)

#### 3.4 Monitoring
- Track signature verification failure rates by algorithm
- Monitor signing/verification latency percentiles
- Alert on any algorithm mismatch errors

---

### 4. Backward Compatibility and Hybrid Schemes

#### 4.1 Hybrid Signature Design
During migration, support both Ed25519 and PQC signatures simultaneously:

```python
@dataclass
class HybridSignature:
    ed25519_sig: str | None  # Legacy
    pq_sig: str | None       # ML-DSA or SLH-DSA
    algorithm: Algorithm     # Which PQC algorithm
    
def verify_hybrid(public_pem_ed25519: str, public_pem_pq: str, message: str, sig: HybridSignature) -> bool:
    # Both must verify if both present; at least one must verify
    ed_ok = verify_ed25519(...) if sig.ed25519_sig else True
    pq_ok = verify_pq(...) if sig.pq_sig else True
    return ed_ok and pq_ok
```

#### 4.2 Key Storage
- Add `algorithm` field to all public key columns (default: `ed25519`)
- Store algorithm alongside key in PEM (use SPKI with algorithm OID when available)
- Maintain backward compatibility: Ed25519 keys continue to work without algorithm field

#### 4.3 Migration Path for Existing Keys
1. **Soft migration**: New registrations use PQC; existing keys remain Ed25519
2. **Re-registration**: Agents/parents re-register with PQC keys (old delegation revoked)
3. **Dual verification**: During transition, accept both Ed25519 and PQC signatures
4. **Sunset**: After all keys migrated, remove Ed25519 support (with grace period)

#### 4.4 Database Column Changes
```sql
-- Add algorithm tracking
ALTER TABLE parent_authorities ADD COLUMN public_key_algorithm VARCHAR(20) DEFAULT 'ed25519';
ALTER TABLE agents ADD COLUMN public_key_algorithm VARCHAR(20) DEFAULT 'ed25519';
ALTER TABLE receivers ADD COLUMN public_key_algorithm VARCHAR(20) DEFAULT 'ed25519';

-- Increase column sizes for PQC
ALTER TABLE parent_authorities ALTER COLUMN public_key_pem TYPE VARCHAR(8000);
ALTER TABLE agents ALTER COLUMN public_key_pem TYPE VARCHAR(8000);
ALTER TABLE user_payment_mandates ALTER COLUMN signature_b64 TYPE VARCHAR(8000);
ALTER TABLE delegation_records ALTER COLUMN delegation_signature_b64 TYPE VARCHAR(8000);
```

#### 4.5 JWT Algorithm Migration
- Current: `"alg": "EdDSA"`
- ML-DSA: `"alg": "ML-DSA-65"` (per draft IETF spec)
- SLH-DSA: `"alg": "SLH-DSA-SHA2-128s"`
- Support both in verification: try EdDSA first, then ML-DSA, then SLH-DSA

---

### 5. Dependencies and Library Choices

| Library | ML-DSA | SLH-DSA | Maturity | Notes |
|---------|--------|---------|----------|-------|
| `liboqs-python` | ✅ | ✅ | Beta | Primary reference implementation. C bindings. |
| `pqcrypto` | ✅ | ✅ | Beta | Pure Python + C. Simpler API. |
| `cryptography` | ❌ (planned) | ❌ (planned) | — | Will support PQC in future release. Monitor. |
| `pyca/boringssl` | ❌ | ❌ | — | No PQC support yet. |

**Recommendation**: Use `liboqs-python` as the primary backend, with `pqcrypto` as fallback. Abstract behind a `PqcSigningBackend` interface similar to the existing `SigningBackend` protocol.

---

### 6. Timeline Summary

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| 0. Preparation | 2 weeks | Benchmarking, library evaluation |
| 1. Abstraction layer | 2 weeks | Algorithm-dispatching crypto_utils |
| 2. Schema updates | 2 weeks | Alembic migrations, column resizing |
| 3. Signing backends | 2 weeks | ML-DSA/SLH-DSA signing backends |
| 4. JWT migration | 2 weeks | Algorithm-aware JWT encoding/decoding |
| 5. Verification paths | 2 weeks | All signature verification points updated |
| 6. SDK updates | 2 weeks | Agent SDK supports PQC |
| 7. Testing | 2 weeks | Full test suite + benchmarks |
| **Total** | **16 weeks** | Production-ready PQC support |

---

### 7. Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Library bugs in liboqs | Use NIST test vectors; cross-validate with pqcrypto |
| Performance regression | Benchmark before/after; cache verification results |
| Database migration failure | Test on both SQLite and PostgreSQL; use additive migrations |
| Interoperability issues | Follow IETF drafts for JWT/PKI algorithm identifiers |
| Key size causing DB bloat | Use VARCHAR(8000) which accommodates all PQC variants |
| Backward compat breakage | Dual-verify during transition; sunset Ed25519 with grace period |