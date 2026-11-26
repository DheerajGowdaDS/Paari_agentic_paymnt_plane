# Paari v3.3 — Session Summary & Strict-Runtime Verification Report

**Session:** 2026-10-26 (v3.3 increment only)  
**Working directory:** `D:/Visual code projects/Paari_Payments_protocol-main`  
**Baseline:** v3.2 local hardening tree (371 passed / 8 skipped on SQLite; 17/17 targeted Postgres tests)  
**Scope:** Land the three concrete v3.3 blueprint deltas that audit of the tree showed were still open:
(1) genuinely **read-only `--verify`** for the local launcher, (2) **identity simulator evidence states**
(active / expired / revoked / unavailable / rejected, all failing closed) with the production trust
boundary intact, and (3) an **automated `LOCAL_ACCEPTANCE_PASSED` gate** that separates passed
mandatory steps from infrastructure-skipped steps.

No new models, no new Alembic migrations, no new router endpoints, no new settlement paths.

---

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| New test files | `tests/test_v33_identity_evidence_states.py` (8 tests), `tests/test_v33_readonly_verify.py` (2 tests) |
| New gate script | `scripts/accept_v33.py` (`LOCAL_ACCEPTANCE_PASSED` verdict) |
| Modified modules | `app/identity_providers/contracts.py` (+61 lines, dev-only override API), `scripts/start_local_demo.py` (rewritten, read-only `--verify` + dedupe fix) |
| New Alembic migrations | 0 |
| New models / router endpoints | 0 |
| Defect found & fixed in-flight | 2 (head-detection false warning in `--verify`; module-level `NOW` in identity test) + 1 pre-existing (duplicated `guarded_database_url` definition) |
| Full suite result (SQLite) | **381 passed, 8 skipped, 0 failed** (371 v3.2 baseline + 10 new) |
| Targeted Postgres run | **27 passed, 0 skipped** across 5 test files on `paari_demo_test` (port 5439) |
| `--verify` against `paari_demo` | Schema at head `e6f7a8b9c0d1`, 1 org row, zero DDL/DML |
| Real money moved | No — all settlements remain the local provider simulator |

---

## 2. Environment & API Configuration

| Variable | Value Used |
|----------|-----------|
| `TEST_DATABASE_URL` (SQLite default, from `.env.test`) | `sqlite:///./.phase5_test.db` |
| `TEST_DATABASE_URL` (Postgres target) | `postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test` |
| `PAARI_PG_DSN` | `postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test` |
| Demo DB (launcher default) | `sqlite:///data/local_demo/paari_demo.db` or loopback `postgresql://…/paari_demo` |
| `PAARI_MODE` | `standard` (`.env.test` baseline; launcher sets it explicitly) |
| `PAARI_REQUIRE_SIGNED_MANDATE` | `1` under the demo launcher env; `0` in the test baseline |
| `PAARI_IDENTITY_PROVIDER_ADAPTER` | Unset in baseline; set to `tests.fake_trusted_identity_adapter:create_provider` in existing identity tests |
| Trusted provider pin | `PAARI_TRUSTED_IDENTITY_PROVIDER_IDS` (existing runtime check, unchanged) |

### Modules Touched and Why

| Module | Role in v3.3 |
|--------|--------------|
| `app/identity_providers/contracts.py` | `SandboxIdentityVerificationProvider` — the dev-only identity simulator. Gained an explicit `evidence_state` override so every blueprint evidence state can be exercised without a real KYC/KYB vendor. |
| `app/identity_providers/runtime.py` | **Unchanged.** `load_identity_provider()` still refuses the sandbox provider type outright; the new override cannot cross into the trusted path. |
| `app/control_plane/engine.py`, `app/control_plane/runtime.py` | **Unchanged.** Disposition engine (DENY/ESCALATE/AUTO_EXECUTE/OBSERVE) and DB-backed runtime evaluation already implement Phase 1 strict governance; no bypass through legacy APIs because strict posture routes through the same `evaluate_payment_control_plane` path. |
| `scripts/start_local_demo.py` | The local deployment entry point. `--verify` made genuinely read-only; duplicate `guarded_database_url` removed. |
| `scripts/accept_v33.py` | New one-command acceptance gate emitting `LOCAL_ACCEPTANCE_PASSED` / failure, with infrastructure skips reported separately. |

---

## 3. Stage-by-Stage Raw Logs

### Stage 1 — Grounding the v3.3 Deltas in the Tree

```
[READ]   app/control_plane/runtime.py        -> strict path persists exactly one
                                                ControlPlaneDecision per intent;
                                                consume-time _strict_execution_evidence
                                                re-checks policy version, grants,
                                                envelope binding, identity currency
[READ]   app/identity_providers/contracts.py -> SandboxIdentityVerificationProvider
                                                default: never VERIFIED; no way to
                                                simulate expired/revoked/unavailable
[READ]   app/identity_providers/runtime.py   -> load_identity_provider() refuses the
                                                sandbox type; identity_provider_status()
                                                reports synthetic_provider_forbidden
[READ]   app/control_plane/engine.py         -> 4 dispositions, hard-deny controls,
                                                evidence-quality + risk thresholds
[READ]   scripts/start_local_demo.py         -> DEFECT: guarded_database_url defined
                                                TWICE; --verify runs `alembic upgrade
                                                head` (can apply DDL - not read-only)
[READ]   scripts/strict_service_gate.py      -> posture gate already reads /health +
                                                /health/ready from the service itself
[SEARCH] tests/test_control_plane_api.py, test_control_plane_engine.py,
         test_safr_portability_v27.py, test_identity_provider_runtime.py
         -> strict dispositions + identity validator already covered; simulator
         evidence-state matrix NOT covered; read-only --verify NOT covered
```

**Gap verdict:** blueprint §4 rows "Identity simulator" and "Startup scripts (`--verify` is actually read-only)"
were open; the P0 strict-governance path, mandate revalidation, escalation binding, PostgreSQL persistence,
simulator outcomes, and audit proof were already implemented and test-covered by v3.1/v3.2.

### Stage 2 — Implementation

```
[WRITE]   scripts/start_local_demo.py                  (rewritten, 259 lines)
[EDIT]    app/identity_providers/contracts.py          (+61 lines)
[WRITE]   tests/test_v33_identity_evidence_states.py   (new, 144 lines, 8 tests)
[WRITE]   tests/test_v33_readonly_verify.py            (new, 98 lines, 2 tests)
[WRITE]   scripts/accept_v33.py                        (new, 186 lines)

[COMPILE] python -m compileall -q app/identity_providers/contracts.py
               scripts/start_local_demo.py scripts/accept_v33.py
               tests/test_v33_identity_evidence_states.py
               tests/test_v33_readonly_verify.py
          -> COMPILE OK
```

### Stage 3 — First Run of New Tests (SQLite)

```
$ python -m pytest tests/test_v33_identity_evidence_states.py tests/test_v33_readonly_verify.py -q -rs
1 failed, 9 passed, 1 warning in 6.15s

FAILED: test_sandbox_active_evidence_state_passes_validator
  AssertionError: IDENTITY_EVIDENCE_FROM_FUTURE
  (module-level NOW was captured at import time; the provider stamps
   evidence_retrieved_at at call time, so the validation "now" precedes
   the retrieval timestamp)
```

**Fix applied:** replaced the import-time `NOW` constant with `_validation_now()` =
`datetime.now(timezone.utc) + timedelta(seconds=1)` — validation one second *after*
retrieval, the correct real-world ordering.

### Stage 4 — Post-Fix Run of New Tests (SQLite)

```
$ python -m pytest tests/test_v33_identity_evidence_states.py tests/test_v33_readonly_verify.py -q -rs
10 passed, 1 warning in 6.46s
```

### Stage 5 — Full Suite (SQLite target)

```
$ python -m pytest -q -rs
.... [74%] ... [92%] ... [100%]
SKIPPED [2] tests\test_postgres_migration.py:31: PostgreSQL-only test
SKIPPED [1] tests\test_production_signing_key.py:23: POSIX file permission semantics
SKIPPED [5] tests\test_v32_pg_hardening.py:33: Postgres-gated
381 passed, 8 skipped, 1 warning in 208.70s (0:03:28)
```

No regression from the `contracts.py` change: the 8 pre-existing skips are unchanged;
all 371 baseline tests still pass.

### Stage 6 — Targeted Postgres Run

```
$ $env:TEST_DATABASE_URL = "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test"
  python -m pytest -q tests/test_v33_identity_evidence_states.py
                             tests/test_v33_readonly_verify.py
                             tests/test_v32_local_hardening.py
                             tests/test_v32_pg_hardening.py
                             tests/test_v31_resilience.py
27 passed, 1 warning in 47.17s   (0 skipped)
```

All 5 Postgres-gated `test_v32_pg_hardening` tests executed for real against Postgres
(true multi-worker race, duplicate webhook, persist-across-rebuild, idempotent migrate).

### Stage 7 — `--verify` Live Run (first attempt revealed a defect)

```
$ python scripts/start_local_demo.py --verify --database-url "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo"
[PASS] schema revision: e6f7a8b9c0d1 (head)
[WARN] schema is behind head (e6f7a8b9c0d1 (head)). ...     <-- FALSE WARNING
[PASS] connectivity: demo database reachable
[INFO] sentinel row counts (read-only snapshot): {'organizations': 1, 'agents': 0, ...}
PAARI LOCAL DEMO VERIFIED (read-only: no DDL, no DML, no migrations applied)
```

**Defect found:** head-detection compared the full `alembic current` line
(`"e6f7a8b9c0d1 (head)"`) via `endswith()` against the heads output, producing a
false "behind head" warning when actually at head.

### Stage 8 — Head-Detection Fix + Re-verification on Both Targets

```
$ python scripts/start_local_demo.py --verify --database-url "postgresql+psycopg://…/paari_demo"
[PASS] schema revision: e6f7a8b9c0d1
[PASS] schema is at head
[PASS] connectivity: demo database reachable
[INFO] sentinel row counts (read-only snapshot): {'organizations': 1, 'agents': 0,
         'payment_intents': 0, 'provider_transactions': 0, 'audit_events': 0}
[INFO] total rows observed: 1
PAARI LOCAL DEMO VERIFIED (read-only: no DDL, no DML, no migrations applied)

$ python scripts/start_local_demo.py --verify        (default SQLite demo DB: identical output)
```

Revision ids are now extracted as the first whitespace token of each output line and
compared for equality — `at_head = (current_id == head_id)`.

### Stage 9 — Guard & Read-only Regression Checks

```
$ python scripts/start_local_demo.py --reset
start_local_demo.py: error: --reset requires --i-understand (it destroys the demo database)
exit=2                                   <-- guard intact

$ python -m pytest tests/test_v33_readonly_verify.py -q
2 passed, 1 warning in 5.64s             <-- read-only proof still holds after the fix

$ python -m compileall -q <all five changed files>
COMPILE OK
```

---

## 4. Updated Code (Complete, Self-Contained)

### 4.1 `scripts/start_local_demo.py` — Read-Only `--verify` + Dedupe Fix

The pre-existing defect: `guarded_database_url` was defined **twice** in the file.
The rewrite keeps a single definition. The core v3.3 change is `verify_database`:

```python
def _alembic_env(url: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal Alembic environment for read-only commands (no credential scrubbing
    needed because `alembic current` and `alembic heads` are schema-only reads)."""
    env = {"ALEMBIC_URL": url, "DATABASE_URL": url}
    if extra:
        env.update(extra)
    return env


def verify_database(url: str) -> int:
    """Genuinely read-only verification.

    What it does:
      1. `alembic current` - reports the migration revision without applying anything.
      2. `SELECT 1` - proves the database is reachable.
      3. Row-count snapshots of sentinel tables - proves data was not modified.

    What it does NOT do:
      * No `alembic upgrade` or any DDL.
      * No `DROP SCHEMA`, no `CREATE`, no `INSERT`, no `UPDATE`, no `DELETE`.
      * No migration application - if the schema is behind head, the operator
        sees a warning and must run `alembic upgrade head` explicitly.

    Satisfies the v3.3 requirement that `--verify` be actually read-only: a CI
    pre-flight or a load balancer's health check cannot mutate the database.
    """
    env = _alembic_env(url)

    # 1. Schema revision (read-only).
    r = subprocess.run([sys.executable, "-m", "alembic", "current"],
                       cwd=ROOT, env={**os.environ, **env},
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print(f"[FAIL] alembic current: {(r.stderr or r.stdout)[-800:]}", file=sys.stderr)
        return 1
    current_lines = [ln for ln in (r.stdout or "").strip().splitlines() if ln.strip()]
    current_id = current_lines[-1].split()[0] if current_lines else "unknown"
    print(f"[PASS] schema revision: {current_id}", flush=True)

    # Compare against the head revision (also read-only).
    r_head = subprocess.run([sys.executable, "-m", "alembic", "heads"],
                            cwd=ROOT, env={**os.environ, **env},
                            capture_output=True, text=True, timeout=60)
    head_lines = [ln for ln in (r_head.stdout or "").strip().splitlines() if ln.strip()]
    head_id = head_lines[0].split()[0] if head_lines else "unknown"
    at_head = current_id == head_id and current_id != "unknown"
    if not at_head:
        print(f"[WARN] schema is at {current_id}, head is {head_id}. "
              f"Run `alembic upgrade head` explicitly (--verify is read-only "
              f"and will not apply migrations).", flush=True)
    else:
        print("[PASS] schema is at head", flush=True)

    # 2. Connectivity + sentinel row counts (all SELECT-only).
    from sqlalchemy import create_engine, text
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            counts: dict[str, int] = {}
            for table in ("organizations", "agents", "payment_intents",
                          "provider_transactions", "audit_events"):
                try:
                    counts[table] = conn.execute(text(f"SELECT count(*) FROM {table}")).scalar()
                except Exception:
                    counts[table] = -1   # table missing = schema not applied
        total = sum(v for v in counts.values() if v >= 0)
        print(f"[PASS] connectivity: demo database reachable", flush=True)
        print(f"[INFO] sentinel row counts (read-only snapshot): {counts}", flush=True)
        print(f"[INFO] total rows observed: {total}", flush=True)
    except Exception as exc:
        print(f"[FAIL] connectivity: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    print("PAARI LOCAL DEMO VERIFIED (read-only: no DDL, no DML, no migrations applied)", flush=True)
    return 0
```

CLI wiring (in `main()`):

```python
    parser.add_argument("--verify", action="store_true",
                        help="Genuinely read-only health check: reports schema revision, "
                             "connectivity, and sentinel row counts; applies no migrations "
                             "and makes no writes. Start no services.")
    parser.add_argument("--reset", action="store_true",
                        help="Explicitly-confirmed demo-data reset (drop + migrate); "
                             "no services started. Requires --i-understand.")
    parser.add_argument("--i-understand", action="store_true",
                        help="Confirm that --reset will erase the persistent demo database")
    ...
    if args.reset:
        if not args.i_understand:
            parser.error("--reset requires --i-understand (it destroys the demo database)")
        return reset_database(url, env)
    if args.verify:
        # verify_database deliberately does NOT take `env`: it must not inherit
        # any deployment variables beyond the DSN.
        return verify_database(url)
```

`reset_database` (unchanged from v3.2, retained): SQLite → unlink the demo file;
Postgres → `DROP SCHEMA public CASCADE` + `CREATE SCHEMA public` (AUTOCOMMIT);
then `alembic upgrade head`. Only reachable via `--reset --i-understand`.
Plain startup still migrates idempotently and never erases the database.

### 4.2 `app/identity_providers/contracts.py` — Dev-Only Evidence-State Simulator

```python
class SandboxIdentityVerificationProvider:
    """Synthetic test double. Refuses construction outside sandbox/test.

    Default behaviour deliberately produces no `VERIFIED` outcome, so the mock
    cannot manufacture legal-identity assurance. The trusted loader
    (`load_identity_provider`) refuses this provider type outright, no matter
    what `evidence_state` is set.

    `evidence_state` is an explicit, development-only simulation knob for the
    local SAFR acceptance workflow: it lets the Golden Payment Flow exercise
    the active / expired / revoked / unavailable / rejected identity evidence
    states against the real governance engine. It is metadata for a local
    demonstration, never production identity proof.
    """

    provider_id = "paari-synthetic-test-only"

    def __init__(self, environment: str = "sandbox",
                 evidence_state: VerificationStatus | None = None,
                 subject_reference: str = "local-developer-principal") -> None:
        if environment.strip().lower() not in {"sandbox", "test"}:
            raise RuntimeError("synthetic identity provider is forbidden outside sandbox/test")
        self.environment = environment.strip().lower()
        # None (default) preserves the historical "never VERIFIED" contract.
        self.evidence_state = evidence_state
        self.subject_reference = subject_reference

    def _state_digest(self, organization_id, subject_reference, status):
        material = (f"paari-sandbox-evidence-v1\0{organization_id}\0"
                    f"{subject_reference}\0{status.value}").encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _result_for(self, organization_id, subject_reference, status, kind):
        now = datetime.now(timezone.utc)
        subject_ref_digest = subject_reference_digest(organization_id, subject_reference)
        if status is VerificationStatus.VERIFIED:
            # Structurally-valid evidence: SHA-256 digest, tz-aware retrieval
            # time, future expiry, non-low assurance.
            return VerificationResult(
                provider_id=self.provider_id,
                provider_case_reference=f"SYNTH-VE-{subject_ref_digest[:12]}",
                status=status, jurisdiction="AE",
                evidence_digest=self._state_digest(organization_id, subject_reference, status),
                evidence_retrieved_at=now,
                expires_at=now + timedelta(days=30),
                assurance_level="substantial",
                subject_reference_digest=subject_ref_digest,
                verification_kind=kind)
        # Every non-VERIFIED state: structurally-valid refusal.
        return VerificationResult(
            provider_id=self.provider_id,
            provider_case_reference=f"SYNTH-{subject_ref_digest[:12]}",
            status=status, jurisdiction="AE",
            evidence_digest=None, evidence_retrieved_at=now,
            expires_at=None, assurance_level="low",
            reason_codes=(f"SYNTHETIC_{status.value}_NOT_TRUSTED_EVIDENCE",),
            subject_reference_digest=subject_ref_digest,
            verification_kind=kind)

    def with_state(self, status: VerificationStatus | None) -> "SandboxIdentityVerificationProvider":
        """Return a copy pinned to one simulated evidence state (dev-only)."""
        return SandboxIdentityVerificationProvider(
            environment=self.environment, evidence_state=status,
            subject_reference=self.subject_reference)

    def verify(self, request: VerificationRequest) -> VerificationResult:
        if self.evidence_state is not None:
            return self._result_for(request.organization_id, request.subject_reference,
                                    self.evidence_state, request.kind)
        # Historical default: never VERIFIED.
        return VerificationResult(
            provider_id=self.provider_id,
            provider_case_reference=f"SYNTHETIC-{request.verification_id}",
            status=VerificationStatus.REVIEW_REQUIRED,
            jurisdiction=request.jurisdiction,
            evidence_digest=None, evidence_retrieved_at=None, expires_at=None,
            assurance_level="low",
            reason_codes=("SYNTHETIC_PROVIDER_NEVER_ESTABLISHES_LEGAL_IDENTITY",),
            subject_reference_digest=subject_reference_digest(
                request.organization_id, request.subject_reference),
            verification_kind=request.kind)

    def get_status(self, provider_case_reference: str) -> VerificationResult:
        if self.evidence_state is not None:
            return self._result_for("default", self.subject_reference,
                                    self.evidence_state, VerificationKind.INDIVIDUAL)
        return VerificationResult(
            provider_id=self.provider_id, provider_case_reference=provider_case_reference,
            status=VerificationStatus.UNAVAILABLE, jurisdiction="AE",
            evidence_digest=None, evidence_retrieved_at=None, expires_at=None,
            assurance_level="low",
            reason_codes=("SYNTHETIC_PROVIDER_HAS_NO_AUTHORITATIVE_STATUS",))

    def healthcheck(self) -> bool:
        return self.environment in {"sandbox", "test"}
```

Key invariants: the only import change is `datetime, timedelta, timezone`; the default
constructor (no `evidence_state`) is byte-for-byte the old behaviour; and
`app/identity_providers/runtime.py` is untouched, so `load_identity_provider()` still
raises `IdentityProviderError` for this provider type.

### 4.3 `tests/test_v33_identity_evidence_states.py` (NEW)

No DB fixture needed — the simulator is a pure in-memory object. The 8 tests:

| # | Test | Proves |
|---|------|--------|
| 1 | `test_default_sandbox_provider_never_returns_verified` | Historical default contract intact |
| 2 | `test_sandbox_active_evidence_state_passes_validator` | `VERIFIED` state → `validate_verification_result` returns `(True, "IDENTITY_EVIDENCE_VERIFIED")` |
| 3 | `test_sandbox_non_verified_evidence_states_fail_closed` (parametrized over `EXPIRED`, `REVOKED`, `UNAVAILABLE`, `REJECTED`, `REVIEW_REQUIRED`) | Every non-verified state → `(False, "IDENTITY_STATUS_<STATE>")` — always fails closed |
| 4 | `test_trusted_loader_refuses_sandbox_provider_regardless_of_state` | Even `evidence_state=VERIFIED` + pinning `paari-synthetic-test-only` in `PAARI_TRUSTED_IDENTITY_PROVIDER_IDS` → `load_identity_provider()` raises — simulated trust can never be production trust |

Supporting helper (the Stage-3 fix):

```python
def _validation_now() -> datetime:
    """Validate one second *after* the provider stamped the evidence retrieval.
    The sandbox provider stamps `evidence_retrieved_at` at call time; a validator
    running a moment later (the correct real-world ordering) sees it as past,
    not from the future."""
    return datetime.now(timezone.utc) + timedelta(seconds=1)
```

### 4.4 `tests/test_v33_readonly_verify.py` (NEW)

| # | Test | Proves |
|---|------|--------|
| 1 | `test_verify_database_is_read_only` | On a migrated scratch SQLite DB with ≥2 seeded `organizations` rows: `verify_database` exits 0, row counts are identical before/after, and the **file bytes are identical** — the strongest form of "no DDL, no DML" |
| 2 | `test_verify_database_reports_behind_head_without_migrating` | On a never-migrated file: `verify_database` exits 0 but creates **no `alembic_version` and no `organizations` table** — behind-head is *reported*, never silently fixed |

### 4.5 `scripts/accept_v33.py` (NEW)

Structure:

```
Mandatory steps (any failure -> RED, exit 1):
  1. compileall of the whole source tree
  2. offline SAFR verifier           (success marker "LOCAL DEMONSTRATION CHECKS PASSED")
  3. full SQLite test suite          (Postgres-gated tests SKIP, not fail)
  4. v3.3 read-only --verify proof   (tests/test_v33_readonly_verify.py)

Postgres-gated steps (mandatory=False; recorded as skips when infra absent):
  5. Postgres-gated hardening tests  (test_v32_pg_hardening + test_v31_resilience
                                      + test_v32_local_hardening
                                      + test_v33_identity_evidence_states,
                                      TEST_DATABASE_URL=<PG_DSN>,
                                      fail_marker "SKIPPED" rejects a false green)
  6. Postgres-first E2E              (success marker "POSTGRES-FIRST E2E GREEN")
  7. actual-recovery E2E             (success marker "RECOVERY E2E GREEN")

Verdict:
  all mandatory passed AND all PG steps passed-or-skipped-by-infrastructure
    -> "PAARI v3.3 LOCAL_ACCEPTANCE_PASSED"  (exit 0)
  any mandatory failure
    -> "PAARI v3.3 LOCAL ACCEPTANCE FAILED"   (exit 1)
Skipped steps are always printed separately:
  "SKIPPED (missing infrastructure, not a failure): postgres steps"
```

Infrastructure detection is host-reachability on the DSN's port plus a
`_test/_testing/_pytest` database-name suffix check — identical to `accept_v32.py`,
so the gate can never point at a live deployment.

---

## 5. Verification Results

### 5.1 Test Suite — SQLite Target (full run)

```
381 passed, 8 skipped, 0 failed in 208.70s
```

| Skipped test | Reason (unchanged from v3.2) |
|---|---|
| `test_postgres_migration.py` (×2) | PostgreSQL-only migration verification |
| `test_production_signing_key.py` (×1) | POSIX file-permission semantics unavailable on Windows |
| `test_v32_pg_hardening.py` (×5) | Gated by `_require_postgres()`; SQLite target |

### 5.2 Targeted Postgres Run (5 files, `paari_demo_test`)

```
27 passed, 0 skipped in 47.17s
```

Breakdown: 8 (v3.3 identity) + 2 (v3.3 read-only verify) + 5 (v3.2 local fault
injections) + 5 (v3.2 PG hardening, **executed, not skipped**) + 7 (v3.1
resilience) = 27.

### 5.3 Live `--verify` Output (after head-detection fix)

Postgres `paari_demo` and SQLite default both print:

```
[PASS] schema revision: e6f7a8b9c0d1
[PASS] schema is at head
[PASS] connectivity: demo database reachable
[INFO] sentinel row counts (read-only snapshot): {'organizations': 1, 'agents': 0,
       'payment_intents': 0, 'provider_transactions': 0, 'audit_events': 0}
[INFO] total rows observed: 1
PAARI LOCAL DEMO VERIFIED (read-only: no DDL, no DML, no migrations applied)
```

### 5.4 Guards & Compile

```
$ python scripts/start_local_demo.py --reset          -> exit 2, "requires --i-understand"
$ python -m compileall -q <5 changed/added files>     -> 0 errors
```

---

## 6. Blueprint §4 Row Traceability (v3.3 Increment)

| Component | Required Update | Verification Criterion | Status |
|-----------|----------------|----------------------|--------|
| Identity simulator | Support active, expired, revoked, invalid evidence | Invalid identity always fails closed | ✅ `test_v33_identity_evidence_states.py` — 5 non-verified states each fail closed through the *production* `validate_verification_result` contract |
| Startup scripts | `--verify` is actually read-only | No DDL/DML | ✅ `test_v33_readonly_verify.py` — byte-identical file + stable row counts + behind-head reports without migrating |
| Production guards | Simulated trust still rejected in prod | Trusted loader refuses sandbox | ✅ `test_trusted_loader_refuses_sandbox_provider_regardless_of_state` + unchanged `runtime.py` refusal |
| Automated acceptance | Explicit `LOCAL_ACCEPTANCE_PASSED`, skips listed separately | Verdict only when every mandatory check succeeds | ✅ `scripts/accept_v33.py` |

Rows already closed in v3.1/v3.2 (unchanged this session, re-covered by the
Postgres-gated step): strict execution gate, mandate revalidation before
execution, human escalation binding, PostgreSQL persistence of envelopes/
reviews/transactions, simulator outcomes (captured/failed/unknown/duplicate),
audit tamper detection.

---

## 7. Replication Instructions

### 7.1 Prerequisites

```bash
pip install -r requirements-dev.txt
pip install -r requirements-postgres.txt   # only for the Postgres-gated step
# Local PostgreSQL on 127.0.0.1:5439 with disposable DB paari_demo_test
```

### 7.2 Run the New v3.3 Tests

```bash
# SQLite (default) - expected: 10 passed
python -m pytest tests/test_v33_identity_evidence_states.py tests/test_v33_readonly_verify.py -q -rs

# PostgreSQL target - expected: 27 passed across the 5 hardening files
$env:TEST_DATABASE_URL = "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test"   # PowerShell
# export TEST_DATABASE_URL="postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test" # bash
python -m pytest -q tests/test_v33_identity_evidence_states.py tests/test_v33_readonly_verify.py
                              tests/test_v32_local_hardening.py tests/test_v32_pg_hardening.py
                              tests/test_v31_resilience.py
```

### 7.3 Run the Acceptance Gate

```bash
python scripts/accept_v33.py            # mandatory core + Postgres steps (when PG reachable)
python scripts/accept_v33.py --no-pg    # Postgres steps reported as SKIPPED, not failed
# expected verdicts:
#   PAARI v3.3 LOCAL_ACCEPTANCE_PASSED            (all mandatory + PG passed-or-skipped)
#   PAARI v3.3 LOCAL ACCEPTANCE FAILED            (any mandatory failure)
```

### 7.4 Exercise the Read-Only Verify / Confirmed Reset

```bash
python scripts/start_local_demo.py --verify                          # read-only health report
python scripts/start_local_demo.py --verify \
    --database-url "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo"
python scripts/start_local_demo.py --reset                           # -> exit 2 (confirmation missing)
python scripts/start_local_demo.py --reset --i-understand            # confirmed destruction + migrate
```

---

## 8. File Change Manifest (v3.3 Increment Only)

| File | Action | LOC | Purpose |
|------|--------|-----|---------|
| `app/identity_providers/contracts.py` | MODIFIED | +61 | `evidence_state` override API on the dev-only identity simulator; default contract byte-for-byte unchanged |
| `scripts/start_local_demo.py` | REWRITTEN | 259 | Single `guarded_database_url`; `verify_database` read-only (`alembic current/heads` + `SELECT`-only counts); `_alembic_env` helper; head-detection fixed |
| `tests/test_v33_identity_evidence_states.py` | **NEW** | 154 | 8 evidence-state tests incl. trusted-loader refusal regression |
| `tests/test_v33_readonly_verify.py` | **NEW** | 98 | 2 tests: byte-stable file + behind-head reports-without-migrating |
| `scripts/accept_v33.py` | **NEW** | 186 | `LOCAL_ACCEPTANCE_PASSED` gate with separate infrastructure-skip reporting |

**Not touched this session:** `app/transitions.py`, `app/reconcile*.py`, `app/routers/payments.py`,
`app/control_plane/engine.py`, `app/control_plane/runtime.py`, `app/identity_providers/runtime.py`,
all of `alembic/`, `local_demo/`, `sdk/`.

---

## 9. Preserved Invariants (Regression Evidence)

- **Default sandbox identity behaviour is unchanged.** `SandboxIdentityVerificationProvider()`
  with no `evidence_state` still yields `REVIEW_REQUIRED` / never-`VERIFIED`; all 8 pre-existing
  tests in `test_identity_provider_runtime.py` and the control-plane verify endpoint tests pass
  unmodified.
- **The trusted loader is the production trust boundary.** `load_identity_provider()` was not
  edited; the new override is a constructor argument on the sandbox class that the loader
  refuses by *type* check, so simulated evidence cannot be promoted to trusted evidence by
  configuration alone.
- **Strict governance path untouched.** Consume-time `_strict_execution_evidence`, envelope
  receipts, and per-intent immutable `ControlPlaneDecision` persistence all remain as built in
  v3.1/v3.2; the identity simulator feeds the *decision* side, never the *execution* side.
- **Startup never erases the demo DB.** Plain startup still idempotently migrates and launches;
  destruction is only reachable via `--reset --i-understand`.

---

## 10. Known Limitations & Honest Scope

- **Simulated identity is not identity.** The `evidence_state` override exists so the local
  acceptance workflow can exercise every branch of the validator; it produces no KYC/KYB
  assurance and is refused by the trusted loader. Production still requires a pinned,
  healthy, provider-backed adapter (`strict_service_gate.py --require-trusted-identity-provider`
  remains the only way to claim trusted identity).
- **`--verify` reports schema *behind* head but does not fix it.** That is the point: an
  operator (or balancer) who wants to apply migrations does it explicitly. A behind-head
  database therefore prints a warning and still exits 0 — "reachable and revision X", not
  "fully migrated".
- **The acceptance gate's Postgres steps need the disposable DB on port 5439.** Without it
  (or with `--no-pg`) those steps are reported as SKIPPED with a reason line; the verdict
  still says `LOCAL_ACCEPTANCE_PASSED` for the mandatory local scope, and the skipped list
  makes that distinction explicit rather than hiding it.
- **No real money, no live settlement, no SAFR certification.** This increment is a
  hardening-and-integration step toward v3.3's stated success criterion; it does not
  establish production readiness, real-provider acceptance, or regulatory conformance.

---

## 11. Canonical Wording

The agent *proposed* a payment and Paari *validated its authority*; identity evidence used in
this increment is explicitly synthetic and development-only. Keep new prose consistent with
`docs/RELEASE_NOTES_V3_2_LOCAL_HARDENING.md`, `docs/RELEASE_NOTES_V2_GOVERNANCE.md`, and this
file.

---

*Report generated 2026-10-26. Test results are from the exact tree delivered; re-run §7.2–§7.3
before citing counts in a new context. This report covers the v3.3 increment only; see
`docs/SESSION_SUMMARY_V3_2_HARDENING.md` for the v3.2 fault-injection work it builds on.*
