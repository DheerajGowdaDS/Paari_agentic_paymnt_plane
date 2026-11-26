"""Regression tests for the P0 acceptance-integrity fix.

The v3.3.1 acceptance scripts had three defects (all P0):
  * `accept_v33.py::step()` and `accept_v33_pipeline.py::_run_step()` ignored a
    step's exit code whenever a success-marker was printed, so a process that
    printed its "GREEN" banner and then crashed was classified as passed.
  * the pipeline's step-1 marker `LOCAL_ACCEPTANCE_PASSED` is a substring of the
    downgraded verdict `LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_SKIPPED`, so a
    skipped-Postgres run could register as a full pass.
  * `_transaction_evidence()` queried a `transaction_id` column that does not
    exist on `provider_transactions`, so the "actual settled rows" section
    always errored.

These tests pin the corrected behaviour so the defects cannot regress:
a marker + non-zero exit must FAIL, the downgraded verdict must NOT satisfy
the full-pass marker, and the evidence query must reference only real columns.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pipeline_marker_present_but_nonzero_exit_fails():
    """A step that prints its verdict marker but exits non-zero must NOT pass."""
    mod = _load_module("_accept_v33_pipeline_test", ROOT / "scripts" / "accept_v33_pipeline.py")
    cmd = [sys.executable, "-c", "import sys; print('POSTGRES-FIRST E2E GREEN'); sys.exit(3)"]
    step = mod._run_step("synthetic", cmd, verdict_marker="POSTGRES-FIRST E2E GREEN")
    assert step["exit_code"] == 3
    assert step["verdict_marker_found"] is True      # the marker text was printed
    assert step["passed"] is False, "marker + non-zero exit must not pass"


def test_pipeline_marker_exact_and_zero_exit_passes():
    mod = _load_module("_accept_v33_pipeline_test2", ROOT / "scripts" / "accept_v33_pipeline.py")
    cmd = [sys.executable, "-c", "import sys; print('POSTGRES-FIRST E2E GREEN'); sys.exit(0)"]
    step = mod._run_step("synthetic-ok", cmd, verdict_marker="POSTGRES-FIRST E2E GREEN")
    assert step["exit_code"] == 0
    assert step["verdict_marker_found"] is True
    assert step["passed"] is True


def test_pipeline_downgraded_verdict_is_not_full_pass():
    """The downgraded verdict must NOT satisfy the full-pass marker."""
    mod = _load_module("_accept_v33_pipeline_test3", ROOT / "scripts" / "accept_v33_pipeline.py")
    cmd = [sys.executable, "-c",
           "import sys; print('PAARI v3.3 LOCAL_ACCEPTANCE_PASSED_WITH_POSTGRES_SKIPPED (downgraded verdict)'); sys.exit(0)"]
    step = mod._run_step("accept_v33", cmd, verdict_marker="LOCAL_ACCEPTANCE_PASSED")
    # The boundary-aware match must NOT treat the downgraded verdict as a full pass.
    assert step["verdict_marker_found"] is False, (
        "downgraded verdict must not satisfy the full-pass marker "
        "(substring false-green regression)")
    assert step["passed"] is False


def test_gate_step_marker_present_but_nonzero_exit_fails():
    """accept_v33.py::step() must require both the marker AND exit code 0."""
    mod = _load_module("_accept_v33_test", ROOT / "scripts" / "accept_v33.py")
    # Reset the module-level recorders so the step's bookkeeping is isolated.
    mod.failures = []
    mod.mandatory_pass = []
    ok = mod.step("synthetic-gate", [sys.executable, "-c",
                  "import sys; print('passed'); sys.exit(1)"],
                  success_marker="passed")
    assert ok is False, "gate step with marker + exit 1 must fail"
    assert "synthetic-gate" in mod.failures


def test_gate_step_zero_exit_passes():
    mod = _load_module("_accept_v33_test2", ROOT / "scripts/accept_v33.py")
    mod.failures = []
    mod.mandatory_pass = []
    ok = mod.step("synthetic-gate-ok", [sys.executable, "-c",
                                        "import sys; print('passed'); sys.exit(0)"],
                  success_marker="passed")
    assert ok is True
    assert "synthetic-gate-ok" in mod.mandatory_pass


def test_transaction_evidence_query_uses_real_columns():
    """The evidence SQL must not reference a `transaction_id` column on
    provider_transactions; it must join payment_intents (which owns it)."""
    src = (ROOT / "scripts" / "accept_v33_pipeline.py").read_text(encoding="utf-8")
    # Find the _transaction_evidence function body.
    m = re.search(r"def _transaction_evidence\(\).*?(?=\n    except|\n    return|\ndef |\n\n\ndef )",
                  src, re.DOTALL)
    body = m.group(0) if m else src
    assert "JOIN payment_intents" in body, "evidence must join payment_intents for transaction_id"
    # No bare `transaction_id` selected straight off provider_transactions.
    assert re.search(r"SELECT\s+authorization_id,\s*transaction_id,.*FROM\s+provider_transactions\b",
                     body) is None, "must not SELECT transaction_id directly from provider_transactions"


def test_pipeline_requires_valid_evidence_for_green():
    """When PG is reachable, a GREEN verdict requires evidence_ok (not just step passes)."""
    mod = _load_module("_accept_v33_pipeline_test4", ROOT / "scripts" / "accept_v33_pipeline.py")
    src = (ROOT / "scripts" / "accept_v33_pipeline.py").read_text(encoding="utf-8")
    # The verdict gate must reference evidence_ok.
    assert "evidence_ok" in src
    assert re.search(r"passed\s*=\s*all\(s\.get\(\"passed\"\)\s+for\s+s\s+in\s+steps\)\s+and\s+pg_on\s+and\s+evidence_ok",
                     src) is not None, "pipeline_green must require evidence_ok when PG is reachable"
