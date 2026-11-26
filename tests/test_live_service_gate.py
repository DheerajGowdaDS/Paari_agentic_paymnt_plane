from __future__ import annotations

from scripts.live_e2e_test import validate_service_posture
from scripts.run_strict_sandbox_server import prepare_environment
from scripts.strict_service_gate import evaluate_gate


def _health(**overrides):
    base = {
        "service": "paari",
        "status": "ok",
        "env": "sandbox",
        "database": "up",
        "mandate_mode": "autonomous",
        "mandate_required": True,
        "require_signed_mandate": True,
        "control_plane_enforcement": True,
        "provider": "real-razorpay(test-mode)",
        "provider_environment": "test",
        "signing_backend": {"backend": "local_pem", "managed": False, "healthy": True},
        "principal_identity_provider": {"provider": None, "configured": False, "trusted_evidence": False},
    }
    base.update(overrides)
    return base


def test_live_driver_requires_strict_control_plane_by_default():
    readiness = {"status": "ready", "blocking_checks": []}
    assert validate_service_posture(_health(), 200, readiness) == []
    failures = validate_service_posture(_health(control_plane_enforcement=False), 503,
                                        {"status": "not_ready", "blocking_checks": ["control_plane_enforcement"]})
    assert any("enforcement is OFF" in item for item in failures)


def test_signed_mandate_only_requires_explicitly_limited_sandbox_posture():
    health = _health(control_plane_enforcement=False)
    readiness = {"status": "not_ready", "blocking_checks": ["control_plane_enforcement"]}
    assert validate_service_posture(health, 503, readiness,
                                    signed_mandate_only_sandbox=True) == []
    unsafe = {"status": "not_ready", "blocking_checks": ["control_plane_enforcement", "webhook_secret_present"]}
    failures = validate_service_posture(health, 503, unsafe, signed_mandate_only_sandbox=True)
    assert any("blockers other than" in item for item in failures)


def test_live_driver_rejects_non_test_provider_even_if_other_checks_pass():
    readiness = {"status": "ready", "blocking_checks": []}
    failures = validate_service_posture(_health(provider_environment="live"), 200, readiness)
    assert any("must be confirmed as test" in item for item in failures)


def test_strict_sandbox_launcher_pins_governance_flags():
    env = prepare_environment({"PAARI_ENV": "sandbox", "PAARI_MODE": "standard",
                               "PAARI_CONTROL_PLANE_ENFORCEMENT": "0",
                               "PAARI_REQUIRE_SIGNED_MANDATE": "0",
                               "PAARI_REQUIRE_USER_MANDATE": "0"})
    assert env["PAARI_CONTROL_PLANE_ENFORCEMENT"] == "1"
    assert env["PAARI_REQUIRE_SIGNED_MANDATE"] == "1"
    assert env["PAARI_REQUIRE_USER_MANDATE"] == "1"
    assert env["PAARI_MODE"] == "autonomous"


def test_strict_sandbox_launcher_refuses_production_environment():
    try:
        prepare_environment({"PAARI_ENV": "prod"})
    except ValueError as exc:
        assert "only starts PAARI_ENV=sandbox/test" in str(exc)
    else:
        raise AssertionError("production environment was accepted by sandbox launcher")


def test_service_gate_rejects_permissive_service_and_warns_about_missing_idp():
    health = _health(control_plane_enforcement=False)
    readiness = {"status": "not_ready", "blocking_checks": ["control_plane_enforcement"]}
    checks = evaluate_gate(health, 503, readiness)
    statuses = {name: passed for name, passed, _detail in checks}
    assert statuses["strict institutional control plane enabled"] is False
    assert statuses["trusted principal identity provider"] is False


def test_service_gate_requires_trusted_idp_when_requested():
    health = _health()
    readiness = {"status": "ready", "blocking_checks": []}
    checks = evaluate_gate(health, 200, readiness, require_trusted_identity_provider=True)
    idp_check = next(passed for name, passed, _detail in checks if name == "trusted principal identity provider")
    assert idp_check is False


def test_live_driver_does_not_own_or_terminate_server_and_does_not_seed_assurance():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "scripts" / "live_e2e_test.py").read_text(encoding="utf-8")
    assert "subprocess.Popen" not in source
    assert "proc.terminate()" not in source
    assert "start_server()" not in source
    assert "assurance_level = \"high\"" not in source
    assert "principal_identity_provider" in source
