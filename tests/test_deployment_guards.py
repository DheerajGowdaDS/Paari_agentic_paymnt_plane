from app.config import PaariEnv
from app.main import PRODUCTION_API_BASE, startup_guards


def _production_env(monkeypatch):
    monkeypatch.setenv("RAZORPAY_API_BASE", PRODUCTION_API_BASE)
    monkeypatch.setenv("PAARI_CONTROL_PLANE_ENFORCEMENT", "1")
    monkeypatch.setenv("PAARI_REQUIRE_SIGNED_MANDATE", "1")
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "A" * 48)
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_live_example")


def test_prod_live_rejects_short_admin_key_and_test_provider_key(monkeypatch):
    _production_env(monkeypatch)
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "short")
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_example")
    config = {"env": PaariEnv.PROD_LIVE, "is_live": True,
              "database_url": "postgresql://paari:secret@localhost/paari",
              "mandate_required": True}

    reasons = startup_guards(config)
    assert any("PAARI_ADMIN_API_KEY" in reason for reason in reasons)
    assert any("rzp_live_*" in reason for reason in reasons)


def test_prod_live_still_fails_closed_on_unimplemented_identity_and_managed_signing(monkeypatch):
    _production_env(monkeypatch)
    config = {"env": PaariEnv.PROD_LIVE, "is_live": True,
              "database_url": "postgresql://paari:secret@localhost/paari",
              "mandate_required": True}
    reasons = startup_guards(config)
    assert any("no managed KMS/HSM signing adapter" in reason for reason in reasons)
    assert any("no trusted KYC/KYB identity-provider adapter" in reason for reason in reasons)
    assert not any("PostgreSQL" in reason or "RAZORPAY_API_BASE" in reason
                   or "PAARI_ADMIN_API_KEY" in reason or "rzp_live_*" in reason
                   or "CONTROL_PLANE_ENFORCEMENT" in reason
                   or "REQUIRE_SIGNED_MANDATE" in reason for reason in reasons)


def test_paypal_production_uses_paypal_live_endpoint_not_razorpay(monkeypatch):
    _production_env(monkeypatch)
    monkeypatch.setenv("PAARI_DEFAULT_PROVIDER", "paypal")
    monkeypatch.setenv("PAYPAL_ENV", "live")
    monkeypatch.setenv("PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    config = {"env": PaariEnv.PROD_LIVE, "is_live": True,
              "database_url": "postgresql://paari:secret@localhost/paari",
              "mandate_required": True}

    reasons = startup_guards(config)
    assert any("PAYPAL_API_BASE" in reason for reason in reasons), reasons
    assert not any("RAZORPAY_API_BASE" in reason or "rzp_live_*" in reason for reason in reasons)

    monkeypatch.setenv("PAYPAL_API_BASE", "https://api-m.paypal.com")
    reasons = startup_guards(config)
    assert not any("PAYPAL_API_BASE" in reason for reason in reasons)
