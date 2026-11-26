"""Regression coverage for the corrected v2.9 distributable, no external APIs."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app.safr.envelope import GovernanceEnvelope
from scripts import live_e2e_test as live
from tests._schema_validator import assert_schema_supported, validate

ROOT = Path(__file__).resolve().parents[1]


def test_governance_schema_example_matches_supported_subset_and_runtime_contract():
    schema = json.loads((ROOT / "schemas/paari-safr-governance-envelope.v1.schema.json").read_text())
    assert_schema_supported(schema)
    assert len(schema["examples"]) == 1
    instance = schema["examples"][0]
    validate(instance, schema)
    envelope = GovernanceEnvelope.model_validate(instance)
    assert envelope.action_context.resource_id == envelope.resource_id
    assert envelope.action_type == "payment.execute"
    for item in ("action_context", "trace", "evidence_refs"):
        assert item in schema["properties"]


def test_schema_and_runtime_reject_invalid_envelope_content():
    schema = json.loads((ROOT / "schemas/paari-safr-governance-envelope.v1.schema.json").read_text())
    example = schema["examples"][0]
    invalid = json.loads(json.dumps(example))
    invalid["action_context"]["currency"] = "BAD-CURRENCY"
    with pytest.raises(AssertionError):
        validate(invalid, schema)
    invalid = json.loads(json.dumps(example))
    invalid["action_context"]["amount_minor_units"] = 9_000_000_000_000_001
    with pytest.raises(AssertionError, match="maximum"):
        validate(invalid, schema)
    with pytest.raises(ValueError):
        GovernanceEnvelope.model_validate(invalid)
    invalid = json.loads(json.dumps(example))
    invalid["evidence_refs"] = [{"evidence_id": "ev", "evidence_type": "other", "source": "test", "digest": "a" * 64}] * 33
    with pytest.raises(AssertionError, match="maxItems"):
        validate(invalid, schema)
    with pytest.raises(ValueError):
        GovernanceEnvelope.model_validate(invalid)


def test_live_driver_keys_support_sdk_and_signature_verification():
    priv, pub = live.generate_keypair()
    assert priv.startswith("-----BEGIN PRIVATE KEY-----")
    assert pub.startswith("-----BEGIN PUBLIC KEY-----")
    key = serialization.load_pem_public_key(pub.encode())
    payload = {"parent_id": "test", "delegation_id": "test-delegation"}
    signature = base64.b64decode(live.sign_delegation(priv, payload), validate=True)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    key.verify(signature, canonical)
    from paari_agent.crypto import sign_text
    key.verify(base64.b64decode(sign_text(priv, "signed-mandate")), b"signed-mandate")


def test_live_driver_proofs_bound_to_method_path_token_and_unique_jti():
    priv, pub = live.generate_keypair()
    client = SimpleNamespace(private_key_pem=priv, agent_id="agent-123", session_token="test-only-session")
    path = "/v1/payments/authorizations/A/consume"
    headers1 = live.signed_agent_headers(client, "POST", path)
    headers2 = live.signed_agent_headers(client, "POST", path)
    assert headers1["Authorization"] == "Bearer test-only-session"
    assert headers1["X-Paari-Proof"] != headers2["X-Paari-Proof"]
    claims = jwt.decode(headers1["X-Paari-Proof"], pub, algorithms=["EdDSA"], options={"verify_aud": False})
    assert claims["htm"] == "POST"
    assert claims["htu"] == path
    assert claims["sub"] == "agent-123"
    assert claims["ath"] == base64.urlsafe_b64encode(hashlib.sha256(client.session_token.encode()).digest()).rstrip(b"=").decode()
    with pytest.raises(ValueError, match="authenticate"):
        live.signed_agent_headers(SimpleNamespace(session_token="", agent_id="X"), "GET", path)
    with pytest.raises(ValueError, match="exact absolute"):
        live.signed_agent_headers(client, "GET", "https://example.com/v1/proof")


def test_limited_mode_script_sends_proofs_and_required_json_to_all_endpoints(monkeypatch, capsys):
    """Network-free integration regression reproducing the three original driver bugs."""
    import paari_agent.client as sdk_client

    monkeypatch.setattr(live, "load_env", lambda: None)
    monkeypatch.setattr(live, "fetch_service_posture", lambda *_: (
        {"service": "paari", "status": "ok", "env": "sandbox", "database": "up",
         "provider_environment": "test", "provider": "real-razorpay(test-mode)",
         "require_signed_mandate": True, "control_plane_enforcement": False,
         "signing_backend": {"managed": False}, "principal_identity_provider": {"configured": False}},
        503, {"status": "not_ready", "blocking_checks": ["control_plane_enforcement"]},
    ))
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "mock-admin-key-for-offline-test")
    monkeypatch.setenv("PAARI_WEBHOOK_URL", "https://example.invalid/v1/payments/webhooks/razorpay")
    monkeypatch.setenv("RAZORPAY_KEY_ID", "rzp_test_fake-public-id")
    proof_jtis = set()
    paths_checked = []

    class FakeSdkClient:
        def __init__(self, base_url, private_key_pem, public_key_pem):
            assert private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
            self.private_key_pem, self.public_key_pem = private_key_pem, public_key_pem
            self.session_token, self.agent_id = None, None

        def register(self, **kwargs):
            assert kwargs["delegation_signature_b64"]
            self.agent_id = "agent-offline"

        def authenticate(self):
            self.session_token = "offline-access-token"

    monkeypatch.setattr(sdk_client, "PaariAgentClient", FakeSdkClient)

    def response(payload):
        return httpx.Response(200, json=payload)

    def check_proof(url, method, headers):
        path = url.removeprefix(live.BASE)
        assert headers and headers.get("Authorization") == "Bearer offline-access-token"
        token = headers.get("X-Paari-Proof")
        assert token, f"missing sender proof on {path}"
        # Decode without signature here: exact cryptographic verification is covered above.
        claims = jwt.decode(token, options={"verify_signature": False})
        assert (claims["htm"], claims["htu"]) == (method, path)
        assert claims["jti"] not in proof_jtis
        proof_jtis.add(claims["jti"])
        paths_checked.append(path)

    def fake_post(url, *, json=None, headers=None, **kwargs):
        path = url.removeprefix(live.BASE)
        if path == "/parents/register": return response({"parent_id": "parent-offline"})
        if path == "/parents/parent-offline/approve": return response({"status": "active"})
        if path == "/v1/mandates":
            assert json["mandate_signature_b64"]
            return response({"mandate_id": json["mandate_id"], "status": "active"})
        check_proof(url, "POST", headers)
        if path == "/v1/payments/intent":
            return response({"transaction_id": "TXN-offline", "decision": "allow",
                             "authorization": {"authorization_id": "AUTH-offline"}})
        assert path == "/v1/payments/authorizations/AUTH-offline/consume"
        assert json == {}, "consume endpoint requires an explicit empty JSON body"
        return response({"state": "PROVIDER_SUBMITTED", "razorpay_order_id": "order_Test123"})

    def fake_get(url, *, headers=None, **kwargs):
        check_proof(url, "GET", headers)
        if "/audit/" in url: return response({"chain_verified": True, "events": []})
        return response({"artifacts": {"payment_result": {"final_state": "PROVIDER_SUBMITTED"},
                                        "audit_record": {"chain_verified": True}}})

    monkeypatch.setattr(live.httpx, "post", fake_post)
    monkeypatch.setattr(live.httpx, "get", fake_get)
    assert live.main(["--signed-mandate-only-sandbox"]) == 0
    assert paths_checked == ["/v1/payments/intent", "/v1/payments/authorizations/AUTH-offline/consume",
                             "/v1/audit/TXN-offline", "/v1/proof/TXN-offline"]
    assert "Current state is only PROVIDER_SUBMITTED" in capsys.readouterr().out


def test_strict_live_path_rejects_untrusted_identity_and_unmanaged_signer(monkeypatch, capsys):
    monkeypatch.setattr(live, "load_env", lambda: None)
    monkeypatch.setenv("PAARI_ADMIN_API_KEY", "mock-admin-key-for-offline-test")
    monkeypatch.setenv("PAARI_WEBHOOK_URL", "https://example.invalid/v1/payments/webhooks/razorpay")
    monkeypatch.setenv("PAARI_REQUIRE_SAFR_ENVELOPE", "1")
    health = {"service": "paari", "status": "ok", "env": "sandbox", "database": "up",
              "provider_environment": "test", "provider": "real-razorpay(test-mode)",
              "require_signed_mandate": True, "control_plane_enforcement": True,
              "signing_backend": {"managed": False, "healthy": True},
              "principal_identity_provider": {"configured": True, "trusted_evidence": False, "healthy": True}}
    monkeypatch.setattr(live, "fetch_service_posture", lambda *_: (health, 200, {"status": "ready"}))
    assert live.main([]) == 2
    assert "explicitly trusted" in capsys.readouterr().err
    health["principal_identity_provider"] = {"configured": True, "trusted_evidence": True, "healthy": True}
    assert live.main([]) == 2
    assert "managed KMS/HSM signer" in capsys.readouterr().err


def test_strict_preflight_reports_missing_external_integrations(monkeypatch, capsys):
    monkeypatch.setattr(live, "load_env", lambda: None)
    monkeypatch.delenv("PAARI_REQUIRE_SAFR_ENVELOPE", raising=False)
    health = {"service": "paari", "status": "ok", "env": "sandbox", "database": "up",
              "provider_environment": "test", "provider": "real-razorpay(test-mode)",
              "require_signed_mandate": True, "control_plane_enforcement": True,
              "signing_backend": {"managed": False, "healthy": True},
              "principal_identity_provider": {"configured": False}}
    monkeypatch.setattr(live, "fetch_service_posture", lambda *_: (health, 200, {"status": "ready"}))
    assert live.main(["--preflight-only"]) == 2
    output = capsys.readouterr()
    assert "preflight is NOT ready" in output.err
    assert "SERVICE PREFLIGHT GREEN" not in output.out
