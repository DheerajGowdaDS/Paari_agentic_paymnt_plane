"""Persistent-server Razorpay test-mode driver with fail-closed posture checks.

The server must be launched separately and remain alive while the provider webhook
arrives. The default path requires strict control-plane enforcement. The legacy
signed-mandate-only pathway is available only by explicit opt-in and never claims
strict SAFR alignment.
"""
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk"))

import httpx
from llm_agent.env import load_env

# Populated only by main(), so importing this operator script never loads .env.
BASE = "http://127.0.0.1:8000"
ADMIN_KEY = ""
WEBHOOK_URL = ""


def generate_keypair() -> tuple[str, str]:
    """Return PKCS8 PEM (not a private-key object) for the SDK and signer."""
    from paari_agent.crypto import generate_keypair as sdk_generate_keypair
    return sdk_generate_keypair()


def fingerprint(pub_pem: str) -> str:
    from app.crypto_utils import public_key_fingerprint
    return public_key_fingerprint(pub_pem)


def sign_delegation(parent_priv_pem: str, delegation: dict) -> str:
    from paari_agent.crypto import sign_delegation as sdk_sign_delegation
    return sdk_sign_delegation(parent_priv_pem, delegation)


def signed_agent_headers(client, method: str, path: str) -> dict[str, str]:
    """Fresh, single-use sender-constrained proof for the exact request path.

    Never reuse headers across requests: every proof has a different JTI.
    """
    from paari_agent.crypto import build_request_proof
    if not client.session_token or not client.agent_id:
        raise ValueError("agent must authenticate before making a protected request")
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("proof path must be the exact absolute API path (without query/fragment)")
    return {
        "Authorization": f"Bearer {client.session_token}",
        "X-Paari-Proof": build_request_proof(
            client.private_key_pem,
            agent_id=client.agent_id,
            access_token=client.session_token,
            method=method.upper(),
            path=path,
        ),
    }


def validate_service_posture(health: dict, readiness_status: int, readiness: dict, *,
                             signed_mandate_only_sandbox: bool = False) -> list[str]:
    """Validate the actual running service before any order can be created.

    The limited signed-mandate-only mode is an explicit reproduction option for
    the earlier sandbox settlement. It must never be described as strict SAFR
    control-plane execution.
    """
    failures: list[str] = []
    if health.get("service") != "paari" or health.get("status") != "ok":
        failures.append("Paari liveness/database health is not OK")
    if health.get("database") != "up":
        failures.append("database is not up")
    if health.get("env") != "sandbox":
        failures.append("live_e2e_test only supports PAARI_ENV=sandbox")
    if health.get("provider_environment") != "test":
        failures.append("provider environment must be confirmed as test by the running server")
    if health.get("provider") != "real-razorpay(test-mode)":
        failures.append("provider must be the real Razorpay test-mode adapter, not a simulator")
    if health.get("require_signed_mandate") is not True:
        failures.append("server does not require signed user mandates")

    cp_enabled = health.get("control_plane_enforcement") is True
    if signed_mandate_only_sandbox:
        if cp_enabled:
            failures.append("signed-mandate-only mode is not allowed when strict control-plane enforcement is enabled")
        if readiness_status != 503:
            failures.append("limited mode expects readiness 503 solely because strict control-plane enforcement is off")
        blockers = set(readiness.get("blocking_checks") or [])
        if blockers != {"control_plane_enforcement"}:
            failures.append("readiness has blockers other than the explicitly permitted control-plane-off condition")
    else:
        if not cp_enabled:
            failures.append("strict control-plane enforcement is OFF; refusing to create a provider order")
        if readiness_status != 200 or readiness.get("status") != "ready":
            failures.append("strict service readiness is not ready")
    return failures



def strict_provider_integration_blockers(health: dict) -> list[str]:
    """Require real, healthy trusted integrations before strict provider trials.

    This is a necessary gate, not a claim of KYC certification, SAFR conformance
    or production readiness. The real organization must independently review the
    installed adapter and enroll governance grants/receipts for this trial.
    """
    failures: list[str] = []
    identity = health.get("principal_identity_provider") or {}
    if not (identity.get("configured") is True and identity.get("trusted_evidence") is True
            and identity.get("healthy") is True):
        failures.append("healthy, explicitly trusted real identity adapter is required")
    signer = health.get("signing_backend") or {}
    if not (signer.get("managed") is True and signer.get("healthy") is True):
        failures.append("healthy managed KMS/HSM signer is required; local PEM is sandbox-only")
    if os.environ.get("PAARI_REQUIRE_SAFR_ENVELOPE") != "1":
        failures.append("PAARI_REQUIRE_SAFR_ENVELOPE=1 is required")
    return failures


def fetch_service_posture(base_url: str) -> tuple[dict, int, dict]:
    """Read posture from the server itself; never infer it from this process."""
    health_response = httpx.get(f"{base_url}/health", timeout=5.0)
    health_response.raise_for_status()
    ready_response = httpx.get(f"{base_url}/health/ready", timeout=5.0)
    try:
        readiness = ready_response.json()
    except ValueError as exc:
        raise RuntimeError("/health/ready returned invalid JSON") from exc
    return health_response.json(), ready_response.status_code, readiness


def wait_for_settlement(transaction_id: str, client, timeout_seconds: int) -> bool:
    """Wait for provider-confirmed PAID using the authenticated proof endpoints."""
    deadline = time.monotonic() + timeout_seconds
    print("Waiting for checkout, signed webhook and provider reconciliation; keep this process and server running.", flush=True)
    while time.monotonic() < deadline:
        try:
            path = f"/v1/proof/{transaction_id}"
            response = httpx.get(f"{BASE}{path}", headers=signed_agent_headers(client, "GET", path), timeout=10.0)
            if response.status_code == 401:
                # Paari sessions are short-lived; refresh using the agent key held
                # only in this process and retry without persisting private state.
                client.authenticate()
                time.sleep(0.2)
                continue
            if response.status_code == 200:
                proof = response.json()
                artifacts = proof.get("artifacts") or {}
                result = artifacts.get("payment_result") or {}
                audit = artifacts.get("audit_record") or {}
                expected = (
                    result.get("final_state") == "PAID"
                    and result.get("terminal") is True
                    and result.get("settlement_source") == "provider"
                    and result.get("provider_environment") == "test"
                    and result.get("webhook_verified") is True
                    and audit.get("chain_verified") is True
                )
                if expected:
                    print("SETTLEMENT VERIFIED: final_state=PAID, source=provider, environment=test, "
                          "webhook_verified=true, audit_chain_verified=true", flush=True)
                    return True
                state = result.get("final_state") or (artifacts.get("payment_execution") or {}).get("state") or "pending"
                print(f"Settlement still pending: state={state}", flush=True)
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(2.0)
    print("SETTLEMENT NOT VERIFIED before timeout; inspect /v1/audit and /v1/proof. "
          "Do not treat PROVIDER_SUBMITTED or CAPTURED alone as PAID.", file=sys.stderr, flush=True)
    return False

def main(argv=None):
    import argparse
    global BASE, ADMIN_KEY, WEBHOOK_URL

    parser = argparse.ArgumentParser(description="Persistent-server Razorpay test-mode E2E driver")
    parser.add_argument("--preflight-only", action="store_true", help="check service posture without creating an order")
    parser.add_argument("--signed-mandate-only-sandbox", action="store_true",
                        help="explicitly run the earlier sandbox-only path with strict control-plane enforcement OFF; not a SAFR strict proof")
    parser.add_argument("--wait-for-settlement", action="store_true",
                        help="wait for user checkout and verify provider-confirmed PAID before exiting")
    parser.add_argument("--wait-timeout-seconds", type=int, default=600)
    args = parser.parse_args(argv)
    if args.wait_timeout_seconds < 10 or args.wait_timeout_seconds > 3600:
        parser.error("--wait-timeout-seconds must be between 10 and 3600")

    load_env()
    BASE = os.environ.get("PAARI_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    ADMIN_KEY = os.environ.get("PAARI_ADMIN_API_KEY", "")
    WEBHOOK_URL = os.environ.get("PAARI_WEBHOOK_URL", "")
    if not args.preflight_only and not ADMIN_KEY:
        print("ERROR: PAARI_ADMIN_API_KEY is required; value will not be printed.", file=sys.stderr)
        return 2
    if not args.preflight_only and not WEBHOOK_URL:
        print("ERROR: PAARI_WEBHOOK_URL is required; set the current webhook endpoint privately.", file=sys.stderr)
        return 2
    if not args.preflight_only:
        from urllib.parse import urlparse
        webhook_parsed = urlparse(WEBHOOK_URL)
        if webhook_parsed.scheme != "https" or not webhook_parsed.hostname or not webhook_parsed.path.rstrip("/").endswith("/v1/payments/webhooks/razorpay"):
            print("ERROR: PAARI_WEBHOOK_URL must be the HTTPS public /v1/payments/webhooks/razorpay endpoint.", file=sys.stderr)
            return 2
    try:
        amount_minor_units = int(os.environ.get("PAARI_LIVE_E2E_AMOUNT_MINOR_UNITS", "100"))
    except ValueError:
        print("ERROR: PAARI_LIVE_E2E_AMOUNT_MINOR_UNITS must be an integer.", file=sys.stderr)
        return 2
    if amount_minor_units < 1 or amount_minor_units > 10000:
        print("ERROR: PAARI_LIVE_E2E_AMOUNT_MINOR_UNITS must be 1..10000 minor units (max INR 100.00).", file=sys.stderr)
        return 2
    if args.signed_mandate_only_sandbox and args.wait_for_settlement is False:
        print("NOTE: limited mode will create only a test-mode order; use --wait-for-settlement to verify capture/webhook/reconciliation.")

    try:
        health, readiness_status, readiness = fetch_service_posture(BASE)
    except Exception as exc:
        print(f"ERROR: could not inspect persistent service at {BASE}: {type(exc).__name__}: {exc}", file=sys.stderr)
        print("Start the service separately; this script deliberately never starts or stops the server.", file=sys.stderr)
        return 2
    failures = validate_service_posture(health, readiness_status, readiness,
                                        signed_mandate_only_sandbox=args.signed_mandate_only_sandbox)
    print("Service posture (values reported by the running server):")
    print(json.dumps({"env": health.get("env"), "database": health.get("database"),
                      "mandate_mode": health.get("mandate_mode"),
                      "require_signed_mandate": health.get("require_signed_mandate"),
                      "control_plane_enforcement": health.get("control_plane_enforcement"),
                      "provider": health.get("provider"),
                      "provider_environment": health.get("provider_environment"),
                      "readiness_status": readiness_status,
                      "signing_backend": (health.get("signing_backend") or {}).get("backend"),
                      "signing_backend_managed": (health.get("signing_backend") or {}).get("managed")}, indent=2))
    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}", file=sys.stderr)
        print("No payment order was requested.", file=sys.stderr)
        return 2
    if args.preflight_only:
        if not args.signed_mandate_only_sandbox:
            blockers = strict_provider_integration_blockers(health)
            if blockers:
                for blocker in blockers:
                    print(f"[BLOCKED] {blocker}", file=sys.stderr)
                print("No transaction was created. Strict-provider preflight is NOT ready.", file=sys.stderr)
                return 2
        print("SERVICE PREFLIGHT GREEN; no transaction was created.")
        if args.signed_mandate_only_sandbox:
            print("LIMITATION: signed-mandate-only sandbox is not strict SAFR control-plane execution.")
        else:
            print("LIMITATION: posture preflight does not certify the provider or complete governance provisioning.")
        return 0
    if not args.signed_mandate_only_sandbox:
        blockers = strict_provider_integration_blockers(health)
        if blockers:
            for blocker in blockers:
                print(f"BLOCKED: {blocker}", file=sys.stderr)
            print("No provider order was created; the script will not seed synthetic identity assurance.",
                  file=sys.stderr)
            return 2
    if args.signed_mandate_only_sandbox:
        print("WARNING: SIGNED-MANDATE-ONLY SANDBOX MODE — institutional control-plane enforcement is OFF. "
              "This is a payment lifecycle test, not proof of strict SAFR runtime governance.", file=sys.stderr)
    print("=== Starting Live E2E Test against the existing persistent service ===\n")
    print("The server is not a child process of this driver and will not be terminated.\n")

    admin = {"X-Admin-Api-Key": ADMIN_KEY}

    # 1. Register parent
    parent_priv, parent_pub = generate_keypair()
    r = httpx.post(f"{BASE}/parents/register", json={
        "name": "Live E2E Parent",
        "parent_type": "developer",
        "contact": "livee2e@example.com",
        "public_key_pem": parent_pub,
    }, headers=admin)
    print(f"1. Parent register: {r.status_code}")
    if r.status_code != 200:
        print(f"   ERROR: {r.text}")
        return 1
    parent_id = r.json()["parent_id"]
    print(f"   parent_id: {parent_id}")

    # 2. Approve parent
    r = httpx.post(f"{BASE}/parents/{parent_id}/approve", headers=admin)
    print(f"2. Parent approve: {r.status_code} status={r.json().get('status') if r.headers.get('content-type', '').startswith('application/json') else '(non-JSON response)'}")
    if r.status_code != 200 or r.json().get("status") != "active":
        print(f"   ERROR: parent approval failed (HTTP {r.status_code}); stopping.", file=sys.stderr)
        return 1

    # 3. Register agent via SDK
    from paari_agent.client import PaariAgentClient
    agent_priv, agent_pub = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {
        "delegation_id": str(uuid.uuid4()),
        "parent_id": parent_id,
        "agent_public_key_fingerprint": fingerprint(agent_pub),
        "granted_capabilities": ["make_payment"],
        "payment_limit_minor_units": 500000,
        "currency": "INR",
        "issued_at": int(now.timestamp()),
        "expires_at": int((now + timedelta(days=7)).timestamp()),
    }
    client = PaariAgentClient(BASE, agent_priv, agent_pub)
    client.register(
        name="Live E2E Agent",
        agent_type="shopping_assistant",
        purpose="live e2e test",
        delegation=delegation,
        delegation_signature_b64=sign_delegation(parent_priv, delegation),
    )
    print(f"3. Agent register: agent_id={client.agent_id}")

    # 4. Authenticate
    client.authenticate()
    print(f"4. Authenticate: got session token")

    # 5. Create signed user mandate
    user_priv, user_pub = generate_keypair()
    mandate_id = f"UM-LIVE-{uuid.uuid4().hex[:8]}"
    mandate_fields = {
        "mandate_id": mandate_id,
        "user_id": os.environ.get("PAARI_LIVE_E2E_USER_ID", "user-live-e2e"),
        "agent_id": client.agent_id,
        "max_per_transaction": 100000,
        "max_daily_amount": 200000,
        "max_per_hour": 100000,
        "max_per_merchant_per_day": 100000,
        "max_category_per_day": None,
        "currency": "INR",
        "allowed_merchants": ["LiveE2EStore"],
        "allowed_categories": [],
        "require_review_above": None,
        "valid_from": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approval_reference": f"live-e2e-{mandate_id}",
    }
    proof_script = ROOT / "scripts" / "foreign_agent_proof.py"
    proof_spec = importlib.util.spec_from_file_location("_paari_foreign_proof_for_live_e2e", proof_script)
    if proof_spec is None or proof_spec.loader is None:
        raise RuntimeError("could not load canonical mandate encoder from scripts/foreign_agent_proof.py")
    proof_module = importlib.util.module_from_spec(proof_spec)
    proof_spec.loader.exec_module(proof_module)
    canonical = proof_module.canonical_mandate_payload(mandate_fields)
    from paari_agent.crypto import sign_text
    signature = sign_text(user_priv, canonical)
    r = httpx.post(f"{BASE}/v1/mandates", json={
        **mandate_fields,
        "user_public_key_pem": user_pub,
        "mandate_signature_b64": signature,
        "signing_key_id": f"user-key-{mandate_id}",
    }, headers=admin)
    print(f"5. Mandate create: {r.status_code}")
    if r.status_code != 200:
        print(f"   ERROR: {r.text}")
        return 1
    mandate_data = r.json()
    print(f"   mandate_id: {mandate_data['mandate_id']}, status: {mandate_data['status']}")

    # 6. Payment intent
    # The server derives the active mandate; do not supply a client-selected mandate_id.
    r = httpx.post(f"{BASE}/v1/payments/intent", json={
        "agent_id": client.agent_id,
        "transaction_id": f"TXN-live-{uuid.uuid4().hex[:8]}",
        "idempotency_key": f"idem-live-{uuid.uuid4().hex[:8]}",
        "merchant": "LiveE2EStore",
        "amount_minor_units": int(os.environ.get("PAARI_LIVE_E2E_AMOUNT_MINOR_UNITS", "100")),
        "currency": "INR",
        "action": "make_payment",
        "purpose": "live e2e test payment",
    }, headers=signed_agent_headers(client, "POST", "/v1/payments/intent"))
    print(f"6. Payment intent: {r.status_code}")
    if r.status_code != 200:
        print(f"   ERROR: {r.text}")
        return 1
    intent_data = r.json()
    transaction_id = intent_data.get("transaction_id", "")
    authorization = intent_data.get("authorization")
    print(f"   transaction_id: {transaction_id or '(not issued)'}")
    print(f"   decision: {intent_data.get('decision')}")
    if intent_data.get("decision") != "allow" or not isinstance(authorization, dict):
        print("   DENIED/REVIEW: no bounded authorization was issued; no provider order will be created.", file=sys.stderr)
        print(f"   reasons: {intent_data.get('reasons', [])}", file=sys.stderr)
        return 1
    authorization_id = authorization.get("authorization_id")
    if not authorization_id:
        print("   ERROR: allow response has no authorization_id; refusing to continue.", file=sys.stderr)
        return 1
    print(f"   authorization_id: {authorization_id}")

    # 7. Consume authorization (creates real Razorpay order)
    r = httpx.post(
        f"{BASE}/v1/payments/authorizations/{authorization_id}/consume",
        json={},
        headers=signed_agent_headers(client, "POST", f"/v1/payments/authorizations/{authorization_id}/consume"),
    )
    print(f"7. Consume: {r.status_code}")
    if r.status_code != 200:
        print(f"   ERROR: {r.text}")
        return 1
    consume_data = r.json()
    razorpay_order_id = consume_data.get("razorpay_order_id", "")
    print(f"   state: {consume_data.get('state')}")
    print(f"   razorpay_order_id: {razorpay_order_id or '(missing)'}")
    if consume_data.get("state") != "PROVIDER_SUBMITTED" or not re.fullmatch(r"order_[A-Za-z0-9]+", str(razorpay_order_id)):
        print("ERROR: provider did not return a valid test-mode order in PROVIDER_SUBMITTED state; refusing checkout instructions.", file=sys.stderr)
        return 1

    # 8. Check audit chain
    r = httpx.get(
        f"{BASE}/v1/audit/{transaction_id}",
        headers=signed_agent_headers(client, "GET", f"/v1/audit/{transaction_id}"),
    )
    print(f"8. Audit chain: {r.status_code}")
    if r.status_code == 200:
        audit_data = r.json()
        print(f"   chain_verified: {audit_data['chain_verified']}")
        kinds = [e["kind"] for e in audit_data["events"]]
        print(f"   events: {kinds}")

    # 9. Check proof bundle
    r = httpx.get(
        f"{BASE}/v1/proof/{transaction_id}",
        headers=signed_agent_headers(client, "GET", f"/v1/proof/{transaction_id}"),
    )
    print(f"9. Proof bundle: {r.status_code}")
    if r.status_code == 200:
        proof = r.json()
        artifacts = proof.get("artifacts") or {}
        payment_result = artifacts.get("payment_result") or {}
        audit_record = artifacts.get("audit_record") or {}
        print(f"   final_state: {payment_result.get('final_state')}")
        print(f"   settlement_source: {payment_result.get('settlement_source')}")
        print(f"   provider_environment: {payment_result.get('provider_environment')}")
        print(f"   webhook_verified: {payment_result.get('webhook_verified')}")
        print(f"   chain_verified: {audit_record.get('chain_verified')}")

    key_id = os.environ.get("RAZORPAY_KEY_ID", "")
    checkout_base = os.environ.get("PAARI_CHECKOUT_BASE_URL", "").strip().rstrip("/")
    checkout_url = (f"{checkout_base}?order_id={razorpay_order_id}&key_id={key_id}"
                    if checkout_base else None)
    print(f"\nTransaction ID: {transaction_id}")
    print(f"Authorization ID: {authorization_id}")
    print(f"Razorpay Order ID: {razorpay_order_id}")
    if checkout_url:
        print(f"Externally configured checkout URL (test mode): {checkout_url}")
    else:
        print("Browser checkout is not bundled in backend-only edition; configure "
              "PAARI_CHECKOUT_BASE_URL to an external provider test checkout if required.")
    print(f"Webhook endpoint configured for this trial: {WEBHOOK_URL}")
    print("Current state is only PROVIDER_SUBMITTED; do not describe it as PAID.")

    if args.wait_for_settlement:
        if not wait_for_settlement(transaction_id, client, args.wait_timeout_seconds):
            return 1
    else:
        print("\nThe service must remain running for webhook delivery and reconciliation. "
              "Run again with --wait-for-settlement to wait for authoritative provider proof.")
    print("\n=== Live E2E Driver Complete ===")
    return 0



if __name__ == "__main__":
    sys.exit(main())
