"""Paari v3.7.1 — complete live demo of the 12 scenarios from the demo guide.

Runs against the disposable paari_demo_test Postgres (docker-compose.local.yml)
and a local Razorpay-compatible simulator. No real money moves.
"""
from __future__ import annotations

import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "sdk"))

from app import crypto_utils  # noqa: E402
from paari_agent import generate_keypair  # noqa: E402
from paari_agent.crypto import sign_text, build_request_proof  # noqa: E402

PG = "postgresql+psycopg://paari:{pw}@127.0.0.1:5439/paari_demo_test".format(
    pw=__import__("urllib.parse", fromlist=["quote"]).quote(
        [l for l in (ROOT / ".env").read_text().splitlines()
         if l.startswith("PAARI_POSTGRES_PASSWORD=")][0].split("=", 1)[1].strip(),
        safe=""))
import hashlib  # noqa: E402
from app.federation.contracts import AgreementClaims  # noqa: E402

CURRENCY = "INR"
MERCHANT = "Danium Suppliers"
CAP = 50_000_000                      # ₹5,00,000 in paise
REVIEW_ABOVE = 42_000_000             # ₹4,20,000 human review threshold
RUN = uuid.uuid4().hex[:8].upper()

results: list[tuple[str, bool, str]] = []


def check(name, ok, evidence):
    results.append((name, bool(ok), str(evidence)[:300]))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {str(evidence)[:220]}", flush=True)


def approx(label, value):
    return f"{label}={value}"


def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def reset_schema() -> None:
    import psycopg
    raw = PG.replace("postgresql+psycopg://", "postgresql://", 1)
    conn = psycopg.connect(raw)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
        cur.execute("CREATE SCHEMA public")
    conn.close()


def _canonical_mandate(fields: dict) -> str:
    payload = {"purpose": "paari_user_payment_mandate", "mandate_version": 1,
               "mandate_id": fields["mandate_id"], "user_id": fields["user_id"],
               "agent_id": fields["agent_id"], "org_id": fields.get("org_id", "default"),
               "constraints": {
                   "currency": fields["currency"],
                   "max_per_transaction": int(fields["max_per_transaction"]),
                   "max_daily_amount": int(fields["max_daily_amount"]),
                   "max_per_hour": fields.get("max_per_hour"),
                   "max_per_merchant_per_day": fields.get("max_per_merchant_per_day"),
                   "max_category_per_day": fields.get("max_category_per_day"),
                   "allowed_merchants": sorted(str(m) for m in (fields.get("allowed_merchants") or [])),
                   "allowed_categories": sorted(str(c) for c in (fields.get("allowed_categories") or [])),
                   "require_review_above": fields.get("require_review_above")},
               "issued_at": int(datetime.fromisoformat(fields["valid_from"]).timestamp()),
               "expires_at": int(datetime.fromisoformat(fields["expires_at"]).timestamp())}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def admin_key() -> str:
    return "paari-demo-" + secrets.token_urlsafe(24)


def start_stack(admin: str, org_id: str) -> tuple[str, list[subprocess.Popen], pathlib.Path, str]:
    processes: list[subprocess.Popen] = []
    sign_key = ROOT / f"_tmp_demo_signing_{RUN}.pem"
    if sign_key.exists():
        sign_key.unlink()
    stub_port = _free_port()
    stub_base = f"http://127.0.0.1:{stub_port}/v1"
    processes.append(subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "stub_razorpay.py"), str(stub_port)],
        cwd=ROOT, env={**os.environ, "PAARI_LIVE": "0"}))
    secret_line = {l.split("=", 1)[0].strip(): l.split("=", 1)[1].strip()
                   for l in pathlib.Path(ROOT / ".env").read_text().splitlines()
                   if "=" in l and not l.strip().startswith("#")}
    # Per-tenant sandbox provider credentials (env-scoped, never in the DB).
    tag = "".join(c for c in org_id if c.isalnum()).upper()
    env = {**os.environ,
           "PAARI_ENV": "sandbox", "PAARI_LIVE": "0", "PAARI_MODE": "standard",
           "PAARI_ADMIN_API_KEY": admin,
           f"RAZORPAY_KEY_ID__{tag}": "rzp_test_SIM_LOCAL",
           f"RAZORPAY_KEY_SECRET__{tag}": "simulated-secret",
           f"RAZORPAY_WEBHOOK_SECRET__{tag}": "stub_webhook_secret",
           "PAARI_V36_KEY_ENCRYPTION_SECRET": secret_line["PAARI_V36_KEY_ENCRYPTION_SECRET"],
           "PAARI_V36_PII_HMAC_SECRET": secret_line["PAARI_V36_PII_HMAC_SECRET"],
           "PAARI_V36_AUTH_SECRET": secret_line["PAARI_V36_AUTH_SECRET"],
           "PAARI_V37_DATA_ENCRYPTION_SECRET": secret_line["PAARI_V37_DATA_ENCRYPTION_SECRET"],
           "PAARI_BENEFICIARY_HASH_SECRET": secret_line["PAARI_BENEFICIARY_HASH_SECRET"],
           "PAARI_CONTROL_PLANE_ENFORCEMENT": "1",
           "PAARI_RECEIVER_ENFORCEMENT": "1",
           "PAARI_FEDERATION_ENFORCEMENT": "1",
           "PAARI_REQUIRE_SIGNED_MANDATE": "1",
           "PAARI_REQUIRE_SAFR_ENVELOPE": "1",
           "PAARI_REQUIRE_USER_MANDATE": "0",
           "PAARI_SIGNING_KEY_PATH": str(sign_key),
           "PAARI_SIGNING_BACKEND": "local_pem",
           "PAARI_AGENTIC_PROVIDER": "",
           "RAZORPAY_KEY_ID": "rzp_test_SIM_LOCAL",
           "RAZORPAY_KEY_SECRET": "simulated-secret",
           "RAZORPAY_WEBHOOK_SECRET": "stub_webhook_secret",
           "RAZORPAY_API_BASE": stub_base,
           "DATABASE_URL": PG, "ALEMBIC_URL": PG, "PAARI_DATABASE_URL": PG,
           "PYTHONIOENCODING": "utf-8"}
    mig = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                         cwd=ROOT, env=env, capture_output=True, text=True)
    if mig.returncode:
        print(mig.stderr[-2000:]); sys.exit("alembic failed")
    server_port = _free_port()
    processes.append(subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(server_port)], cwd=ROOT, env=env))
    base = f"http://127.0.0.1:{server_port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            h = httpx.get(base + "/health", timeout=2)
            if h.status_code == 200 and h.json().get("database") == "up":
                return base, processes, sign_key, stub_base
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    for p in processes:
        p.terminate()
    sys.exit("server never became healthy")


def stop(processes, sign_key: pathlib.Path) -> None:
    for p in reversed(processes):
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    if sign_key.exists():
        try:
            sign_key.unlink()
        except PermissionError:
            print(f"[warn] scratch key left behind: {sign_key}", file=sys.stderr)


def health_check_summary(base: str) -> dict:
    r = httpx.get(f"{base}/health", timeout=5)
    d = r.json()
    return {"status": d.get("status"), "database": d.get("database"),
            "mandate_mode": d.get("mandate_mode"),
            "control_plane_enforcement": d.get("control_plane_enforcement"),
            "receiver_enforcement": d.get("receiver_enforcement"),
            "federation_enforcement": d.get("federation_enforcement"),
            "safr_envelope_required": d.get("safr_envelope_required")}


def process_envelope(base, priv, pub, agent_id, parent_id, mandate_id, org_id,
                     principal_id, resource_id, txn_id, amount_minor, purpose,
                     org_headers):
    import app.crypto_utils as cu
    from app.safr.envelope import (
        GovernanceEnvelope, compute_action_digest, beneficiary_reference_digest,
        signing_payload,
    )
    now = datetime.now(timezone.utc)
    context_digest = hashlib.sha256(cu.canonical_json({
        "org_id": org_id, "agent_id": agent_id, "mandate_id": mandate_id,
        "transaction_id": txn_id, "merchant": MERCHANT,
        "amount_minor_units": amount_minor, "currency": CURRENCY,
        "action": "make_payment", "purpose": purpose,
        "merchant_category": None}).encode("utf-8")).hexdigest()
    raw = {
        "envelope_type": "paari.safr.governance-envelope", "schema_version": "1.0",
        "envelope_id": str(uuid.uuid4()), "tenant_id": org_id,
        "agent_id": agent_id, "parent_id": parent_id,
        "principal_id": principal_id, "resource_id": resource_id,
        "mandate_id": mandate_id, "action_type": "payment.execute",
        "action_context": {
            "resource_id": resource_id, "operation": "make_payment",
            "amount_minor_units": amount_minor, "currency": CURRENCY,
            "beneficiary_ref_digest": beneficiary_reference_digest(MERCHANT),
            "merchant": MERCHANT, "purpose": purpose, "provider_id": "razorpay",
            "jurisdiction": "AE", "request_context_digest": context_digest,
        },
        "trace": {"trace_id": f"safr-{txn_id}", "source_system": "paari-sandbox-agent",
                   "sequence": 1, "parent_trace_id": None,
                   "trace_digest": hashlib.sha256(txn_id.encode("utf-8")).hexdigest()},
        "evidence_refs": [], "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=2)).isoformat(),
        "signing_key_fingerprint": cu.public_key_fingerprint(pub),
        "action_digest": "0" * 64, "signature_b64": "A" * 88,
    }
    env = GovernanceEnvelope.model_validate(raw)
    raw["action_digest"] = compute_action_digest(env)
    env = GovernanceEnvelope.model_validate(raw)
    raw["signature_b64"] = cu.sign_with_private_key(
        priv, cu.canonical_json(signing_payload(env)))
    signed = GovernanceEnvelope.model_validate(raw).model_dump(mode="json")
    resp = httpx.post(f"{base}/control/v1/governance/envelopes/process",
                      params={"transaction_id": txn_id}, headers=org_headers, json=signed,
                      timeout=20.0)
    return resp


def simulate_capture(base, _stub_base, order_id, amount_minor, webhook_secret):
    import importlib.util
    spec = importlib.util.spec_from_file_location("stub_razorpay", ROOT / "scripts" / "stub_razorpay.py")
    stub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stub)
    basic = ("sim_key", "sim_secret")
    payment = httpx.post(f"{_stub_base}/payments",
                          json={"order_id": order_id, "amount": amount_minor,
                                "currency": CURRENCY}, auth=basic, timeout=20.0).json()
    captured = httpx.post(f"{_stub_base}/payments/{payment['id']}/capture",
                           json={"amount": amount_minor, "currency": CURRENCY},
                           auth=basic, timeout=20.0).json()
    raw_w, sig_w = stub.build_capture_webhook(captured, webhook_secret)
    wh = httpx.post(f"{base}/v1/payments/webhooks/razorpay", content=raw_w,
                    headers={"X-Razorpay-Signature": sig_w,
                             "Content-Type": "application/json"}, timeout=20.0)
    return wh


def main() -> int:
    admin = admin_key()
    suffix = RUN[:6]
    org_id = "demoorg" + RUN[:8].lower()
    print(f"target reset: paari_demo_test"); reset_schema()
    base, processes, sign_key, stub_base = start_stack(admin, org_id)
    h = health_check_summary(base)
    admin_headers = {"X-Admin-Api-Key": admin}
    print("[health]", json.dumps(h))
    try:
        # ---------- Scenario 1: parent onboarding ----------
        digits = "".join(str(int(c, 16) % 10) for c in RUN[:8][:4])
        gst = f"29ABCDE{digits}F1Z{digits[0]}"
        reg = httpx.post(f"{base}/v36/parents/register", json={
            "parent_type": "organization", "name": f"Demo Procurement Org {suffix}",
            "identifier": gst, "representative_name": "Demo Treasury Lead",
            "representative_email": f"treasury{suffix.lower()}@example.invalid",
            "representative_phone": "+919800000000",
            "address": "Synthetic sandbox address",
            "password": "Sandbox-Passw0rd-" + suffix,
            "accept_terms": True, "accept_privacy": True, "accept_agent_security": True}, timeout=30)
        regj = reg.json(); run_parent_id = regj.get("parent_id")
        check("Test 1a parent registers -> pending", reg.status_code == 201 and regj["status"] == "pending_verification",
              f"HTTP {reg.status_code} status={regj.get('status')}")
        status = httpx.get(f"{base}/v36/parents/status/{regj['registration_reference']}", timeout=10).json()
        check("Test 1b status lookup returns pending", status["status"] == "pending_verification", status["status"])
        pending = httpx.get(f"{base}/portal/v1/platform/parents/pending",
                            headers=admin_headers, timeout=10).json()["items"]
        check("Test 1c platform console lists pending parent",
              any(i["parent_id"] == run_parent_id for i in pending),
              f"pending={len(pending)}")

        # ---------- Scenario 2: approval + tenant ----------
        approved = httpx.post(f"{base}/portal/v1/platform/parents/{run_parent_id}/review",
                              headers=admin_headers, json={
                                  "approve": True, "identity_checked": True,
                                  "contact_checked": True, "representative_authority_checked": True,
                                  "reviewer_note": "Synthetic sandbox application; demo approval only."},
                              timeout=10)
        check("Test 2a parent approved", approved.status_code == 200 and approved.json()["status"] == "active",
              f"HTTP {approved.status_code} status={approved.json().get('status')}")
        prov = httpx.post(f"{base}/portal/v1/platform/tenants/provision",
                          headers=admin_headers, json={"parent_id": run_parent_id, "org_id": org_id,
                                                       "name": f"Demo Tenant {suffix}"}, timeout=10)
        check("Test 2b tenant provisioned", prov.status_code == 200 and prov.json()["org_id"] == org_id,
              f"HTTP {prov.status_code} org={prov.json().get('org_id')}")
        # Sandbox fixture: this tenant routes to the local Razorpay-compatible
        # simulator under org-tagged env credentials (provider_accounts is a
        # marker row; secrets stay in env).
        import psycopg
        _conn = psycopg.connect(PG.replace("postgresql+psycopg://", "postgresql://", 1))
        _conn.autocommit = True
        _ = datetime.now(timezone.utc)
        with _conn.cursor() as _cur:
            _cur.execute("INSERT INTO provider_accounts"
                         " (org_id, provider_name, key_id_label, is_default, created_at)"
                         " VALUES (%s, 'razorpay', %s, false, %s) ON CONFLICT (org_id) DO NOTHING",
                         (org_id, "rzp_test_SIM_LOCAL", _))
        _conn.close()
        _conn.close()
        login = httpx.post(f"{base}/v36/parents/login", json={"parent_id": run_parent_id,
                                                              "password": "Sandbox-Passw0rd-" + suffix}, timeout=10)
        org_token = login.json()["access_token"]
        phdr = {"Authorization": f"Bearer {org_token}"}
        ov = httpx.get(f"{base}/portal/v1/parent/overview", headers=phdr, timeout=10).json()
        check("Test 2c parent login and org workspace",
              ov.get("parent", {}).get("status") == "active" and ov.get("parent", {}).get("org_id") == org_id,
              f"org={ov.get('parent', {}).get('org_id')} status={ov.get('parent', {}).get('status')}")

        # ---------- Scenario 3: agent registration ----------
        agent_priv, agent_pub = generate_keypair()
        agent = httpx.post(f"{base}/v36/agents/register", headers=phdr, json={
            "basics": {"name": f"ProcurementBot {suffix}", "agent_type": "procurement",
                        "purpose": "Approved supplier invoices",
                        "description": "Sandbox procurement agent",
                        "software_operator": "Demo Runtime"},
            "agent_public_key_pem": agent_pub,
            "delegation": {"capabilities": ["make_payment"], "limit_minor_units": CAP,
                           "currency": CURRENCY, "valid_days": 30},
            "escalation_contact": {"name": "Demo Treasury Lead",
                                   "email": f"treasury{suffix.lower()}@example.invalid",
                                   "phone": "+919800000000", "alternate_email": None},
            "accept_agent_security": True}, timeout=30)
        aj = agent.json(); agent_id = aj["agent_card"]["agent_id"]
        check("Test 3a agent registered + card issued", agent.status_code == 201 and bool(aj["agent_card"].get("card_signature_b64")),
              f"HTTP {agent.status_code} agent_id={agent_id}")
        pubv = httpx.get(f"{base}/portal/v1/public/agent-cards/{agent_id}/verify", timeout=10).json()
        check("Test 3b public verification page validates signature", pubv.get("signature_valid") is True,
              f"signature_valid={pubv.get('signature_valid')}")

        # ---------- Mandate & provider fixture ----------
        # Standalone payer mandate (Ed25519), the same artifact the reference
        # golden flow signs; the USER federation agreement can only be signed
        # with a key the payer holds, which the v3.6 parent-managed key never
        # exposes. The parent can still approve/reject reviews.
        user_priv, user_pub = generate_keypair()
        payer_user_id = f"payer-{suffix.lower()}"
        now = datetime.now(timezone.utc)
        umid = f"UM-DEMO-{RUN}"
        fields = {"mandate_id": umid, "user_id": payer_user_id, "agent_id": agent_id,
                  "org_id": org_id,
                  "max_per_transaction": CAP, "max_daily_amount": CAP * 4, "max_per_hour": CAP * 4,
                  "max_per_merchant_per_day": CAP * 4, "max_category_per_day": None,
                  "currency": CURRENCY, "allowed_merchants": [MERCHANT],
                  "allowed_categories": [], "require_review_above": REVIEW_ABOVE,
                  "valid_from": now.isoformat(),
                  "expires_at": (now + timedelta(days=30)).isoformat(),
                  "approval_reference": "demo-user-consent"}
        sig = sign_text(user_priv, _canonical_mandate(fields))
        mand = httpx.post(f"{base}/v1/mandates",
                          json={**fields, "user_public_key_pem": user_pub,
                                "mandate_signature_b64": sig,
                                "signing_key_id": f"user-key-demo-{suffix.lower()}"},
                          headers={"X-Admin-Api-Key": admin}, timeout=20.0)
        mand_id = umid
        check("mandate signed by payer key",
              mand.status_code == 200 and mand.json().get("signature_valid") is True,
              f"HTTP {mand.status_code} mandate_id={mand_id}")

        prov_resp = httpx.post(f"{base}/v36/providers/register", json={
            "legal_name": f"Danium Settlement {suffix}",
            "registration_number": "SIM-" + suffix,
            "contact_email": f"sim{suffix.lower()}@example.invalid",
            "representative_name": "Settlement Officer",
            "payment_rail": "razorpay_simulator", "currencies": ["INR"],
            "accept_terms": True, "accept_privacy": True,
            "accept_provider_participation": True}, timeout=15)
        provider_id = prov_resp.json()["provider_id"]
        httpx.post(f"{base}/v36/admin/providers/{provider_id}/review", headers=admin_headers,
                   json={"approve": True, "identity_checked": True, "contact_checked": True,
                         "representative_authority_checked": True,
                         "reviewer_note": "Synthetic payment institution; local approval."}, timeout=15)
        httpx.post(f"{base}/v36/admin/providers/{provider_id}/requirements", headers=admin_headers,
                   json={"required_context_fields": ["merchant", "purpose", "parent_id", "agent_id"],
                         "max_amount_minor_units": 100_000_000, "required_currency": "INR"}, timeout=15)
        print(f"[provider {provider_id} approved with requirements]")

        # ---------- Control-plane + receiver + federation fixtures ----------
        key_resp = httpx.post(f"{base}/control/v1/admin-keys", headers=admin_headers,
                              json={"org_id": org_id, "scopes": ["control:read", "control:write"],
                                    "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}, timeout=15)
        control_key = key_resp.json()["secret"]
        ch = {"X-Paari-Control-Key": control_key, "X-Paari-Org": org_id}
        pr = httpx.post(f"{base}/control/v1/principals", headers=ch, json={
            "external_subject_id": payer_user_id,
            "identity_provider": "sandbox-fixture:synthetic-trusted-idp",
            "display_name": f"Demo Payer Principal {suffix}"}, timeout=15).json()
        principal_id = pr["principal_id"]
        httpx.post(f"{base}/control/v1/principals/{principal_id}/attest", headers=ch,
                   json={"attestation_reference": f"sandbox-attest-{suffix}"}, timeout=15)
        import psycopg
        raw = PG.replace("postgresql+psycopg://", "postgresql://", 1)
        conn = psycopg.connect(raw); conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("UPDATE principal_identities SET assurance_level='high' WHERE principal_id=%s", (principal_id,))
        conn.close()
        res = httpx.post(f"{base}/control/v1/resources", headers=ch, json={
            "resource_type": "bank_account", "provider_id": "razorpay",
            "external_resource_ref": f"demo-source-{suffix}", "owner_principal_id": principal_id,
            "currency": CURRENCY, "classification": "restricted",
            "metadata": {"scheme": "sandbox-demo"}}, timeout=15).json()
        resource_id = res["resource_id"]
        httpx.post(f"{base}/control/v1/policies", headers=ch, json={
            "policy_name": "payment_execution", "version": f"demo-{RUN}", "activate": True,
            "min_evidence_quality_bps": 8500, "observe_threshold_bps": 2500,
            "escalate_threshold_bps": 6000, "deny_threshold_bps": 9000,
            "require_signed_mandate": True,
            # Explicit org opt-in: signed parent review may release an ESCALATE
            # that is held only for human review. Without this the institution
            # cannot release a held payment at all (fail-closed by design).
            "allow_signed_review_release": True}, timeout=15)
        now = datetime.now(timezone.utc)
        for s_type, s_id in (("principal", principal_id), ("agent", agent_id)):
            httpx.post(f"{base}/control/v1/resources/{resource_id}/grants", headers=ch, json={
                "subject_type": s_type, "subject_id": s_id,
                "actions": ["payment:execute"], "consent_reference": f"demo-consent-{s_type}-{suffix}",
                "valid_from": (now - timedelta(seconds=2)).isoformat(),
                "valid_until": (now + timedelta(days=10)).isoformat()}, timeout=15)
        rb_priv, rb_pub = generate_keypair()
        inst = httpx.post(f"{base}/control/v1/receivers/institutions", headers=ch, json={
            "external_id": f"demo-recv-{suffix}", "name": f"Demo Settlement {suffix}",
            "rail": "SANDBOX", "public_key_pem": rb_pub}, timeout=15).json()
        receiver_id = str(inst["receiver_id"])
        httpx.post(f"{base}/control/v1/receivers/institutions/{receiver_id}/approve",
                   headers={"X-Admin-Api-Key": admin, "X-Paari-Org": org_id},
                   json={"verification_reference": f"demo-receiver-approval-{suffix}"}, timeout=15)
        benef = httpx.post(f"{base}/control/v1/receivers/beneficiaries", headers=ch, json={
            "receiver_id": receiver_id, "alias": MERCHANT,
            "account_reference": f"demo-account-{suffix}", "currency": CURRENCY,
            "max_payment_minor_units": CAP}, timeout=15).json()
        beneficiary_id = str(benef["beneficiary_id"])
        bind = httpx.post(f"{base}/v1/mandates/{mand_id}/provider-binding",
                          headers={"X-Admin-Api-Key": admin}, json={
            "provider": "razorpay", "source_resource_id": resource_id,
            "provider_mandate_ref": f"demo-pmandate-{suffix}",
            "provider_instrument_ref": f"demo-instr-{suffix}",
            "currency": CURRENCY, "max_amount_minor_units": CAP,
            "expires_at": (now + timedelta(days=10)).isoformat()}, timeout=15)
        check("strict control-plane fixture created", bind.status_code == 200,
              f"HTTP {bind.status_code}")
        sender_priv, sender_pub = generate_keypair()
        httpx.post(f"{base}/control/v1/federation/signers", headers=ch,
                   json={"subject_type": "SENDER_ORG", "subject_id": org_id,
                         "public_key_pem": sender_pub}, timeout=15)
        httpx.post(f"{base}/control/v1/federation/signers", headers=ch,
                   json={"subject_type": "USER", "subject_id": payer_user_id,
                         "public_key_pem": user_pub}, timeout=15)
        requirements = httpx.get(f"{base}/control/v1/federation/requirements", headers=ch, timeout=15).json()
        policy_hash = requirements["policy_digest"]
        for role, subject_id, private_key in (("SENDER_ORG", org_id, sender_priv),
                                               ("USER", payer_user_id, user_priv),
                                               ("RECEIVER", receiver_id, rb_priv)):
            claims = {
                "agreement_id": str(uuid.uuid4()), "org_id": org_id,
                "agent_id": agent_id, "beneficiary_id": beneficiary_id,
                "subject_type": role, "subject_id": subject_id,
                "purpose": "Approved supplier invoices",
                "max_amount_minor_units": CAP,
                "currency": CURRENCY, "policy_digest": policy_hash,
                "document_digest": hashlib.sha256(f"paari-demo-{RUN}-{role}".encode()).hexdigest(),
                "issued_at": now.isoformat(),
                "expires_at": (now + timedelta(days=2)).isoformat(),
            }
            canonical = crypto_utils.canonical_json(
                AgreementClaims.model_validate(claims).model_dump(mode="json"))
            sig = crypto_utils.sign_with_private_key(private_key, canonical)
            acc = httpx.post(f"{base}/control/v1/federation/agreements", headers=ch,
                             json={"claims": claims, "signature_b64": sig}, timeout=15)
            print(f"  federation {role}: HTTP {acc.status_code} signature_verified={(acc.json() or {}).get('signature_verified')}")

        def agent_intent(amount_minor: int, txn: str, idem: str, beneficiary: str | None = None):
            path = "/v1/payments/intent"
            proof = build_request_proof(agent_priv, agent_id=agent_id,
                                        access_token=agent_session, method="POST", path=path)
            body = {"agent_id": agent_id, "transaction_id": txn, "idempotency_key": idem,
                    "merchant": MERCHANT, "amount_minor_units": amount_minor,
                    "currency": CURRENCY, "action": "make_payment",
                    "purpose": "Approved supplier invoices",
                    "provider_id": provider_id}
            if beneficiary:
                body["beneficiary_id"] = beneficiary
            return httpx.post(f"{base}{path}", headers={
                "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof},
                json=body, timeout=30)

        # Authenticate agent via v1 challenge/verify
        challenge = httpx.post(f"{base}/v1/auth/challenge", json={"agent_id": agent_id}, timeout=15).json()
        auth = httpx.post(f"{base}/v1/auth/verify", json={
            "agent_id": agent_id, "nonce": challenge["nonce"],
            "signature_b64": sign_text(agent_priv, challenge["nonce"]),
            "credential_jwt": aj["credential_jwt"]}, timeout=15)
        agent_session = auth.json()["session_token"]
        print(f"[agent session established] agent_id={agent_id}")

        # ---------- Test 4: AUTO_EXECUTE ----------
        intent1 = agent_intent(1_000_000, f"TXN-Demo-auto-{RUN}", f"idem-auto-{RUN}", beneficiary_id)
        j1 = intent1.json()
        check("Test 4 AUTO_EXECUTE intent permitted",
              j1.get("decision") == "allow" and not j1.get("review_expires_at"),
              f"decision={j1.get('decision')} reasons={j1.get('reasons')}")
        auth_id = (j1.get("authorization") or {}).get("authorization_id")
        print(f"  authorization_id={auth_id}")
        txn1 = f"TXN-Demo-auto-{RUN}"
        env_resp = process_envelope(base, agent_priv, agent_pub, agent_id, run_parent_id,
                                    mand_id, org_id, principal_id, resource_id,
                                    txn1, 1_000_000,
                                    "Approved supplier invoices", ch)
        print(f"  SAFR envelope: HTTP {env_resp.status_code} disposition={(env_resp.json() or {}).get('disposition')} permitted={(env_resp.json() or {}).get('execution_permitted')}")
        consume_path1 = f"/v1/payments/authorizations/{auth_id}/consume"
        proof = build_request_proof(agent_priv, agent_id=agent_id,
                                    access_token=agent_session, method="POST", path=consume_path1)
        consumed = httpx.post(f"{base}{consume_path1}", headers={
            "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof}, json={}, timeout=30)
        cj = consumed.json()
        check("Test 4b authorization consumed after envelope",
              consumed.status_code == 200 and cj.get("state") == "PROVIDER_SUBMITTED",
              f"HTTP {consumed.status_code} state={cj.get('state')} body={consumed.text[:250]}")
        order_id = cj.get("razorpay_order_id")
        wh = simulate_capture(base, stub_base, order_id, 1_000_000, "stub_webhook_secret")
        reconcile_path = f"/v1/reconcile/{auth_id}"
        proof = build_request_proof(agent_priv, agent_id=agent_id,
                                    access_token=agent_session, method="POST", path=reconcile_path)
        settled = httpx.post(f"{base}{reconcile_path}", headers={
            "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof}, json={}, timeout=30).json()
        check("Test 4c simulated capture -> PAID",
              (settled.get("state") == "PAID" or settled.get("status") == "terminal"),
              f"webhook HTTP {wh.status_code} reconcile state={settled.get('state')} provenance={settled.get('provenance') or settled.get('source')}")

        # ---------- Test 5: OBSERVE ----------
        intent2 = agent_intent(37_500_000, f"TXN-Demo-observe-{RUN}", f"idem-observe-{RUN}", beneficiary_id)
        j2 = intent2.json()
        check("Test 5 OBSERVE permitted, monitored",
              j2.get("decision") == "allow",
              f"decision={j2.get('decision')} reasons={j2.get('reasons')}")
        dec = httpx.get(f"{base}/control/v1/decisions", params={"limit": 50},
                        headers=ch, timeout=15).json()
        observed = [d for d in dec if d.get("intent_id") == j2.get("intent_id")] if isinstance(dec, list) else []
        check("Test 5b SAFR persisted the OBSERVE disposition",
              any(str(d.get("disposition")).upper() == "OBSERVE" for d in observed),
              f"dispositions={[d.get('disposition') for d in observed]}")

        # ---------- Test 6: ESCALATE -> reject ----------
        intent3 = agent_intent(45_000_000, f"TXN-Demo-reject-{RUN}", f"idem-reject-{RUN}", beneficiary_id)
        j3 = intent3.json()
        review_intent_id = j3.get("intent_id")
        check("Test 6a over-review-threshold enters REVIEW",
              j3.get("decision") == "review",
              f"decision={j3.get('decision')} reasons={j3.get('reasons')}")
        reviews = httpx.get(f"{base}/portal/v1/parent/reviews", headers=phdr, timeout=15).json()
        pending_ids = [i.get("intent_id") for i in reviews.get("items", reviews if isinstance(reviews, list) else [])]
        check("Test 6b parent review queue lists intent",
              review_intent_id in pending_ids, f"review intents={pending_ids}")
        reject = httpx.post(f"{base}/portal/v1/parent/reviews/{review_intent_id}/decision",
                            headers=phdr, json={"approve": False,
                                                "reviewer_password": "Sandbox-Passw0rd-" + suffix,
                                                "reviewer_note": "Rejected: supplier quote unverified."},
                            timeout=15)
        check("Test 6c parent rejection recorded",
              reject.status_code == 200 and reject.json().get("decision") == "deny"
              and reject.json().get("authorization_issued") is False,
              f"HTTP {reject.status_code} body={reject.text[:150]}")
        auth_after_reject = httpx.get(f"{base}/payments/intents/{review_intent_id}/authorization",
                                      headers={"Authorization": f"Bearer {agent_session}"}, timeout=15)
        check("Test 6d rejected intent minted no authorization",
              auth_after_reject.status_code >= 400,
              f"HTTP {auth_after_reject.status_code}")

        # ---------- Test 7: ESCALATE -> approve ----------
        intent4 = agent_intent(46_500_000, f"TXN-Demo-approve-{RUN}", f"idem-approve-{RUN}", beneficiary_id)
        j4 = intent4.json()
        review2 = j4.get("intent_id")
        check("Test 7a second reviewable intent enters REVIEW",
              j4.get("decision") == "review",
              f"decision={j4.get('decision')} reasons={j4.get('reasons')}")
        approve = httpx.post(f"{base}/portal/v1/parent/reviews/{review2}/decision",
                             headers=phdr, json={"approve": True,
                                                 "reviewer_password": "Sandbox-Passw0rd-" + suffix,
                                                 "reviewer_note": "Approved: quote verified and PO matched."},
                             timeout=15)
        check("Test 7b parent approval recorded",
              approve.status_code == 200,
              f"HTTP {approve.status_code} body={approve.text[:150]}")
        auth_path = f"/payments/intents/{review2}/authorization"
        proof = build_request_proof(agent_priv, agent_id=agent_id,
                                    access_token=agent_session, method="GET", path=auth_path)
        auth_resp = httpx.get(f"{base}{auth_path}", headers={
            "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof}, timeout=15)
        auth_by_agent = auth_resp.json() if auth_resp.status_code == 200 else {}
        check("Test 7c agent retrieves bounded authorization",
              bool(auth_by_agent.get("authorization_id")),
              f"HTTP {auth_resp.status_code} auth_id={auth_by_agent.get('authorization_id')}")
        review_auth_id = auth_by_agent.get("authorization_id")
        env2 = process_envelope(base, agent_priv, agent_pub, agent_id, run_parent_id,
                                mand_id, org_id, principal_id, resource_id,
                                f"TXN-Demo-approve-{RUN}", 46_500_000,
                                "Approved supplier invoices", ch)
        print(f"  SAFR envelope: HTTP {env2.status_code} disposition={(env2.json() or {}).get('disposition')}")
        consume_path2 = f"/v1/payments/authorizations/{review_auth_id}/consume"
        proof = build_request_proof(agent_priv, agent_id=agent_id,
                                    access_token=agent_session, method="POST", path=consume_path2)
        consumed2 = httpx.post(f"{base}{consume_path2}", headers={
            "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof}, json={}, timeout=30)
        cj2 = consumed2.json()
        check("Test 7d approved authorization consumed (bounded, single-use)",
              consumed2.status_code == 200 and cj2.get("state") == "PROVIDER_SUBMITTED",
              f"HTTP {consumed2.status_code} state={cj2.get('state')} order={cj2.get('razorpay_order_id')}")

        # ---------- Test 8: over-limit DENY ----------
        intent5 = agent_intent(CAP + 1, f"TXN-Demo-over-{RUN}", f"idem-over-{RUN}")
        j5 = intent5.json()
        check("Test 8 over-limit intent denied before provider",
              j5.get("decision") == "deny" and not j5.get("authorization"),
              f"decision={j5.get('decision')} reasons={j5.get('reasons')}")

        # ---------- Test 9: replay attack ----------
        # The velocity limiter parks the 5th intent in a minute; let it expire.
        print("  waiting 70s for the velocity window to expire...")
        time.sleep(70)
        replay_txn = f"TXN-Demo-replay-{RUN}"
        intent6 = agent_intent(2_000_000, replay_txn, f"idem-replay-{RUN}", beneficiary_id)
        j6 = intent6.json()
        if not (j6.get("authorization") or {}).get("authorization_id"):
            print(f"  debug replay intent: {json.dumps(j6)[:400]}")
        replay_auth = (j6.get("authorization") or {}).get("authorization_id")
        env3 = process_envelope(base, agent_priv, agent_pub, agent_id, run_parent_id,
                                mand_id, org_id, principal_id, resource_id,
                                replay_txn, 2_000_000,
                                "Approved supplier invoices", ch)
        consume_path = f"/v1/payments/authorizations/{replay_auth}/consume"
        proof1 = build_request_proof(agent_priv, agent_id=agent_id,
                                     access_token=agent_session, method="POST", path=consume_path)
        first = httpx.post(f"{base}{consume_path}", headers={
            "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof1}, json={}, timeout=30)
        proof2 = build_request_proof(agent_priv, agent_id=agent_id,
                                     access_token=agent_session, method="POST", path=consume_path)
        second = httpx.post(f"{base}{consume_path}", headers={
            "Authorization": f"Bearer {agent_session}", "X-Paari-Proof": proof2}, json={}, timeout=30)
        check("Test 9 first consumption accepted",
              first.status_code == 200,
              f"HTTP {first.status_code} state={(first.json() or {}).get('state') if first.status_code == 200 else first.text[:120]}")
        check("Test 9b replay rejected",
              second.status_code >= 400,
              f"HTTP {second.status_code} body={second.text[:150]}")

        # ---------- Test 11/12: receiver restrictions ----------
        ghost = "ghost-beneficiary-does-not-exist"
        unreg = agent_intent(1_000_000, f"TXN-Demo-unreg-{RUN}", f"idem-unreg-{RUN}", ghost)
        check("Test 12a unregistered receiver blocks before authorization",
              unreg.status_code >= 400 or unreg.json().get("decision") == "deny",
              f"HTTP {unreg.status_code} decision={unreg.json().get('decision') if unreg.status_code < 400 else 'n/a'} reasons={(unreg.json() or {}).get('reasons') if unreg.status_code < 400 else ''}")
        block = httpx.post(f"{base}/control/v1/receivers/beneficiaries/{beneficiary_id}/block",
                           headers=ch, json={"reason": "Block after approved demo transactions for assurance test"},
                           timeout=15)
        check("Test 12b beneficiary blocked by receiver operator", block.status_code == 200,
              f"HTTP {block.status_code} status={(block.json() or {}).get('status')}")
        blocked = agent_intent(1_000_000, f"TXN-Demo-blocked-{RUN}", f"idem-blocked-{RUN}", beneficiary_id)
        check("Test 12c blocked beneficiary blocks new payment",
              blocked.status_code >= 400 or blocked.json().get("decision") == "deny",
              f"HTTP {blocked.status_code} decision={blocked.json().get('decision') if blocked.status_code < 400 else 'n/a'} reasons={(blocked.json() or {}).get('reasons') if blocked.status_code < 400 else ''}")

        # ---------- Test 10: agent revocation (must be last) ----------
        revoke = httpx.post(f"{base}/v36/agents/{agent_id}/revoke", headers=phdr,
                            json={"reason": "Revoke procurement agent after demo for assurance test"}, timeout=15)
        check("Test 10a agent revoked by parent",
              revoke.status_code == 200,
              f"HTTP {revoke.status_code} status={revoke.json().get('status') if revoke.status_code == 200 else revoke.text[:120]}")
        gone = agent_intent(100_000, f"TXN-Demo-revoked-{RUN}", f"idem-revoked-{RUN}", beneficiary_id)
        check("Test 10b revoked agent cannot pay",
              gone.status_code >= 400 or gone.json().get("decision") == "deny",
              f"HTTP {gone.status_code} decision={gone.json().get('decision') if gone.status_code < 400 else 'n/a'}")

        print("\nSUMMARY of checks:", sum(1 for _n, ok, _e in results if ok), "/", len(results))
        failed = [r for r in results if not r[1]]
        for name, ok, detail in failed:
            print(f"  FAILED: {name} :: {detail}")
        return 0 if not failed else 1
    finally:
        stop(processes, sign_key)


if __name__ == "__main__":
    raise SystemExit(main())
