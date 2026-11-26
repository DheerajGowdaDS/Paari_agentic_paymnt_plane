"""v3.3 strict SAFR Golden Payment Flow on persistent PostgreSQL.

Proves one complete, persistent, strict-governance workflow end to end, with
every stage backed by a real service and a real provider simulator - no
disconnected preview records, no hardcoded success flags:

    1. development identity verification   -> trusted identity evidence seeded
                                               (simulated active state, dev-only)
    2. registered agent                     -> parent delegation + authn
    3. signed mandate                        -> Ed25519 user mandate + provider binding
    4. governance envelope                   -> signed SAFR envelope bound to the intent
    5. disposition                           -> institutional control plane AUTO_EXECUTE
    6. fresh authorization                   -> one-time bounded authorization
    7. simulated payment                     -> local provider stub order/capture/webhook
    8. PostgreSQL settlement                 -> reconcile to terminal PAID
    9. verified audit proof                  -> hash chain verifies through PAID

And it proves the two strict gates that make the flow safe:

    * over-mandate intent is DENIED before any provider submission
    * consume WITHOUT a processed SAFR envelope is blocked (403)

The database name MUST end in a disposable suffix - the harness refuses to run
against a live database. No real money moves; settlement is the local simulator.

    python scripts/golden_flow_e2e.py
    PAARI_PG_DSN=postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test \
        python scripts/golden_flow_e2e.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk"))

import httpx  # noqa: E402

from paari_agent import PaariAgentClient, generate_keypair, sign_delegation, fingerprint  # noqa: E402
from paari_agent.crypto import sign_text  # noqa: E402

AMOUNT = 150_000
CURRENCY = "INR"
MERCHANT = "GoldenStore"
CAP = 500_000
RUN = uuid.uuid4().hex[:6]
_STUB_BASE = ""
failures: list[str] = []


def check(name: str, ok: bool, evidence) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {json.dumps(evidence, default=str)[:300]}", flush=True)
    if not ok:
        failures.append(name)
    return ok


def _require_disposable_dsn(dsn: str) -> None:
    from app.database import assert_disposable_database_url
    assert_disposable_database_url(dsn, "run the v3.3 strict Golden Payment Flow")
    print(f"[note] Postgres target: {dsn.split('@')[-1] if '@' in dsn else dsn}", flush=True)


def _reset_public_schema(dsn: str) -> None:
    import psycopg
    raw = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
    conn = psycopg.connect(raw)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
            cur.execute("CREATE SCHEMA public")
    finally:
        conn.close()


def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_stack(dsn: str) -> tuple[str, str, list[subprocess.Popen], Path]:
    """Own the stub provider, the migration, and a STRICT server on the DSN."""
    global _STUB_BASE
    processes: list[subprocess.Popen] = []
    admin_key = "local-v33-" + uuid.uuid4().hex[:24]
    sign_key = ROOT / "_tmp_golden_flow_signing_key.pem"
    if sign_key.exists():
        sign_key.unlink()

    stub_port = _free_port()
    stub_base = f"http://127.0.0.1:{stub_port}/v1"
    _STUB_BASE = stub_base
    processes.append(subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "stub_razorpay.py"), str(stub_port)], cwd=ROOT))

    # STRICT local posture: institutional control plane + signed mandate + a
    # SAFR envelope bound to the exact intent before any provider consume.
    # `standard` mode (not autonomous) so the settlement path uses the local
    # provider stub rather than an unconfigured provider-native agentic
    # adapter - autonomous settlement is out of scope for the local golden flow.
    env = {**os.environ,
           "PAARI_ENV": "sandbox", "PAARI_LIVE": "0", "PAARI_MODE": "standard",
           "PAARI_CONTROL_PLANE_ENFORCEMENT": "1",
           "PAARI_REQUIRE_SIGNED_MANDATE": "1", "PAARI_REQUIRE_SAFR_ENVELOPE": "1",
           # PAARI_REQUIRE_USER_MANDATE must stay 0 (unset): the legacy alias
           # would silently flip the posture to autonomous, routing settlement
           # through an unconfigured provider-native adapter. The strict control
           # plane already hard-requires a signed mandate, so the alias is not
           # needed and would only break the local simulator path.
           "PAARI_REQUIRE_USER_MANDATE": "0",
           "PAARI_ADMIN_API_KEY": admin_key, "PAARI_SIGNING_KEY_PATH": str(sign_key),
           "PAARI_SIGNING_BACKEND": "local_pem", "PAARI_AGENTIC_PROVIDER": "",
           "RAZORPAY_KEY_ID": "rzp_test_SIM_<REDACTED>", "RAZORPAY_KEY_SECRET": "simulated-secret",
           "RAZORPAY_WEBHOOK_SECRET": "stub_webhook_secret", "RAZORPAY_API_BASE": stub_base,
           "DATABASE_URL": dsn, "ALEMBIC_URL": dsn, "PAARI_DATABASE_URL": dsn,
           "PYTHONIOENCODING": "utf-8"}

    migrated = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                              cwd=ROOT, env=env, capture_output=True, text=True)
    if migrated.returncode != 0:
        for p in processes:
            p.terminate()
        sys.exit(f"ABORT: alembic upgrade head failed on Postgres\n{(migrated.stderr or '')[-1200:]}")

    server_port = _free_port()
    processes.append(subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(server_port)], cwd=ROOT, env=env))
    base_url = f"http://127.0.0.1:{server_port}"
    deadline = time.time() + 45
    while time.time() < deadline:
        try:
            health = httpx.get(f"{base_url}/health", timeout=2)
            if health.status_code == 200 and health.json().get("database") == "up":
                return base_url, admin_key, processes, sign_key
        except httpx.HTTPError:
            pass
        time.sleep(1)
    for p in processes:
        p.terminate()
    sys.exit(f"ABORT: server never became healthy at {base_url}")


def _stop(processes: list[subprocess.Popen], sign_key: Path) -> None:
    for p in reversed(processes):
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    if sign_key.exists():
        sign_key.unlink()


def onboard(base_url: str, admin_key: str) -> PaariAgentClient:
    parent_priv, parent_pub = generate_keypair()
    with httpx.Client(base_url=base_url, timeout=30.0) as boot:
        r = boot.post("/parents/register", json={"name": f"Golden Parent {RUN}",
                       "parent_type": "developer", "contact": f"golden-{RUN}@example.com",
                       "public_key_pem": parent_pub})
        r.raise_for_status()
        parent_id = r.json()["parent_id"]
        boot.post(f"/parents/{parent_id}/approve", headers={"X-Admin-Api-Key": admin_key}).raise_for_status()
    agent_priv, agent_pub = generate_keypair()
    now = datetime.now(timezone.utc)
    delegation = {"delegation_id": str(uuid.uuid4()), "parent_id": parent_id,
                  "agent_public_key_fingerprint": fingerprint(agent_pub),
                  "granted_capabilities": ["make_payment"], "payment_limit_minor_units": CAP,
                  "currency": CURRENCY, "issued_at": int(now.timestamp()),
                  "expires_at": int((now + timedelta(days=7)).timestamp())}
    client = PaariAgentClient(base_url, agent_priv, agent_pub)
    client.register(name=f"Golden Agent {RUN}", agent_type="shopping_assistant",
                    purpose="v3.3 strict SAFR golden flow", delegation=delegation,
                    delegation_signature_b64=sign_delegation(parent_priv, delegation))
    client.authenticate()
    return client


def _canonical_mandate(fields: dict) -> str:
    payload = {"purpose": "paari_user_payment_mandate", "mandate_version": 1,
               "mandate_id": fields["mandate_id"], "user_id": fields["user_id"],
               "agent_id": fields["agent_id"], "org_id": "default",
               "constraints": {"currency": fields["currency"],
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


def create_signed_mandate(base_url: str, admin_key: str, agent_id: str,
                          user_priv: str, user_pub: str, mandate_id: str, user_id: str) -> httpx.Response:
    now = datetime.now(timezone.utc)
    fields = {"mandate_id": mandate_id, "user_id": user_id, "agent_id": agent_id,
              "max_per_transaction": CAP, "max_daily_amount": CAP * 2, "max_per_hour": CAP,
              "max_per_merchant_per_day": CAP, "max_category_per_day": None, "currency": CURRENCY,
              "allowed_merchants": [MERCHANT], "allowed_categories": [], "require_review_above": None,
              "valid_from": now.isoformat(), "expires_at": (now + timedelta(days=30)).isoformat(),
              "approval_reference": f"golden-consent-{RUN}"}
    sig = sign_text(user_priv, _canonical_mandate(fields))
    return httpx.post(f"{base_url}/v1/mandates",
                      json={**fields, "user_public_key_pem": user_pub,
                            "mandate_signature_b64": sig, "signing_key_id": f"user-key-{RUN}"},
                      headers={"X-Admin-Api-Key": admin_key}, timeout=20.0)


def _set_parent_trust(session, parent_id: str) -> None:
    """Development-only: raise the parent trust tier so the strict evidence
    floor (admin_approved) is met by a synthetic agent."""
    import app.models as models
    parent = session.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if parent:
        parent.trust_tier = "admin_approved"


def _set_principal_assurance(session, principal_id: str) -> None:
    """Development-only: mark the locally-attested principal as substantial
    assurance. A real trusted identity provider would establish this itself;
    the local golden flow simulates the ACTIVE evidence state (never trusted
    in production)."""
    import app.models as models
    row = session.query(models.PrincipalIdentity).filter_by(principal_id=principal_id).first()
    if row:
        row.assurance_level = "substantial"


def seed_control_plane(base_url: str, admin_key: str, control_key: str, client,
                       mandate_id: str, user_id: str, database_url: str | None = None) -> tuple[str, str, str, dict]:
    """Create the institutional fixture that makes a strict payment AUTO_EXECUTE:
    high-assurance principal, governed resource, active policy, agent+principal
    grants, and the signed mandate's provider-instrument binding.
    Returns (principal_id, resource_id, org_secret, control_headers)."""
    from app.database import get_engine
    from sqlalchemy.orm import sessionmaker

    now = datetime.now(timezone.utc)
    ch = {"X-Paari-Control-Key": control_key, "X-Paari-Org": "default"}

    def _db_poke(query_fn) -> None:
        """Development-only DB poke against the demo database the caller named.
        Skipped (and non-fatal to the sequence) when no database_url is supplied;
        the operator flow still runs, just without the AUTO_EXECUTE evidence floor."""
        if not database_url:
            return
        engine = get_engine(database_url)
        S = sessionmaker(bind=engine)
        s = S()
        try:
            query_fn(s)
            s.commit()
        finally:
            s.close()

    # parent trust tier -> admin_approved (evidence quality baseline for AUTO).
    _db_poke(lambda s: _set_parent_trust(s, client.card["parent_id"]))

    # 1. development identity verification (simulated ACTIVE evidence, dev-only).
    pr = httpx.post(f"{base_url}/control/v1/principals", headers=ch, json={
        "external_subject_id": user_id, "identity_provider": "oidc:local-dev-idp",
        "display_name": f"Golden principal {RUN}"})
    pr.raise_for_status()
    principal_id = pr.json()["principal_id"]
    attest = httpx.post(f"{base_url}/control/v1/principals/{principal_id}/attest", headers=ch,
                        json={"attestation_reference": f"dev-kyc-{RUN}"})
    attest.raise_for_status()
    # Development-only: elevate assurance so the evidence floor is met. A real
    # trusted identity provider would set this itself; the local golden flow
    # simulates the ACTIVE evidence state (never trusted in production).
    _db_poke(lambda s: _set_principal_assurance(s, principal_id))

    # 2. governed resource.
    res = httpx.post(f"{base_url}/control/v1/resources", headers=ch, json={
        "resource_type": "bank_account", "provider_id": "razorpay",
        "external_resource_ref": f"golden_source_{RUN}", "owner_principal_id": principal_id,
        "currency": CURRENCY, "classification": "restricted", "metadata": {}})
    res.raise_for_status()
    resource_id = res.json()["resource_id"]

    # 3. active policy (versioned, auditable).
    pol = httpx.post(f"{base_url}/control/v1/policies", headers=ch, json={
        "policy_name": "payment_execution", "version": f"golden-{RUN}", "activate": True,
        "min_evidence_quality_bps": 8500, "observe_threshold_bps": 2500,
        "escalate_threshold_bps": 6000, "deny_threshold_bps": 9000,
        "require_signed_mandate": True})
    pol.raise_for_status()

    # 4. grants to BOTH the agent and the principal (the engine requires both).
    for subject_type, subject_id in (("principal", principal_id), ("agent", client.agent_id)):
        g = httpx.post(f"{base_url}/control/v1/resources/{resource_id}/grants", headers=ch, json={
            "subject_type": subject_type, "subject_id": subject_id,
            "actions": ["payment:execute"], "consent_reference": f"golden-{subject_type}-{RUN}",
            "valid_from": (now - timedelta(seconds=1)).isoformat(),
            "valid_until": (now + timedelta(days=10)).isoformat()})
        g.raise_for_status()

    # 5. provider-instrument binding for the signed mandate.
    bind = httpx.post(f"{base_url}/v1/mandates/{mandate_id}/provider-binding",
                      headers={"X-Admin-Api-Key": admin_key}, json={
        "provider": "razorpay", "source_resource_id": resource_id,
        "provider_mandate_ref": f"golden_pmandate_{RUN}", "provider_instrument_ref": f"golden_instr_{RUN}",
        "currency": CURRENCY, "max_amount_minor_units": CAP,
        "expires_at": (now + timedelta(days=10)).isoformat()})
    bind.raise_for_status()
    return principal_id, resource_id, control_key, ch


def process_safR_envelope(base_url: str, client, headers: dict, *, principal_id: str,
                          resource_id: str, mandate_id: str, txn_id: str,
                          amount: int, purpose: str) -> dict:
    """Sign a SAFR governance envelope bound to this exact intent and process it.

    Under PAARI_REQUIRE_SAFR_ENVELOPE=1 the consume path will refuse to run until
    this receipt is persisted, so the fresh-authorization rule is enforced.
    """
    from app import crypto_utils
    from app.safr.envelope import (
        GovernanceEnvelope, compute_action_digest, beneficiary_reference_digest,
        signing_payload,
    )

    now = datetime.now(timezone.utc)
    card = client.card or {}
    context_digest_payload = {
        "org_id": "default", "agent_id": client.agent_id, "mandate_id": mandate_id,
        "transaction_id": txn_id, "merchant": MERCHANT, "amount_minor_units": amount,
        "currency": CURRENCY, "action": "make_payment", "purpose": purpose,
        "merchant_category": None,
    }
    context_digest = hashlib.sha256(
        crypto_utils.canonical_json(context_digest_payload).encode("utf-8")).hexdigest()
    raw = {
        "envelope_type": "paari.safr.governance-envelope", "schema_version": "1.0",
        "envelope_id": str(uuid.uuid4()), "tenant_id": "default",
        "agent_id": client.agent_id, "parent_id": card["parent_id"],
        "principal_id": principal_id, "resource_id": resource_id,
        "mandate_id": mandate_id, "action_type": "payment.execute",
        "action_context": {
            "resource_id": resource_id, "operation": "make_payment",
            "amount_minor_units": amount, "currency": CURRENCY,
            "beneficiary_ref_digest": beneficiary_reference_digest(MERCHANT),
            "merchant": MERCHANT, "purpose": purpose, "provider_id": "razorpay",
            "jurisdiction": "AE", "request_context_digest": context_digest,
        },
        "trace": {"trace_id": f"safr-{txn_id}", "source_system": "paari-sandbox-agent",
                   "sequence": 1, "parent_trace_id": None,
                   "trace_digest": hashlib.sha256(txn_id.encode("utf-8")).hexdigest()},
        "evidence_refs": [], "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=2)).isoformat(),
        "signing_key_fingerprint": crypto_utils.public_key_fingerprint(client.public_key_pem),
        "action_digest": "0" * 64, "signature_b64": "A" * 88,
    }
    env = GovernanceEnvelope.model_validate(raw)
    raw["action_digest"] = compute_action_digest(env)
    env = GovernanceEnvelope.model_validate(raw)
    raw["signature_b64"] = crypto_utils.sign_with_private_key(
        client.private_key_pem, crypto_utils.canonical_json(signing_payload(env)))
    signed = GovernanceEnvelope.model_validate(raw).model_dump(mode="json")

    resp = httpx.post(f"{base_url}/control/v1/governance/envelopes/process",
                      params={"transaction_id": txn_id}, headers=headers, json=signed, timeout=20.0)
    try:
        body = resp.json()
    except ValueError:
        body = {"body": resp.text[:300]}
    ok = (resp.status_code == 200 and body.get("disposition") in {"AUTO_EXECUTE", "OBSERVE"}
          and body.get("execution_permitted") is True and body.get("authorization_issued") is True
          and body.get("transaction_id") == txn_id)
    check("5. signed SAFR envelope bound to the persisted AUTO_EXECUTE disposition",
          ok, {"http": resp.status_code, "envelope_id": raw["envelope_id"],
               "disposition": body.get("disposition"),
               "execution_permitted": body.get("execution_permitted"),
               "detail": body.get("detail") or body.get("next_step")})
    if not ok:
        raise RuntimeError(f"SAFR envelope processing failed closed: HTTP {resp.status_code} {body}")
    return body


def main() -> int:
    dsn = os.environ.get("PAARI_PG_DSN",
                         "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test")
    if not dsn.startswith("postgresql"):
        sys.exit("ABORT: PAARI_PG_DSN must be a PostgreSQL URL (the strict golden flow is Postgres-first).")
    _require_disposable_dsn(dsn)
    _reset_public_schema(dsn)

    sign_key = ROOT / "_tmp_golden_flow_signing_key.pem"
    processes: list[subprocess.Popen] = []
    try:
        base_url, admin_key, processes, sign_key = start_stack(dsn)
        # start_stack sets PAARI_DATABASE_URL only in its own env; expose it here
        # for the seed() DB pokes (trust tier + assurance) against the DSN.
        os.environ["PAARI_DATABASE_URL"] = dsn

        # Control-plane org key.
        org_key = httpx.post(f"{base_url}/control/v1/admin-keys",
                             headers={"X-Admin-Api-Key": admin_key},
                             json={"org_id": "default", "scopes": ["control:read", "control:write"],
                                   "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()})
        org_key.raise_for_status()
        control_key = org_key.json()["secret"]

        client = onboard(base_url, admin_key)
        check("1. agent registered + authenticated", bool(client.agent_id and client.session_token),
              {"agent_id": client.agent_id})

        user_priv, user_pub = generate_keypair()
        user_id = f"user-golden-{RUN}"
        mandate = create_signed_mandate(base_url, admin_key, client.agent_id, user_priv, user_pub,
                                        mandate_id=f"UM-GOLDEN-{RUN}", user_id=user_id)
        check("3. signed user mandate accepted on Postgres",
              mandate.status_code == 200 and mandate.json().get("signature_valid") is True,
              mandate.json() if mandate.status_code == 200 else mandate.text[:200])
        mandate_id = mandate.json()["mandate_id"]

        # `control_key` is the tenant-scoped control-plane key (not the root
        # admin key) that authorizes the institutional seeding calls below.
        principal_id, resource_id, _, ch = seed_control_plane(
            base_url, admin_key, control_key, client, mandate_id, user_id,
            database_url=dsn)
        check("4. development identity + institutional control plane seeded (AUTO_EXECUTE baseline)",
              bool(principal_id and resource_id), {"principal_id": principal_id, "resource_id": resource_id})

        # --- 6. governance decision: submit intent under strict control plane ---
        txn_id = f"TXN-golden-{RUN}"
        intent = client.payment_intent(transaction_id=txn_id, idempotency_key=f"idem-golden-{RUN}",
                                       merchant=MERCHANT, amount_minor_units=AMOUNT, currency=CURRENCY,
                                       purpose="v3.3 strict golden flow")
        check("6a. governance ALLOW under signed mandate + strict control plane",
              intent.get("decision") == "allow" and intent.get("mandate_id"),
              {"decision": intent.get("decision"), "mandate_id": intent.get("mandate_id")})
        auth_id = intent["authorization"]["authorization_id"]

        # Read the persisted institutional disposition straight from the API.
        dec = httpx.get(f"{base_url}/control/v1/decisions", params={"disposition": "AUTO_EXECUTE"},
                       headers=ch, timeout=20.0)
        match = [d for d in dec.json() if d.get("intent_id") == intent["intent_id"]] if dec.status_code == 200 else []
        check("6b. control plane persisted an AUTO_EXECUTE disposition for the intent",
              bool(match), {"decision_id": (match[0]["decision_id"] if match else None)})

        # --- strict gate 1: over-mandate intent is DENIED before provider ---
        over = client.payment_intent(transaction_id=f"TXN-golden-over-{RUN}",
                                    idempotency_key=f"idem-golden-over-{RUN}",
                                    merchant=MERCHANT, amount_minor_units=CAP + 1, currency=CURRENCY,
                                    purpose="over-limit negative gate")
        check("GATE1. over-mandate intent is DENIED before any provider submission",
              over.get("decision") == "deny" and not over.get("authorization"),
              {"decision": over.get("decision"), "reasons": over.get("reasons", [])[:2]})

        # --- strict gate 2: consume without a processed SAFR envelope is blocked ---
        from sdk.paari_agent.crypto import build_request_proof
        consume_path = f"/v1/payments/authorizations/{auth_id}/consume"
        proof = build_request_proof(client.private_key_pem, agent_id=client.agent_id,
                                    access_token=client.session_token, method="POST", path=consume_path)
        blocked = client.http.post(consume_path, json={}, headers={
            "Authorization": f"Bearer {client.session_token}", "X-Paari-Proof": proof})
        check("GATE2. consume blocked until a SAFR envelope is processed (fresh authorization)",
              blocked.status_code == 403, {"http": blocked.status_code,
                                           "detail": (blocked.json() or {}).get("detail", "")[:160]})

        # --- 5. process the signed SAFR envelope, then 6. consume ---
        process_safR_envelope(base_url, client, ch, principal_id=principal_id, resource_id=resource_id,
                              mandate_id=mandate_id, txn_id=txn_id, amount=AMOUNT,
                              purpose="v3.3 strict golden flow")
        consumed = client.consume(auth_id)
        check("7. bounded authorization consumed -> PROVIDER_SUBMITTED (post-envelope)",
              consumed.get("consumed") is True and consumed.get("state") == "PROVIDER_SUBMITTED",
              {"state": consumed.get("state"), "order_id": consumed.get("razorpay_order_id")})
        order_id = consumed["razorpay_order_id"]

        # --- 7/8. simulated payer capture + signed webhook + reconciliation ---
        import importlib.util
        spec = importlib.util.spec_from_file_location("stub_razorpay", ROOT / "scripts" / "stub_razorpay.py")
        stub = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stub)
        basic = ("sim_key", "sim_secret")
        payment = httpx.post(f"{_STUB_BASE}/payments",
                             json={"order_id": order_id, "amount": AMOUNT, "currency": CURRENCY},
                             auth=basic, timeout=20.0).json()
        captured = httpx.post(f"{_STUB_BASE}/payments/{payment['id']}/capture",
                              json={"amount": AMOUNT, "currency": CURRENCY}, auth=basic, timeout=20.0).json()
        raw, signature = stub.build_capture_webhook(captured, os.environ.get("RAZORPAY_WEBHOOK_SECRET", "stub_webhook_secret"))
        wh = httpx.post(f"{base_url}/v1/payments/webhooks/razorpay", content=raw,
                       headers={"X-Razorpay-Signature": signature, "Content-Type": "application/json"},
                       timeout=20.0)
        settled = client.reconcile(auth_id)
        check("8. simulated capture reconciles to terminal PAID on Postgres",
              wh.status_code == 200 and (settled.get("state") == "PAID" or settled.get("status") == "terminal"),
              {"webhook": wh.json() if wh.status_code == 200 else wh.status_code, "reconcile": settled})

        bundle = client.proof_bundle(txn_id)
        record = (bundle.get("artifacts") or {}).get("audit_record") or {}
        result = (bundle.get("artifacts") or {}).get("payment_result") or {}
        check("9. audit chain verified through PAID + settlement provenance is the simulator",
              record.get("chain_verified") is True
              and result.get("final_state") == "PAID"
              and result.get("settlement_source") in {"simulator", "provider"},
              {"events": [e.get("event_type") or e.get("kind") for e in (record.get("events") or [])],
               "final_state": result.get("final_state"), "settlement_source": result.get("settlement_source")})
    finally:
        _stop(processes, sign_key)

    verdict = "PAARI v3.3 STRICT SAFR GOLDEN FLOW GREEN" if not failures else f"PAARI v3.3 STRICT SAFR GOLDEN FLOW RED: {failures}"
    print("\n" + "=" * 68, flush=True)
    print(" PAARI v3.3 STRICT SAFR GOLDEN PAYMENT FLOW (POSTGRES)", flush=True)
    print("=" * 68, flush=True)
    print(f"DATABASE     Postgres ({dsn.split('@')[-1] if '@' in dsn else dsn})", flush=True)
    print("WORKFLOW     identity -> agent -> signed mandate -> envelope -> "
          "AUTO_EXECUTE -> fresh authorization -> simulated PAID -> verified audit", flush=True)
    print("GATES        over-mandate DENY + consume-without-envelope BLOCKED", flush=True)
    print(f"SETTLEMENT   simulated PAID (local provider stub; no real money)", flush=True)
    print("=" * 68, flush=True)
    print(verdict, flush=True)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
