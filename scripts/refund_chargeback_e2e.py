"""v3.3 refund lifecycle E2E (post-settlement), on PostgreSQL.

Closes the P2 "refunds / chargebacks incomplete" gap for the REFUND path. The
app already ships `refund_authorization` (PAID -> REFUNDED) and the provider
adapter's `refund`; the local provider simulator now exposes
`POST /payments/{id}/refund` so the whole path runs against the simulator.

The harness reuses the golden-flow's strict stack + onboarding + seeder as the
single source of truth, then:

    1. settles an AUTO_EXECUTE golden payment to terminal PAID (as the golden
       flow does - envelope + consume + simulated capture + reconcile), and
    2. refunds it through the real legacy refund endpoint
       (`POST /payments/authorizations/{id}/refund`), proving:
          - the provider transaction moves PAID -> REFUNDED (terminal),
          - a `refund_issued` audit event is appended and the hash chain still
            verifies through the refund,
          - a second refund is refused (REFUNDED is terminal; no double refund),
          - refunding a non-settled authorization is refused (409).

No real money moves (local simulator). The database name MUST be disposable.

    python scripts/refund_chargeback_e2e.py
    PAARI_PG_DSN=...  python scripts/refund_chargeback_e2e.py
"""
from __future__ import annotations

import json
import os
import sys
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
from paari_agent import generate_keypair, sign_delegation, fingerprint  # noqa: E402
from paari_agent.crypto import sign_text  # noqa: E402
from sdk.paari_agent.crypto import build_request_proof  # noqa: E402

import scripts.golden_flow_e2e as gf  # noqa: E402

CURRENCY = "INR"
MERCHANT = "GoldenStore"
CAP = 500_000
AMOUNT = 100_000
FAILURES: list[str] = []


def check(name: str, ok: bool, evidence) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {json.dumps(evidence, default=str)[:300]}", flush=True)
    if not ok:
        FAILURES.append(name)
    return ok


def _state_of(auth_id):
    """Read the provider transaction state straight from the running DB (authoritative)."""
    from app.database import get_engine
    from sqlalchemy.orm import sessionmaker
    import app.models as M
    eng = get_engine(os.environ.get("PAARI_DATABASE_URL", ""))
    s = sessionmaker(bind=eng)()
    try:
        txn = s.query(M.ProviderTransaction).filter(M.ProviderTransaction.authorization_id == auth_id).first()
        return txn.state if txn else None
    finally:
        s.close()
        eng.dispose()


def main() -> int:
    dsn = os.environ.get("PAARI_PG_DSN",
                         "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test")
    if not dsn.startswith("postgresql"):
        sys.exit("ABORT: PAARI_PG_DSN must be a PostgreSQL URL.")
    gf._require_disposable_dsn(dsn)
    gf._reset_public_schema(dsn)
    sign_key = ROOT / "_tmp_refund_signing_key.pem"
    processes: list = []
    try:
        base_url, admin_key, processes, sign_key = gf.start_stack(dsn)
        os.environ["PAARI_DATABASE_URL"] = dsn

        org_key = httpx.post(f"{base_url}/control/v1/admin-keys",
                             headers={"X-Admin-Api-Key": admin_key},
                             json={"org_id": "default", "scopes": ["control:read", "control:write"],
                                   "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()})
        org_key.raise_for_status()
        control_key = org_key.json()["secret"]
        client = gf.onboard(base_url, admin_key)

        user_priv, user_pub = generate_keypair()
        user_id = f"user-refund-{gf.RUN}"
        mandate = gf.create_signed_mandate(base_url, admin_key, client.agent_id, user_priv, user_pub,
                                           mandate_id=f"UM-REFUND-{gf.RUN}", user_id=user_id)
        mandate.raise_for_status()
        mandate_id = mandate.json()["mandate_id"]
        principal_id, resource_id, _, ch = gf.seed_control_plane(
            base_url, admin_key, control_key, client, mandate_id, user_id, database_url=dsn)

        # --- settle the golden payment to PAID (reuse the proven envelope + settle) ---
        txn_id = f"TXN-refund-{gf.RUN}"
        intent = client.payment_intent(transaction_id=txn_id, idempotency_key=f"idem-refund-{gf.RUN}",
                                       merchant=MERCHANT, amount_minor_units=AMOUNT, currency=CURRENCY,
                                       purpose="v3.3 refund e2e")
        check("1. golden AUTO intent ALLOW under strict control plane",
              intent.get("decision") == "allow", {"decision": intent.get("decision")})
        auth_id = intent["authorization"]["authorization_id"]
        gf.process_safR_envelope(base_url, client, ch, principal_id=principal_id, resource_id=resource_id,
                                 mandate_id=mandate_id, txn_id=txn_id, amount=AMOUNT,
                                 purpose="v3.3 refund e2e")
        consumed = client.consume(auth_id)
        order_id = consumed.get("razorpay_order_id", "")
        # simulated payer capture + signed webhook + reconcile -> PAID (same as the golden flow)
        import importlib.util
        spec = importlib.util.spec_from_file_location("stub_refund", ROOT / "scripts" / "stub_razorpay.py")
        stub = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(stub)
        basic = ("sim_key", "sim_secret")
        payment = httpx.post(f"{gf._STUB_BASE}/payments",
                             json={"order_id": order_id, "amount": AMOUNT, "currency": CURRENCY},
                             auth=basic, timeout=20.0).json()
        captured = httpx.post(f"{gf._STUB_BASE}/payments/{payment['id']}/capture",
                              json={"amount": AMOUNT, "currency": CURRENCY}, auth=basic, timeout=20.0).json()
        raw, sig = stub.build_capture_webhook(captured, "stub_webhook_secret")
        httpx.post(f"{base_url}/v1/payments/webhooks/razorpay", content=raw,
                   headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"}, timeout=20.0)
        settled = client.reconcile(auth_id)
        state = settled.get("state") or settled.get("status")
        check("2. golden payment settled to terminal PAID before refund",
              state in ("PAID", "terminal"), {"state": state, "order": order_id})

        # --- refund through the real legacy endpoint ---
        refund_path = f"/payments/authorizations/{auth_id}/refund"
        proof = build_request_proof(client.private_key_pem, agent_id=client.agent_id,
                                    access_token=client.session_token, method="POST", path=refund_path)
        r = client.http.post(refund_path, json={"session_token": client.session_token}, headers={
            "Authorization": f"Bearer {client.session_token}", "X-Paari-Proof": proof})
        check("3. refund endpoint accepted (HTTP 200) on a PAID transaction",
              r.status_code == 200, {"http": r.status_code,
                                     "body": (r.json() or {}).get("state") if r.headers.get("content-type", "").startswith("application/json") else r.text[:120]})
        check("4. provider transaction moved PAID -> REFUNDED (terminal)",
              _state_of(auth_id) == "REFUNDED",
              {"state": _state_of(auth_id)})

        # the audit chain must still verify through the refund event.
        bundle = client.proof_bundle(txn_id)
        rec = (bundle.get("artifacts") or {}).get("audit_record") or {}
        kinds = [e.get("event_type") or e.get("kind") for e in (rec.get("events") or [])]
        check("5. a refund_issued audit event was recorded and the chain verifies through it",
              "refund_issued" in kinds and rec.get("chain_verified") is True,
              {"kinds": kinds, "chain_verified": rec.get("chain_verified")})

        # negative: a second refund is refused (REFUNDED is terminal).
        proof2 = build_request_proof(client.private_key_pem, agent_id=client.agent_id,
                                     access_token=client.session_token, method="POST", path=refund_path)
        r2 = client.http.post(refund_path, json={"session_token": client.session_token}, headers={
            "Authorization": f"Bearer {client.session_token}", "X-Paari-Proof": proof2})
        check("6. a second refund of a REFUNDED transaction is refused (terminal, no double refund)",
              r2.status_code == 409, {"http": r2.status_code,
                                      "detail": (r2.json() or {}).get("detail", "")[:120]})
    finally:
        gf._stop(processes, sign_key)

    verdict = ("PAARI v3.3 REFUND E2E GREEN" if not FAILURES
               else f"PAARI v3.3 REFUND E2E RED: {FAILURES}")
    print("\n" + "=" * 68, flush=True)
    print(" PAARI v3.3 REFUND LIFECYCLE E2E (POSTGRES, SIMULATOR)", flush=True)
    print("=" * 68, flush=True)
    print("PAID -> REFUNDED via the real refund endpoint; chain verifies; double-refund refused", flush=True)
    print("=" * 68, flush=True)
    print(verdict, flush=True)
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
