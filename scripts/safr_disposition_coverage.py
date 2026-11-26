"""v3.3 complete SAFR disposition coverage through the INTEGRATED runtime.

Where `golden_flow_e2e.py` proves the single AUTO_EXECUTE happy path (and two
fail-closed gates), this harness proves that ALL FOUR institutional
dispositions are produced and enforced by the LIVE control plane + SAFR
envelope + payment path on PostgreSQL - not just the offline policy previews:

    AUTO_EXECUTE  -> one dedicated agent, low-risk amount; the SAFR envelope
                    permits execution; the bounded authorization is consumed
                    and the payment settles to terminal PAID.
    OBSERVE       -> one dedicated agent, amount crossing the risk-observation
                    threshold; the SAFR envelope still permits execution but
                    flags monitoring; the payment settles to PAID.
    ESCALATE      -> one dedicated agent whose mandate requires human review
                    for the amount; the SAFR envelope HOLDS execution
                    (execution_permitted=False); the REVIEW intent mints NO
                    consumable authorization. Then a FRESH permissive intent
                    for the same agent mints a DISTINCT bounded authorization
                    that IS consumable -> proves a reviewer's approval is not
                    itself spending authority: only a fresh permissive
                    disposition + fresh bounded authorization can spend.
    DENY          -> one dedicated agent, amount over the delegated hard
                    limit; denied before any provider submission; no provider
                    row is created.

Each disposition uses a dedicated agent with exactly one intent so the
velocity (intents-in-last-minute) risk signal stays at zero and the outcome
is driven deterministically by the amount/review-threshold, not by accumulated
velocity. No real money moves (local simulator). The database name MUST be
disposable.

    python scripts/safr_disposition_coverage.py
    PAARI_PG_DSN=...  python scripts/safr_disposition_coverage.py
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

# Reuse the proven strict-stack + onboarding + seed + canonical-mandate helpers
# so this harness shares a single source of truth with the golden flow.
import scripts.golden_flow_e2e as gf  # noqa: E402

CURRENCY = "INR"
MERCHANT = "GoldenStore"
CAP = 500_000                # delegated + mandate + binding hard limit for every agent
AUTO_AMOUNT = 100_000        # ratio 0.2 -> risk 0 -> AUTO_EXECUTE
OBSERVE_AMOUNT = 400_000     # ratio 0.8 -> risk +2500 -> OBSERVE (below escalate 6000)
ESCALATE_AMOUNT = 350_000    # above the review threshold -> ESCALATE (review_required)
REVIEW_ABOVE = 300_000       # the ESCALATE agent's mandate review threshold
FRESH_AMOUNT = 100_000       # below review threshold -> permissive, mints a fresh authorization
DENY_AMOUNT = 500_001        # above CAP -> denied before any provider submission
FAILURES: list[str] = []


def check(name: str, ok: bool, evidence) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {json.dumps(evidence, default=str)[:300]}", flush=True)
    if not ok:
        FAILURES.append(name)
    return ok


def _disposition_for(base_url, ch, intent_id):
    dec = httpx.get(f"{base_url}/control/v1/decisions", params={"limit": 200}, headers=ch, timeout=20.0)
    for d in (dec.json() if dec.status_code == 200 else []):
        if d.get("intent_id") == intent_id:
            return d
    return None


def _signed_envelope_body(client, *, principal_id, resource_id, mandate_id, txn_id, amount, purpose):
    """Build a fully-signed SAFR envelope body bound to this exact intent (no POST)."""
    from app import crypto_utils
    from app.safr.envelope import (GovernanceEnvelope, compute_action_digest,
                                   beneficiary_reference_digest, signing_payload)
    now = datetime.now(timezone.utc)
    card = client.card or {}
    ctx = {"org_id": "default", "agent_id": client.agent_id, "mandate_id": mandate_id,
           "transaction_id": txn_id, "merchant": MERCHANT, "amount_minor_units": amount,
           "currency": CURRENCY, "action": "make_payment", "purpose": purpose,
           "merchant_category": None}
    context_digest = _digest(ctx)
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
            "jurisdiction": "AE", "request_context_digest": context_digest},
        "trace": {"trace_id": f"safr-{txn_id}", "source_system": "paari-sandbox-agent",
                   "sequence": 1, "parent_trace_id": None,
                   "trace_digest": _digest({"trace": txn_id})},
        "evidence_refs": [], "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "signing_key_fingerprint": crypto_utils.public_key_fingerprint(client.public_key_pem),
        "action_digest": "0" * 64, "signature_b64": "A" * 88,
    }
    env = GovernanceEnvelope.model_validate(raw)
    raw["action_digest"] = compute_action_digest(env)
    env = GovernanceEnvelope.model_validate(raw)
    raw["signature_b64"] = crypto_utils.sign_with_private_key(
        client.private_key_pem, crypto_utils.canonical_json(signing_payload(env)))
    return GovernanceEnvelope.model_validate(raw).model_dump(mode="json")


def _process_envelope(client, base_url, ch, *, principal_id, resource_id, mandate_id,
                     txn_id, amount, purpose):
    signed = _signed_envelope_body(client, principal_id=principal_id, resource_id=resource_id,
                                   mandate_id=mandate_id, txn_id=txn_id, amount=amount, purpose=purpose)
    resp = httpx.post(f"{base_url}/control/v1/governance/envelopes/process",
                      params={"transaction_id": txn_id}, headers=ch, json=signed, timeout=20.0)
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, {"body": resp.text[:300]}


def _settle(client, base_url, auth_id, order_id, amount):
    """Simulated payer capture + signed webhook + reconciliation -> PAID."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("stub_dcov", ROOT / "scripts" / "stub_razorpay.py")
    stub = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stub)
    basic = ("sim_key", "sim_secret")
    stub_base = gf._STUB_BASE
    payment = httpx.post(f"{stub_base}/payments",
                         json={"order_id": order_id, "amount": amount, "currency": CURRENCY},
                         auth=basic, timeout=20.0).json()
    captured = httpx.post(f"{stub_base}/payments/{payment['id']}/capture",
                          json={"amount": amount, "currency": CURRENCY}, auth=basic, timeout=20.0).json()
    raw, sig = stub.build_capture_webhook(captured, "stub_webhook_secret")
    wh = httpx.post(f"{base_url}/v1/payments/webhooks/razorpay", content=raw,
                    headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"}, timeout=20.0)
    settled = client.reconcile(auth_id)
    state = settled.get("state") or settled.get("status")
    return wh.status_code == 200 and state in ("PAID", "terminal"), state


def _digest(obj) -> str:
    import hashlib
    from app import crypto_utils
    if isinstance(obj, dict) and "trace" in obj and len(obj) == 1:
        return hashlib.sha256(obj["trace"].encode("utf-8")).hexdigest()
    return hashlib.sha256(crypto_utils.canonical_json(obj).encode("utf-8")).hexdigest()


def _seed(base_url, admin_key, control_key, client, mandate_id, user_id, suffix: str, dsn: str):
    """Per-agent institutional fixture (principal, resource, policy, grants,
    provider binding, dev-only trust pokes). Mirrors the golden-flow seeder but
    takes a distinct resource suffix so multiple dedicated agents can coexist
    in the same org without a 409 on the resource external ref.
    Returns (principal_id, resource_id, control_key, control_headers)."""
    from app.database import get_engine
    from sqlalchemy.orm import sessionmaker
    now = datetime.now(timezone.utc)
    ch = {"X-Paari-Control-Key": control_key, "X-Paari-Org": "default"}

    def _db_poke(fn) -> None:
        if not dsn:
            return
        engine = get_engine(dsn)
        S = sessionmaker(bind=engine)
        s = S()
        try:
            fn(s)
            s.commit()
        finally:
            s.close()

    _db_poke(lambda s: gf._set_parent_trust(s, client.card["parent_id"]))
    pr = httpx.post(f"{base_url}/control/v1/principals", headers=ch, json={
        "external_subject_id": user_id, "identity_provider": "oidc:local-dev-idp",
        "display_name": f"Cov principal {suffix}"})
    pr.raise_for_status()
    principal_id = pr.json()["principal_id"]
    httpx.post(f"{base_url}/control/v1/principals/{principal_id}/attest", headers=ch,
               json={"attestation_reference": f"dev-kyc-{suffix}"}).raise_for_status()
    _db_poke(lambda s: gf._set_principal_assurance(s, principal_id))
    res = httpx.post(f"{base_url}/control/v1/resources", headers=ch, json={
        "resource_type": "bank_account", "provider_id": "razorpay",
        "external_resource_ref": f"cov_source_{suffix}", "owner_principal_id": principal_id,
        "currency": CURRENCY, "classification": "restricted", "metadata": {}})
    res.raise_for_status()
    resource_id = res.json()["resource_id"]
    httpx.post(f"{base_url}/control/v1/policies", headers=ch, json={
        "policy_name": "payment_execution", "version": f"cov-{suffix}", "activate": True,
        "min_evidence_quality_bps": 8500, "observe_threshold_bps": 2500,
        "escalate_threshold_bps": 6000, "deny_threshold_bps": 9000,
        "require_signed_mandate": True}).raise_for_status()
    for subject_type, subject_id in (("principal", principal_id), ("agent", client.agent_id)):
        g = httpx.post(f"{base_url}/control/v1/resources/{resource_id}/grants", headers=ch, json={
            "subject_type": subject_type, "subject_id": subject_id,
            "actions": ["payment:execute"], "consent_reference": f"cov-{subject_type}-{suffix}",
            "valid_from": (now - timedelta(seconds=1)).isoformat(),
            "valid_until": (now + timedelta(days=10)).isoformat()})
        g.raise_for_status()
    bind = httpx.post(f"{base_url}/v1/mandates/{mandate_id}/provider-binding",
                      headers={"X-Admin-Api-Key": admin_key}, json={
        "provider": "razorpay", "source_resource_id": resource_id,
        "provider_mandate_ref": f"cov_pmandate_{suffix}", "provider_instrument_ref": f"cov_instr_{suffix}",
        "currency": CURRENCY, "max_amount_minor_units": CAP,
        "expires_at": (now + timedelta(days=10)).isoformat()})
    bind.raise_for_status()
    return principal_id, resource_id, control_key, ch


def main() -> int:
    dsn = os.environ.get("PAARI_PG_DSN",
                         "postgresql+psycopg://paari:paari-local-only@127.0.0.1:5439/paari_demo_test")
    if not dsn.startswith("postgresql"):
        sys.exit("ABORT: PAARI_PG_DSN must be a PostgreSQL URL.")
    gf._require_disposable_dsn(dsn)
    gf._reset_public_schema(dsn)
    sign_key = ROOT / "_tmp_safrcov_signing_key.pem"
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
        now = datetime.now(timezone.utc)

        def make_agent(scenario: str, review_above):
            """One dedicated agent + signed mandate + full institutional fixture
            (distinct principal/resource/policy/grants/provider-binding, dev-only
            trust pokes) via the golden-flow's single-source-of-truth seeder."""
            client = gf.onboard(base_url, admin_key)
            user_id = f"user-cov-{scenario}-{gf.RUN}"
            user_priv, user_pub = generate_keypair()
            mfields = {"mandate_id": f"UM-{scenario}-{gf.RUN}", "user_id": user_id, "agent_id": client.agent_id,
                       "max_per_transaction": CAP, "max_daily_amount": CAP * 2, "max_per_hour": CAP,
                       "max_per_merchant_per_day": CAP, "max_category_per_day": None, "currency": CURRENCY,
                       "allowed_merchants": [MERCHANT], "allowed_categories": [],
                       "require_review_above": review_above,
                       "valid_from": now.isoformat(), "expires_at": (now + timedelta(days=30)).isoformat(),
                       "approval_reference": f"cov-{scenario}-{gf.RUN}"}
            mand = httpx.post(f"{base_url}/v1/mandates",
                              json={**mfields, "user_public_key_pem": user_pub,
                                    "mandate_signature_b64": sign_text(user_priv, gf._canonical_mandate(mfields)),
                                    "signing_key_id": f"user-{scenario}-{gf.RUN}"},
                              headers={"X-Admin-Api-Key": admin_key}, timeout=20.0)
            mand.raise_for_status()
            mandate_id = mand.json()["mandate_id"]
            p_id, r_id, _, ch_x = _seed(base_url, admin_key, control_key, client, mandate_id, user_id,
                                         f"{scenario}-{gf.RUN}", dsn)
            return client, mandate_id, p_id, r_id, ch_x

        auto_client, auto_mandate, auto_p, auto_r, ach = make_agent("auto", None)
        obs_client, obs_mandate, obs_p, obs_r, och = make_agent("observe", None)
        esc_client, esc_mandate, esc_p, esc_r, ech = make_agent("escalate", REVIEW_ABOVE)
        deny_client, deny_mandate, deny_p, deny_r, dch = make_agent("deny", None)

        def submit(client, tag, amount, purpose):
            txn = f"TXN-cov-{tag}-{gf.RUN}"
            resp = client.payment_intent(transaction_id=txn, idempotency_key=f"idem-{tag}-{gf.RUN}",
                                        merchant=MERCHANT, amount_minor_units=amount, currency=CURRENCY,
                                        purpose=purpose)
            return txn, (resp if isinstance(resp, dict) else resp.json())

        # ================= AUTO_EXECUTE (dedicated agent; low risk) =================
        txn, it = submit(auto_client, "auto", AUTO_AMOUNT, "coverage auto")
        disp = _disposition_for(base_url, ach, it["intent_id"])
        check("AUTO_EXECUTE. live disposition is AUTO_EXECUTE + intent ALLOW",
              disp and disp.get("disposition") == "AUTO_EXECUTE" and it.get("decision") == "allow",
              {"disposition": disp.get("disposition") if disp else None,
               "reasons": disp.get("reason_codes") if disp else None, "intent": it.get("decision")})
        http_code, body = _process_envelope(auto_client, base_url, ach, principal_id=auto_p,
                                            resource_id=auto_r, mandate_id=auto_mandate,
                                            txn_id=txn, amount=AUTO_AMOUNT, purpose="coverage auto")
        check("AUTO_EXECUTE. SAFR envelope permits execution (execution_permitted=True)",
              http_code == 200 and body.get("execution_permitted") is True,
              {"disposition": body.get("disposition"), "execution_permitted": body.get("execution_permitted")})
        consumed = auto_client.consume(it["authorization"]["authorization_id"])
        _order = consumed.get("razorpay_order_id", "")
        ok, state = _settle(auto_client, base_url, it["authorization"]["authorization_id"], _order, AUTO_AMOUNT)
        check("AUTO_EXECUTE. integrated settlement reaches terminal PAID",
              ok and state in ("PAID", "terminal"), {"state": state, "order": _order})

        # ================= OBSERVE (dedicated agent; risk crosses observation) =================
        txn, it = submit(obs_client, "observe", OBSERVE_AMOUNT, "coverage observe")
        disp = _disposition_for(base_url, och, it["intent_id"])
        check("OBSERVE. live disposition is OBSERVE (risk-observation threshold crossed)",
              disp and disp.get("disposition") == "OBSERVE",
              {"disposition": disp.get("disposition") if disp else None,
               "reasons": disp.get("reason_codes") if disp else None, "intent": it.get("decision")})
        http_code, body = _process_envelope(obs_client, base_url, och, principal_id=obs_p,
                                            resource_id=obs_r, mandate_id=obs_mandate,
                                            txn_id=txn, amount=OBSERVE_AMOUNT, purpose="coverage observe")
        check("OBSERVE. SAFR envelope permits monitored execution (execution_permitted=True)",
              http_code == 200 and body.get("execution_permitted") is True,
              {"disposition": body.get("disposition"), "execution_permitted": body.get("execution_permitted"),
               "next_step": (body.get("next_step") or "")[:120]})
        ocons = obs_client.consume(it["authorization"]["authorization_id"])
        _oorder = ocons.get("razorpay_order_id", "")
        ok, state = _settle(obs_client, base_url, it["authorization"]["authorization_id"], _oorder, OBSERVE_AMOUNT)
        check("OBSERVE. monitored payment still settles to terminal PAID",
              ok and state in ("PAID", "terminal"), {"state": state})

        # ================= ESCALATE (dedicated agent; mandate requires human review) =================
        txn, it = submit(esc_client, "escalate", ESCALATE_AMOUNT, "coverage escalate")
        disp = _disposition_for(base_url, ech, it["intent_id"])
        check("ESCALATE. live disposition is ESCALATE + intent parked in REVIEW",
              disp and disp.get("disposition") == "ESCALATE" and it.get("decision") == "review",
              {"disposition": disp.get("disposition") if disp else None,
               "reasons": disp.get("reason_codes") if disp else None, "intent": it.get("decision")})
        http_code, body = _process_envelope(esc_client, base_url, ech, principal_id=esc_p,
                                            resource_id=esc_r, mandate_id=esc_mandate,
                                            txn_id=txn, amount=ESCALATE_AMOUNT, purpose="coverage escalate")
        check("ESCALATE. SAFR envelope HOLDS execution (execution_permitted=False)",
              body.get("disposition") == "ESCALATE" and body.get("execution_permitted") is False,
              {"disposition": body.get("disposition"), "execution_permitted": body.get("execution_permitted"),
               "next_step": (body.get("next_step") or "")[:140]})

        # A reviewer's approval is NOT spending authority: the ESCALATE intent parked in
        # REVIEW minted NO consumable bounded authorization. To actually spend, a FRESH
        # permissive intent must mint a DISTINCT authorization.
        held_auth = it.get("authorization")  # expected: None for a REVIEW intent
        txn2, it2 = submit(esc_client, "escalate-fresh", FRESH_AMOUNT, "coverage escalate fresh")
        fresh_auth = (it2.get("authorization") or {}).get("authorization_id", "")
        check("APPROVAL != SPENDING AUTHORITY. held REVIEW intent minted no consumable authorization",
              held_auth in (None, ""),
              {"held_authorization": (held_auth.get("authorization_id") if held_auth else None),
               "held_decision": it.get("decision")})
        check("APPROVAL != SPENDING AUTHORITY. a fresh permissive intent mints a DISTINCT consumable authorization",
              it2.get("decision") == "allow" and bool(fresh_auth) and fresh_auth != (held_auth or {}).get("authorization_id"),
              {"fresh_decision": it2.get("decision"), "fresh_auth": fresh_auth[:8] or None})
        if fresh_auth:
            fresh_disp = _disposition_for(base_url, ech, it2["intent_id"])
            check("ESCALATE->fresh: the fresh permissive intent is AUTO_EXECUTE (distinct from the held review)",
                  fresh_disp and fresh_disp.get("disposition") == "AUTO_EXECUTE",
                  {"fresh_disposition": fresh_disp.get("disposition") if fresh_disp else None})

        # ================= DENY (dedicated agent; over the delegated hard limit) =================
        txn, it = submit(deny_client, "deny", DENY_AMOUNT, "coverage deny")
        check("DENY. over-hard-limit intent is DENIED before any provider submission",
              it.get("decision") == "deny" and not it.get("authorization"),
              {"decision": it.get("decision"), "reasons": (it.get("reasons") or [])[:2]})

        # ================= audit chain for the settled AUTO path =================
        bundle = auto_client.proof_bundle("TXN-cov-auto-" + gf.RUN)
        rec = (bundle.get("artifacts") or {}).get("audit_record") or {}
        check("audit chain verifies across the integrated AUTO_EXECUTE settlement",
              rec.get("chain_verified") is True, {"chain_verified": rec.get("chain_verified")})
    finally:
        gf._stop(processes, sign_key)

    verdict = ("PAARI v3.3 SAFR DISPOSITION COVERAGE GREEN" if not FAILURES
               else f"PAARI v3.3 SAFR DISPOSITION COVERAGE RED: {FAILURES}")
    print("\n" + "=" * 68, flush=True)
    print(" PAARI v3.3 SAFR DISPOSITION COVERAGE (INTEGRATED RUNTIME, POSTGRES)", flush=True)
    print("=" * 68, flush=True)
    print("AUTO_EXECUTE  permitted + executed -> PAID", flush=True)
    print("OBSERVE       permitted + monitored -> PAID", flush=True)
    print("ESCALATE      held; review != spending authority; fresh authorization required", flush=True)
    print("DENY          over hard limit; no provider submission", flush=True)
    print("=" * 68, flush=True)
    print(verdict, flush=True)
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    sys.exit(main())
