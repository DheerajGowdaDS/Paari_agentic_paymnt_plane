"""Live two-workspace portal walkthrough against a running Paari server.

Covers guide scenarios 1-3, 8 (fail-closed denial), 10 (revocation), 11 (fleet view).
Run: python paari_portal_walkthrough.py --base-url http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import uuid

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk"))
from paari_agent import crypto  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)


def load_env(path: pathlib.Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    args = ap.parse_args()
    env = load_env(ROOT / ".env")
    admin_key = env["PAARI_ADMIN_API_KEY"]
    base = args.base_url.rstrip("/")
    c = httpx.Client(base_url=base, timeout=60.0)
    suffix = uuid.uuid4().hex[:8].upper()
    password = "Sandbox-Passw0rd-" + suffix
    org_id = "tenant-" + suffix.lower()
    # GSTIN: 2 digits + 5 letters + 4 digits + letter + alnum + Z + alnum (15 chars).
    gst_digits = "".join(str(int(ch, 16) % 10) for ch in suffix[:4])

    # ---------- 1. parent onboarding ----------
    reg = c.post("/v36/parents/register", json={
        "parent_type": "organization",
        "name": f"Demo Procurement Org {suffix}",
        "identifier": f"29ABCDE{gst_digits}F1Z{gst_digits[0]}",
        "representative_name": "Demo Treasury Lead",
        "representative_email": f"treasury{suffix.lower()}@example.com",
        "representative_phone": "+919800000000",
        "address": "Synthetic sandbox address",
        "password": password,
        "accept_terms": True,
        "accept_privacy": True,
        "accept_agent_security": True,
    })
    check("1a register parent", reg.status_code == 201, f"HTTP {reg.status_code} {reg.text[:120]}")
    regj = reg.json()
    parent_id = regj["parent_id"]
    check("1b pending status returned", regj["status"] == "pending_verification", regj["status"])

    status = c.get(f"/v36/parents/status/{regj['registration_reference']}").json()
    check("1c registration status pending", status["status"] == "pending_verification", status["status"])

    hdr = {"X-Admin-Api-Key": admin_key}
    pending = c.get("/portal/v1/platform/parents/pending", headers=hdr).json()["items"]
    check("1d visible in console pending queue", any(i["parent_id"] == parent_id for i in pending),
          f"{len(pending)} pending")

    # ---------- 2. approval + tenant ----------
    review = c.post(f"/portal/v1/platform/parents/{parent_id}/review", headers=hdr, json={
        "approve": True, "identity_checked": True, "contact_checked": True,
        "representative_authority_checked": True,
        "reviewer_note": "Synthetic sandbox application reviewed by automated walkthrough.",
    })
    check("2a approve parent", review.status_code == 200 and review.json()["status"] == "active",
          f"HTTP {review.status_code} {review.text[:120]}")

    prov = c.post("/portal/v1/platform/tenants/provision", headers=hdr, json={
        "parent_id": parent_id, "org_id": org_id, "name": f"Demo Tenant {suffix}"})
    check("2b provision tenant", prov.status_code == 200 and prov.json()["org_id"] == org_id,
          f"HTTP {prov.status_code} {prov.text[:120]}")

    login = c.post("/v36/parents/login", json={"parent_id": parent_id, "password": password})
    check("2c parent login", login.status_code == 200, f"HTTP {login.status_code}")
    ptoken = login.json()["access_token"]
    phdr = {"Authorization": f"Bearer {ptoken}"}

    ov = c.get("/portal/v1/parent/overview", headers=phdr)
    ovj = ov.json()
    check("2d organization workspace overview", ov.status_code == 200 and ovj["parent"]["org_id"] == org_id,
          f"status={ovj.get('parent', {}).get('status')} org={ovj.get('parent', {}).get('org_id')}")

    # ---------- 3. agent registration + card ----------
    priv, pub = crypto.generate_keypair("ed25519")
    agent = c.post("/v36/agents/register", headers=phdr, json={
        "basics": {"name": f"Procurement Agent {suffix}", "agent_type": "procurement",
                   "purpose": "Supplier invoice payment", "description": "Sandbox demo agent",
                   "software_operator": "Demo Runtime"},
        "agent_public_key_pem": pub,
        "delegation": {"capabilities": ["make_payment"], "limit_minor_units": 5_000_000,
                       "currency": "INR", "valid_days": 30},
        "escalation_contact": {"name": "Demo Treasury Lead", "email": f"treasury{suffix.lower()}@example.com",
                               "phone": "+919800000000", "alternate_email": None},
        "accept_agent_security": True,
    })
    check("3a register agent", agent.status_code == 201, f"HTTP {agent.status_code} {agent.text[:160]}")
    agentj = agent.json()
    agent_id = agentj["agent_card"]["agent_id"]
    cred = agentj["credential_jwt"]
    sig_ok = crypto.verify_paari_card(agentj["agent_card"])
    check("3b agent card signature verifies", sig_ok, f"agent_id={agent_id}")

    card = c.get(f"/v1/agents/{agent_id}/card")
    check("3c fetch agent card", card.status_code == 200 and card.json()["agent_id"] == agent_id,
          f"HTTP {card.status_code}")

    pubv = c.get(f"/portal/v1/public/agent-cards/{agent_id}/verify")
    pvj = pubv.json()
    check("3d public verification page endpoint", pubv.status_code == 200 and pvj.get("signature_valid") is True,
          f"signature_valid={pvj.get('signature_valid')}")

    qr = c.get(f"/portal/v1/agent-cards/{agent_id}/qr.svg", headers=phdr)
    check("3e agent-card QR endpoint", qr.status_code == 200 and "svg" in qr.headers.get("content-type", ""),
          f"HTTP {qr.status_code} {qr.headers.get('content-type')} {qr.text[:100] if qr.status_code != 200 else ''}")

    # ---------- agent runtime auth ----------
    ch = c.post("/v1/auth/challenge", json={"agent_id": agent_id}).json()
    ver = c.post("/v1/auth/verify", json={
        "agent_id": agent_id, "nonce": ch["nonce"],
        "signature_b64": crypto.sign_text(priv, ch["nonce"]), "credential_jwt": cred})
    check("3f agent session established", ver.status_code == 200, f"HTTP {ver.status_code} {ver.text[:120]}")
    stoken = ver.json()["session_token"]

    path = "/v1/payments/intent"

    def intent(txn, amount, key):
        headers = {
            "Authorization": f"Bearer {stoken}",
            "X-Paari-Proof": crypto.build_request_proof(
                priv, agent_id=agent_id, access_token=stoken, method="POST", path=path),
        }
        body = {"agent_id": agent_id, "transaction_id": txn, "idempotency_key": key,
                "merchant": "Approved Supplier Ltd", "amount_minor_units": amount,
                "currency": "INR", "action": "make_payment", "purpose": "Supplier invoice"}
        return c.post(path, headers=headers, json=body)

    # ---------- 8. fail-closed denial on this deployment ----------
    d = intent(f"walk-{suffix}-1", 400_000_00, f"idem-{suffix}-1")
    dj = d.json()
    check("8 fail-closed payment denial", d.status_code == 200 and dj.get("decision") == "deny"
          and not dj.get("authorization"),
          f"decision={dj.get('decision')} reasons={dj.get('reasons')}")

    # ---------- 11. treasury / fleet view ----------
    pov = c.get("/portal/v1/platform/overview", headers=hdr)
    check("11a platform overview", pov.status_code == 200,
          f"agents={pov.json().get('agents')} parents={pov.json().get('parents')}")
    agents = c.get("/portal/v1/platform/agents", headers=hdr).json()["items"]
    check("11b fleet lists agent", any(a["agent_id"] == agent_id for a in agents), f"{len(agents)} agents")

    # ---------- 10. revocation ----------
    rv = c.post(f"/portal/v1/platform/agents/{agent_id}/revoke", headers=hdr,
                json={"reason": "Automated walkthrough revocation check"})
    check("10a revoke agent", rv.status_code == 200, f"HTTP {rv.status_code} {rv.text[:120]}")
    d2 = intent(f"walk-{suffix}-2", 10_000_00, f"idem-{suffix}-2")
    d2j = d2.json()
    blocked = d2.status_code in (401, 403) or d2j.get("decision") == "deny"
    check("10b revoked agent cannot pay", blocked,
          f"HTTP {d2.status_code} decision={d2j.get('decision')} reasons={d2j.get('reasons')}")

    # ---------- audit ----------
    pa = c.get("/portal/v1/platform/audit?limit=50", headers=hdr)
    check("audit endpoint readable", pa.status_code == 200, f"{len(pa.json().get('items', []))} events")

    failed = [r for r in RESULTS if not r[1]]
    print(f"\nSUMMARY: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    for name, ok, detail in failed:
        print(f"  FAILED: {name} :: {detail}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
