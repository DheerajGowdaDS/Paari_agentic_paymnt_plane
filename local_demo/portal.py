"""Loopback API-only local SAFR scenario service.

Never expose to a public interface or run as production payment authority.
Mutating requests require an explicit out-of-band operator API token and
same-origin checks; provider and model credentials are scrubbed.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request

from local_demo.core import EvidenceStore, LIFECYCLE_DEMOS, SCENARIOS, decision_preview, lifecycle_preview
from local_demo.reviews import ReviewQueue

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_HOME = ROOT / "data" / "local_demo"
E2E = {
    "strict_payment": {
        "title": "Strict institutional controls + provider settlement",
        "description": "Real Paari APIs, institutional controls, synthetic identity, signed mandate, stub webhook, PAID and replay checks",
        "command": ["scripts/llm_agent_e2e.py", "--with-server", "--rehearse", "--strict-control-plane", "--execute-stub", "--settle"],
        "warning": "Controlled sandbox: standard payment mode plus strict control-plane checks; not full production strict autonomous posture",
    },
    "autonomous_payment": {
        "title": "Autonomous provider-native settlement",
        "description": "Real Paari API + signed mandate + bounded authorization + reference provider PAID + audit checks",
        "command": ["scripts/autonomous_payment_e2e.py", "--provider", "reference"],
        "warning": "Reference autonomous provider only; independent from strict institution + identity E2E",
    },
}


def safe_demo_env(home: Path, source: dict[str, str] | None = None) -> dict[str, str]:
    """Fail-closed sandbox process environment, including .env loader precedence.

    Set sensitive variables to empty, rather than removing them: the legacy
    test harness calls load_env(), which otherwise re-reads a developer's .env.
    """
    base = dict(os.environ if source is None else source)
    for key in list(base):
        if any(key.startswith(prefix) for prefix in (
            "RAZORPAY_", "KILO_", "BYNARA_", "OPENAI_", "OPENAI_COMPATIBLE_", "PAARI_IDENTITY_PROVIDER_",
            "PAARI_TRUSTED_IDENTITY_PROVIDER", "PAARI_SIGNING_ADAPTER", "PAARI_PAYMENT_PROVIDER_")):
            base[key] = ""
    base.update({"PAARI_ENV": "sandbox", "PAARI_LIVE": "0", "PAARI_DATABASE_URL": "",
        "PAARI_LLM_PROVIDER": "", "RAZORPAY_KEY_ID": "", "RAZORPAY_KEY_SECRET": "",
        "RAZORPAY_WEBHOOK_SECRET": "stub_webhook_secret", "PAARI_AGENTIC_PROVIDER": "",
        "PAARI_CONTROL_PLANE_ENFORCEMENT": "0", "PAARI_REQUIRE_SAFR_ENVELOPE": "0",
        "PAARI_SIGNING_BACKEND": "local_pem", "PAARI_SIGNING_ADAPTER": "",
        "PAARI_SIGNING_KEY_PATH": str(home / "scenario_signing_key.pem"),
        "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"})
    return base


class ScenarioRuns:
    def __init__(self, store: EvidenceStore, home: Path):
        self.store = store
        self.home = home
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {}
        self._active_id: str | None = None

    def launch(self, name: str) -> dict:
        if name not in E2E:
            raise KeyError(name)
        with self._lock:
            if self._active_id:
                raise RuntimeError("Another E2E is already executing; check its result first")
            run_id = uuid.uuid4().hex[:16]
            run = {"id": run_id, "name": name, "title": E2E[name]["title"],
                "state": "running", "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None, "exit_code": None, "output": "", "sandbox_only": True}
            self._runs[run_id] = run
            self._active_id = run_id
        self.store.append("e2e_started", {"run_id": run_id, "scenario": name,
                                         "provider": "local_simulator", "sandbox_only": True})
        threading.Thread(target=self._execute, args=(run_id, name), daemon=True).start()
        return dict(run)

    def _execute(self, run_id: str, name: str):
        spec = E2E[name]
        env = safe_demo_env(self.home)
        cmd = [sys.executable, *spec["command"]]
        state, exit_code, output = "failed", None, ""
        try:
            done = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True,
                                  timeout=240, encoding="utf-8", errors="replace")
            exit_code = done.returncode
            output = (done.stdout or "") + ("\nSTDERR:\n" + done.stderr if done.stderr else "")
            # Never trust just a shell exit: some older harnesses print failures
            # and still exit cleanly. Require successful E2E-specific evidence.
            verified = ("[FAIL]" not in output and "ABORT:" not in output and
                        ("PAID" in output) and
                        ("PASS" in output))
            state = "passed" if exit_code == 0 and verified else "failed"
        except subprocess.TimeoutExpired as exc:
            output = f"Timed out at 240 seconds.\n{str(exc.stdout or '')[-3000:]}"
            state = "timeout"
        except Exception as exc:
            output = f"Could not run scenario: {type(exc).__name__}: {exc}"
        # Diagnostic output can contain dynamic IDs, never credentials; keep it
        # local and bounded. No ability to submit arbitrary commands over HTTP.
        output = output[-48000:]
        with self._lock:
            run = self._runs[run_id]
            run.update(state=state, exit_code=exit_code, output=output,
                       finished_at=datetime.now(timezone.utc).isoformat())
            self._active_id = None
        self.store.append("e2e_completed", {"run_id": run_id, "scenario": name,
                          "state": state, "exit_code": exit_code, "provider": "local_simulator"})

    def get(self, run_id: str) -> dict | None:
        with self._lock:
            run = self._runs.get(run_id)
            return dict(run) if run else None

    def list(self) -> list[dict]:
        with self._lock:
            return [{k: v for k, v in r.items() if k != "output"}
                    for r in reversed(list(self._runs.values()))]


def create_app(home: Path | None = None, *, backend_url: str = "http://127.0.0.1:8000",
               reviewer_code: str | None = None, provider_stub_base: str = "",
               admin_api_key: str = "", demo_api_token: str | None = None) -> FastAPI:
    """Create the portal app.

    `provider_stub_base` is the base URL of the local provider simulator
    (e.g. `http://127.0.0.1:PORT/v1`). It is required for the operator
    golden-flow route to deliver a simulated capture + signed webhook.
    `admin_api_key` is the root admin key for parent approval + mandate
    creation. Both are empty by default; the operator route refuses to
    run when either is missing rather than falling back to a disconnected
    preview record.
    """
    home = Path(home or DEFAULT_HOME).resolve()
    home.mkdir(parents=True, exist_ok=True)
    store = EvidenceStore(home / "portal_evidence.sqlite3")
    runs = ScenarioRuns(store, home)
    reviews = ReviewQueue(home / "reviews.sqlite3", store, reviewer_code)
    # API-only: credentials are provisioned by the trusted local caller,
    # never returned from an unauthenticated web page or status endpoint.
    csrf = demo_api_token or os.environ.get("PAARI_DEMO_API_TOKEN") or secrets.token_urlsafe(32)
    app = FastAPI(title="Paari v3.2 Local SAFR Demonstration", docs_url=None, redoc_url=None,
                  openapi_url=None)

    def authorize(request: Request):
        if request.url.hostname not in {"127.0.0.1", "localhost"}:
            raise HTTPException(403, "local access only")
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "cross-origin requests denied")
        if not secrets.compare_digest(request.headers.get("x-paari-demo-token", ""), csrf):
            raise HTTPException(403, "CSRF token missing or invalid")

    @app.get("/api/status")
    def status():
        try:
            r = httpx.get(f"{backend_url}/health", timeout=2)
            health = r.json() if r.status_code == 200 else {"status": "unavailable"}
        except (httpx.HTTPError, ValueError):
            health = {"status": "unavailable"}
        return {"version": "3.2-local-demo", "sandbox_only": True,
                "backend_url": backend_url, "backend": health,
                "evidence": store.verify(), "runs": runs.list(), "reviews": reviews.list(), "backend_ready": health.get("database") == "up"}

    @app.get("/api/catalog")
    def catalog():
        return {"policy": [{"key": key, "title": case["title"],
                  "description": case["description"], "expected": case["expected"]}
                  for key, case in SCENARIOS.items()],
                "lifecycle": [{"key": key, "title": case["title"],
                              "description": case["description"], "expected": case["expected"]}
                             for key, case in LIFECYCLE_DEMOS.items()],
                "workflows": [
                    {"key": "full_workflow", "title": "Full SAFR workflow",
                     "description": "Onboarding \u2192 delegated mandate \u2192 governance (all four outcomes) \u2192 authorized execution preview \u2192 simulated settlement \u2192 audit proof, driven from the dashboard",
                     "expected": "PASS"},
                    {"key": "escalation", "title": "Human escalation lifecycle",
                     "description": "Missing authority refused, single resolve, approve vs deny, and expiration fail-closed; approval never confers payment authority",
                     "expected": "PASS"},
                ],
                "e2e": [{"key": key, **{k:v for k,v in case.items() if k != "command"}}
                        for key, case in E2E.items()]}

    @app.post("/api/policy/{key}")
    def policy(key: str, request: Request):
        authorize(request)
        try:
            result = decision_preview(key)
        except KeyError:
            raise HTTPException(404, "Unknown named scenario") from None
        proof = store.append("safr_policy_preview", result)
        return {**result, "audit_event_id": proof["id"], "audit_hash": proof["entry_hash"]}

    @app.post("/api/lifecycle/{key}")
    def lifecycle(key: str, request: Request):
        authorize(request)
        try:
            result = lifecycle_preview(key)
        except KeyError:
            raise HTTPException(404, "Unknown lifecycle demo") from None
        proof = store.append("safr_lifecycle_demo", result)
        return {**result, "audit_event_id": proof["id"], "audit_hash": proof["entry_hash"]}

    @app.post("/api/full_workflow")
    def full_workflow(request: Request):
        """Guided SAFR demonstration, driven entirely from the dashboard.

        Composes the deterministic local engine + the real transition table into
        one reproducible stage map: onboarding (signed envelope) -> delegated
        mandate decision -> governance disposition across all four SAFR
        outcomes -> authorized execution preview -> simulated settlement
        lifecycle -> tamper-evident audit proof. No provider is called and no
        money moves; the two real-HTTP provider E2Es remain separate launches.
        """
        authorize(request)
        stages: list[dict] = []

        def stage(name, ok, detail):
            stages.append({"stage": name, "passed": bool(ok), "detail": detail})

        # 1. Onboarding + delegate: a freshly signed SAFR envelope authenticates.
        auto = decision_preview("auto_execute")
        stage("onboarding_and_signed_envelope", auto["envelope_verified"],
              {"envelope_id": auto["envelope_id"], "agent_id": auto["agent_id"], "mandate_id": auto["mandate_id"]})

        # 2. Delegated-mandate governance across all four SAFR outcomes.
        disposition_map = {}
        for key, expected in (("auto_execute", "AUTO_EXECUTE"), ("observe", "OBSERVE"),
                              ("escalate", "ESCALATE"), ("deny_limit", "DENY")):
            res = decision_preview(key)
            disposition_map[key] = res["disposition"]
        stage("governance_dispositions", all(disposition_map[k] == e for k, e in
              (("auto_execute", "AUTO_EXECUTE"), ("observe", "OBSERVE"),
               ("escalate", "ESCALATE"), ("deny_limit", "DENY"))), disposition_map)

        # 3. Expiry / revocation fail closed before execution.
        mandate_map = {k: decision_preview(k)["disposition"] for k in ("deny_mandate_expired", "deny_mandate_revoked")}
        stage("mandate_expiry_revocation_fail_closed",
              all(v == "DENY" for v in mandate_map.values()), mandate_map)

        # 4. Authorized execution preview + simulated settlement lifecycle.
        lifecycle_map = {}
        for key in LIFECYCLE_DEMOS:
            res = lifecycle_preview(key)
            lifecycle_map[key] = res["outcome"]
        stage("execution_and_settlement_lifecycle", all(v == "PASS" for v in lifecycle_map.values()), lifecycle_map)

        # 5. Tamper-evident audit proof.
        audit = store.verify()
        stage("audit_evidence", audit["verified"], {"entries": audit["entries"], "head": (audit.get("head") or "")[:18]})

        proof = store.append("safr_full_workflow", {"stages": stages, "provider_executed": False, "sandbox_only": True})
        all_pass = all(s["passed"] for s in stages)
        return {"workflow": "safr_full_workflow", "outcome": "PASS" if all_pass else "FAIL",
                "all_passed": all_pass, "provider_executed": False, "sandbox_only": True,
                "stages": stages, "audit_event_id": proof["id"], "audit_hash": proof["entry_hash"]}

    @app.post("/api/run/{key}")
    def e2e_run(key: str, request: Request):
        authorize(request)
        try:
            return runs.launch(key)
        except KeyError:
            raise HTTPException(404, "Unknown E2E scenario") from None
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from None

    def _operator_golden_flow() -> dict:
        """Drive one complete, API-backed, persistent golden payment.

        Pure HTTP against the real backend + local provider stub. No DB pokes,
        no preview records, no hardcoded flags: every value returned is a live
        read. Requires the signed-mandate posture (PAARI_REQUIRE_SIGNED_MANDATE=1)
        and a reachable provider stub. Works in standard mode; under strict
        control-plane + SAFR-envelope posture the envelope is processed first.
        """
        import sys as _sys, importlib.util as _iul
        for _p in (str(ROOT), str(ROOT / "sdk")):
            if _p not in _sys.path:
                _sys.path.insert(0, _p)
        from paari_agent import PaariAgentClient, generate_keypair, sign_delegation, fingerprint
        from paari_agent.crypto import sign_text

        run_tag = uuid.uuid4().hex[:6]
        amount = 50_000
        cap = 200_000
        currency = "INR"
        merchant = "OperatorStore"
        now = datetime.now(timezone.utc)

        # 1. register a parent + agent through the real APIs.
        parent_priv, parent_pub = generate_keypair()
        with httpx.Client(base_url=backend_url, timeout=30.0) as boot:
            pr = boot.post("/parents/register", json={
                "name": f"Operator Parent {run_tag}", "parent_type": "developer",
                "contact": f"op-{run_tag}@example.com", "public_key_pem": parent_pub})
            pr.raise_for_status()
            parent_id = pr.json()["parent_id"]
            if admin_api_key:
                boot.post(f"/parents/{parent_id}/approve",
                          headers={"X-Admin-Api-Key": admin_api_key})
        agent_priv, agent_pub = generate_keypair()
        delegation = {"delegation_id": str(uuid.uuid4()), "parent_id": parent_id,
                      "agent_public_key_fingerprint": fingerprint(agent_pub),
                      "granted_capabilities": ["make_payment"], "payment_limit_minor_units": cap,
                      "currency": currency, "issued_at": int(now.timestamp()),
                      "expires_at": int((now + timedelta(days=7)).timestamp())}
        client = PaariAgentClient(backend_url, agent_priv, agent_pub)
        client.register(name=f"Operator Agent {run_tag}", agent_type="shopping_assistant",
                        purpose="dashboard operator golden flow", delegation=delegation,
                        delegation_signature_b64=sign_delegation(parent_priv, delegation))
        client.authenticate()

        # 2. signed user mandate (required by the demo posture). Reuse the
        #    proven canonical builder from the golden-flow harness so the Ed25519
        #    signature byte-for-byte matches the server's mandate_payload().
        from scripts.golden_flow_e2e import _canonical_mandate
        user_priv, user_pub = generate_keypair()
        user_id = f"user-op-{run_tag}"
        mfields = {"mandate_id": f"UM-OP-{run_tag}", "user_id": user_id, "agent_id": client.agent_id,
                   "max_per_transaction": cap, "max_daily_amount": cap * 2, "max_per_hour": cap,
                   "max_per_merchant_per_day": cap, "max_category_per_day": None, "currency": currency,
                   "allowed_merchants": [merchant], "allowed_categories": [], "require_review_above": None,
                   "valid_from": now.isoformat(), "expires_at": (now + timedelta(days=30)).isoformat(),
                   "approval_reference": f"operator-consent-{run_tag}"}
        mh = {"X-Admin-Api-Key": admin_api_key} if admin_api_key else {}
        mresp = httpx.post(f"{backend_url}/v1/mandates",
                           json={**mfields, "user_public_key_pem": user_pub,
                                 "mandate_signature_b64": sign_text(user_priv, _canonical_mandate(mfields)),
                                 "signing_key_id": f"op-user-{run_tag}"},
                           headers=mh, timeout=20.0)
        if mresp.status_code not in (200, 201):
            raise HTTPException(502, f"mandate creation failed: HTTP {mresp.status_code} {mresp.text[:160]}")

        # 3. submit the payment intent (governance decision).
        txn_id = f"TXN-op-{run_tag}"
        intent = client.payment_intent(transaction_id=txn_id, idempotency_key=f"idem-op-{run_tag}",
                                      merchant=merchant, amount_minor_units=amount, currency=currency,
                                      purpose="dashboard operator golden flow")
        decision = intent.get("decision")
        auth_id = (intent.get("authorization") or {}).get("authorization_id", "")
        if not auth_id:
            raise HTTPException(
                502, f"intent did not mint an authorization: decision={decision} reasons={intent.get('reasons')}")

        # 4. process a SAFR envelope first if the strict envelope gate is active.
        envelope_state = "not_required"
        if os.environ.get("PAARI_REQUIRE_SAFR_ENVELOPE") == "1":
            from scripts.golden_flow_e2e import process_safR_envelope
            ctrl_key = os.environ.get("PAARI_OPERATOR_CONTROL_KEY", "")
            proc_headers = ({"X-Paari-Control-Key": ctrl_key, "X-Paari-Org": "default"}
                            if ctrl_key else {"X-Admin-Api-Key": admin_api_key})
            try:
                process_safR_envelope(
                    backend_url, client, proc_headers,
                    principal_id=intent.get("principal_id") or "", resource_id=intent.get("resource_id") or "",
                    mandate_id=intent.get("mandate_id") or "", txn_id=txn_id, amount=amount,
                    purpose="dashboard operator golden flow")
                envelope_state = "processed"
            except RuntimeError as exc:
                raise HTTPException(502, f"SAFR envelope processing failed closed: {exc}") from exc

        # 5. consume -> provider submit, simulated capture, signed webhook, reconcile.
        consumed = client.consume(auth_id)
        order_id = consumed.get("razorpay_order_id", "")
        stub_spec = _iul.spec_from_file_location("stub_operator", ROOT / "scripts" / "stub_razorpay.py")
        stub_op = _iul.module_from_spec(stub_spec)
        stub_spec.loader.exec_module(stub_op)
        basic = ("sim_key", "sim_secret")
        payment = httpx.post(f"{provider_stub_base}/payments",
                             json={"order_id": order_id, "amount": amount, "currency": currency},
                             auth=basic, timeout=20.0).json()
        captured = httpx.post(f"{provider_stub_base}/payments/{payment['id']}/capture",
                              json={"amount": amount, "currency": currency}, auth=basic, timeout=20.0).json()
        raw, sig = stub_op.build_capture_webhook(
            captured, os.environ.get("RAZORPAY_WEBHOOK_SECRET", "stub_webhook_secret"))
        wh = httpx.post(f"{backend_url}/v1/payments/webhooks/razorpay", content=raw,
                        headers={"X-Razorpay-Signature": sig, "Content-Type": "application/json"},
                        timeout=20.0)
        settle = client.reconcile(auth_id)
        final_state = settle.get("state") or settle.get("status")
        bundle = client.proof_bundle(txn_id)
        record = (bundle.get("artifacts") or {}).get("audit_record") or {}
        result_artifact = (bundle.get("artifacts") or {}).get("payment_result") or {}
        return {
            "transaction_id": txn_id,
            "authorization_id": auth_id,
            "mandate_id": intent.get("mandate_id"),
            "agent_id": client.agent_id,
            "decision": decision,
            "envelope_state": envelope_state,
            "webhook_applied": wh.status_code == 200,
            "webhook_state": wh.json().get("state") if wh.status_code == 200 else wh.status_code,
            "reconcile_state": final_state,
            "audit_chain_verified": record.get("chain_verified"),
            "audit_events": [e.get("event_type") or e.get("kind") for e in (record.get("events") or [])],
            "settlement_source": result_artifact.get("settlement_source"),
            "note": "All values are live API reads from the persistent backend; "
                    "cross-check against the database for independent verification.",
        }

    @app.post("/api/operator/golden_flow")
    def operator_golden_flow(request: Request):
        """One real, API-backed operator workflow - a complete persistent golden
        payment driven through the live backend + local provider simulator.

        No manual API requests from the operator, no hardcoded success
        responses, no disconnected preview records: the portal calls the real
        Paari APIs and returns the live transaction evidence, which the
        operator UI (and dashboard_operator.py) can independently verify
        against the database.
        """
        authorize(request)
        if not provider_stub_base:
            raise HTTPException(503, "Provider stub is not configured; the operator golden flow is unavailable.")
        try:
            return _operator_golden_flow()
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(502, f"operator golden flow failed: {type(exc).__name__}: {exc}") from exc

    @app.get("/api/run/{run_id}")
    def e2e_result(run_id: str):
        result = runs.get(run_id)
        if not result:
            raise HTTPException(404, "Run not found in this portal session")
        return result

    @app.get("/api/reviews")
    def review_list():
        return {"reviews": reviews.list(), "timeout_default_seconds": 120,
                "approval_confers_payment_authority": False}

    @app.post("/api/escalation/simulate")
    def escalation_simulate(request: Request):
        """Deterministic demonstration of the human-escalation state machine.

        Drives the real ReviewQueue through its edge cases using the process's
        own (local-only) authority, so the dashboard can show the whole
        escalation lifecycle without a human pasting a code. It proves the two
        things that matter most: approval NEVER confers payment authority, and
        an unanswered/missing-authority review fails closed.
        """
        authorize(request)
        out: dict[str, dict] = {}
        pending: dict = {}

        # Missing authority: the wrong code is rejected before anything happens.
        try:
            pending = reviews.request("escalate")
            reviews.resolve(pending["id"], decision="approve",
                            reviewer_code="not-the-reviewer-code", reviewer="local-reviewer")
            out["missing_authority"] = {"status": "error", "note": "authority unexpectedly accepted"}
        except PermissionError:
            out["missing_authority"] = {"status": "rejected", "note": "wrong reviewer code refused; review still pending"}
        except ValueError as exc:
            out["missing_authority"] = {"status": "rejected", "note": str(exc)}

        # The pending review created above can be re-checked fresh and approved.
        if "id" in pending:
            try:
                approved = reviews.resolve(pending["id"], decision="approve",
                                           reviewer_code=reviews._reviewer_code, reviewer="local-reviewer")
                out["approved_preview"] = {"status": approved["status"],
                                           "provider_executed": False,
                                           "note": "documented reviewer disposition, not payment authorization"}
            except (PermissionError, ValueError, KeyError) as exc:
                out["approved_preview"] = {"status": "error", "note": str(exc)}
            # A second resolve must be refused: a review resolves exactly once.
            try:
                reviews.resolve(pending["id"], decision="approve",
                                reviewer_code=reviews._reviewer_code, reviewer="local-reviewer")
                out["double_resolve"] = {"status": "error", "note": "second resolve unexpectedly accepted"}
            except ValueError:
                out["double_resolve"] = {"status": "refused", "note": "a review resolves exactly once"}

        # Deny path: a fresh escalated review resolved with a deny.
        try:
            denied = reviews.request("escalate")
            result = reviews.resolve(denied["id"], decision="deny",
                                     reviewer_code=reviews._reviewer_code, reviewer="local-reviewer")
            out["denied"] = {"status": result["status"]}
        except (PermissionError, ValueError, KeyError) as exc:
            out["denied"] = {"status": "error", "note": str(exc)}

        all_ok = (out.get("missing_authority", {}).get("status") == "rejected"
                  and out.get("approved_preview", {}).get("status") == "approved_preview"
                  and out.get("double_resolve", {}).get("status") == "refused"
                  and out.get("denied", {}).get("status") == "denied")
        proof = store.append("safr_escalation_simulate", {**out, "provider_executed": False,
                                                           "sandbox_only": True, "all_passed": all_ok})
        return {"workflow": "safr_escalation", "outcome": "PASS" if all_ok else "FAIL",
                "all_passed": all_ok, "provider_executed": False, "sandbox_only": True,
                "results": out, "audit_event_id": proof["id"], "audit_hash": proof["entry_hash"]}

    @app.post("/api/reviews/{scenario}/request")
    def review_request(scenario: str, request: Request):
        authorize(request)
        try:
            return reviews.request(scenario)
        except KeyError:
            raise HTTPException(404, "Unknown scenario") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/reviews/{review_id}/resolve")
    async def review_resolve(review_id: str, request: Request):
        authorize(request)
        body = await request.json()
        try:
            return reviews.resolve(review_id, decision=body.get("decision", ""),
                                   reviewer_code=body.get("reviewer_code", ""), reviewer="local-reviewer")
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from None
        except KeyError:
            raise HTTPException(404, "No such review") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.get("/api/audit")
    def audit():
        return {"verification": store.verify(), "records": store.records(70)}

    return app
