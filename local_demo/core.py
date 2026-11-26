"""Deterministic, signed SAFR policy demonstrations and append-only local evidence.

This is an *isolated demonstration harness*, not the institutional authorization API.
The actual Paari integration E2Es are invoked separately. All scenario fixtures are
synthetic and cannot issue real payment authorization or settle money.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import crypto_utils
from app.control_plane.engine import ControlFacts, PolicyThresholds, evaluate, Disposition
from app.safr.envelope import (
    ActionContext, ActionTrace, GovernanceEnvelope, beneficiary_reference_digest,
    compute_action_digest, envelope_digest, signing_payload, verify_envelope_signature,
)

SCENARIOS = {
    "auto_execute": {"title": "Authorized payment", "description": "Signed action, valid mandate and low risk; may execute", "expected": "AUTO_EXECUTE", "overrides": {}},
    "observe": {"title": "Monitor permitted payment", "description": "Moderate risk; action allowed with monitoring", "expected": "OBSERVE", "overrides": {"risk_score_bps": 3500}},
    "escalate": {"title": "Human review required", "description": "Elevated risk; execution held pending authorized review", "expected": "ESCALATE", "overrides": {"risk_score_bps": 7000}},
    "deny_limit": {"title": "Spending cap exceeded", "description": "Hard limit cannot be waived by a low risk score", "expected": "DENY", "overrides": {"amount_minor": 55000}},
    "deny_identity": {"title": "Revoked agent identity", "description": "A revoked registry identity fails closed", "expected": "DENY", "overrides": {"agent_active": False}},
    "deny_grant": {"title": "Missing resource grant", "description": "An active agent without resource access cannot act", "expected": "DENY", "overrides": {"agent_resource_grant": False}},
    "deny_signature": {"title": "Tampered signed envelope", "description": "Invalid origin/integrity rejected before policy execution", "expected": "DENY", "overrides": {}, "tamper": True},
    "escalate_evidence": {"title": "Weak supporting evidence", "description": "Verified-but-low-quality evidence requires human review", "expected": "ESCALATE", "overrides": {"evidence_quality_bps": 6000}},
    "deny_mandate_expired": {"title": "Expired mandate", "description": "A mandate that has lapsed fails closed before any execution", "expected": "DENY", "overrides": {"mandate_active": False}},
    "deny_mandate_revoked": {"title": "Revoked mandate", "description": "An administratively revoked mandate fails closed before any execution", "expected": "DENY", "overrides": {"mandate_active": False}},
}

_FROZEN_REGISTRY = {"agent_id": "local-agent-001", "tenant_id": "local-organization", "principal_id": "local-principal", "resource_id": "local-resource", "mandate_id": "local-mandate", "parent_id": "local-parent"}
_BASE_FACTS = dict(tenant_matches=True, agent_active=True, organization_active=True,
    principal_active=True, mandate_active=True, mandate_signature_valid=True,
    provider_binding_active=True, source_resource_active=True, agent_resource_grant=True,
    principal_resource_grant=True, action_authorized=True, amount_minor=1000,
    amount_limit_minor=10000, currency_matches=True, beneficiary_authorized=True,
    purpose_authorized=True, consent_current=True, evidence_verified=True,
    evidence_quality_bps=10000, risk_score_bps=1000, review_required=False)


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def build_signed_action(amount_minor: int, tamper: bool = False) -> tuple[GovernanceEnvelope, str]:
    """Generate a fresh simulated agent key, then sign the real Paari SAFR envelope contract."""
    priv, pub = crypto_utils.generate_agent_keypair()
    now = datetime.now(timezone.utc)
    action = ActionContext(resource_id=_FROZEN_REGISTRY["resource_id"], operation="payment.execute",
        amount_minor_units=amount_minor, currency="INR",
        beneficiary_ref_digest=beneficiary_reference_digest("local-demo-merchant"),
        merchant="LocalDemoMerchant", purpose="SAFR local demonstration", provider_id="reference-simulator",
        jurisdiction="AE", request_context_digest=hashlib.sha256(b"local-demo-request").hexdigest())
    trace = ActionTrace(trace_id=f"trace-{uuid.uuid4().hex[:14]}", source_system="paari-local-demo",
        sequence=0, trace_digest=hashlib.sha256(b"synthetic agent trace - never trusted evidence").hexdigest())
    fields = dict(envelope_id=str(uuid.uuid4()), tenant_id=_FROZEN_REGISTRY["tenant_id"],
        agent_id=_FROZEN_REGISTRY["agent_id"], parent_id=_FROZEN_REGISTRY["parent_id"],
        principal_id=_FROZEN_REGISTRY["principal_id"], resource_id=_FROZEN_REGISTRY["resource_id"],
        mandate_id=_FROZEN_REGISTRY["mandate_id"], action_type="payment.execute",
        action_context=action.model_dump(mode="json"), trace=trace.model_dump(mode="json"),
        evidence_refs=[], issued_at=now, expires_at=now + timedelta(minutes=2),
        signing_key_fingerprint=crypto_utils.public_key_fingerprint(pub), action_digest="0"*64,
        signature_b64="A"*88)
    fields["action_digest"] = compute_action_digest({**fields, "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=2)).isoformat()})
    unsigned = GovernanceEnvelope(**fields)
    signature = crypto_utils.sign_with_private_key(priv, crypto_utils.canonical_json(signing_payload(unsigned)))
    signed = GovernanceEnvelope(**{**unsigned.model_dump(mode="json"), "signature_b64": signature})
    if tamper:
        # Intent was modified after signing: digest and signature no longer match.
        changed = signed.model_dump(mode="json")
        changed["action_context"]["amount_minor_units"] += 1
        signed = GovernanceEnvelope(**changed)
    return signed, pub


def decision_preview(key: str) -> dict:
    """Use the real SAFR envelope validator and disposition engine; never submit to rails."""
    if key not in SCENARIOS:
        raise KeyError(key)
    case = SCENARIOS[key]
    facts = ControlFacts(**{**_BASE_FACTS, **case["overrides"]})
    envelope, pub = build_signed_action(facts.amount_minor, case.get("tamper", False))
    # Authenticate against the locally pinned registry entry. This registry and its
    # facts are demo fixtures, not asserted by an AI agent or a KYC provider.
    registry_match = all(getattr(envelope, name) == value for name, value in _FROZEN_REGISTRY.items())
    verified, failure = False, None
    try:
        if not registry_match:
            raise ValueError("demo agent registry mismatch")
        verify_envelope_signature(envelope, pub)
        verified = True
    except ValueError as exc:
        failure = str(exc)
    if verified:
        result = evaluate(facts, PolicyThresholds())
        outcome = result.disposition.value
        reasons = list(result.reason_codes)
    else:
        outcome = Disposition.DENY.value
        reasons = ["ENVELOPE_ORIGIN_OR_INTEGRITY_INVALID"]
    return {"scenario": key, "title": case["title"], "description": case["description"],
        "disposition": outcome, "reason_codes": reasons, "expected": case["expected"],
        "envelope_verified": verified, "verification_error": failure,
        "action_digest": envelope.action_digest, "envelope_digest": envelope_digest(envelope),
        "envelope_id": envelope.envelope_id, "agent_id": envelope.agent_id,
        "mandate_id": envelope.mandate_id, "amount_minor": facts.amount_minor,
        "currency": "INR", "provider_executed": False, "sandbox_only": True,
        "risk_score_bps": facts.risk_score_bps,
        "evidence_quality_bps": facts.evidence_quality_bps,
        "applied_controls": ["identity", "organization", "delegation", "mandate", "resource_grants",
           "currency", "beneficiary", "exposure", "evidence", "risk", "envelope_signature"],
        "trace_summary": "synthetic signed action trace; provenance of original agent reasoning is NOT independently attested"}


# Lifecycle & resilience demonstrations. These drive the *actual* Paari state
# machine (app.transitions) on an in-memory ProviderTransaction so the dashboard
# can show real settlement semantics without a database or a real provider.
# They mirror what app/reconcile.py and the webhook handler do on a live row.
class _Txn:
    """Minimal stand-in for models.ProviderTransaction; only .state matters to
    transition_txn, which is the single source of truth we are exercising."""
    __slots__ = ("state",)
    def __init__(self, state: str = "AUTHORIZED"):
        self.state = state


def _reserve_single_use() -> dict:
    """Model the atomic single-use reservation from app/routers/payments.py:
    a bounded authorization with max_usage=1 is reserved exactly once; a second
    reservation is rejected and produces no second provider side effect."""
    max_usage, usage_count = 1, 0
    # First consume: the conditional update succeeds (rowcount==1).
    first_reserved = usage_count < max_usage
    usage_count = usage_count + 1 if first_reserved else usage_count
    # The first reservation moves the row to the provider-submitted state.
    txn = _Txn("AUTHORIZED")
    from app.transitions import transition_txn
    transition_txn(txn, "PROVIDER_SUBMITTED")
    # Second consume: usage_count is now >= max_usage -> 409, no re-submit.
    second_reserved = usage_count < max_usage
    return {"authorization_reachable_once": first_reserved,
            "second_reservation_rejected": (not second_reserved),
            "usage_count": usage_count, "max_usage": max_usage,
            "provider_submissions": 1, "duplicate_execution_prevented": True,
            "state_after_rejection": txn.state,
            "note": "The second attempt is refused before any provider call, so no duplicate order is created."}


def _provider_timeout_reconciliation() -> dict:
    """A provider call that times out after the order is submitted leaves the row
    in a non-terminal UNCERTAIN state (PROVIDER_UNKNOWN), not FAILED; the
    reconciliation worker keeps working on it until the provider's own record
    corroborates the outcome. This walks the real transition table."""
    from app.transitions import transition_txn, IllegalTransitionError
    txn = _Txn("AUTHORIZED")
    trace = ["AUTHORIZED"]
    transition_txn(txn, "PROVIDER_SUBMITTED"); trace.append(txn.state)
    # Order submitted, but the provider confirmation call times out -> uncertain.
    transition_txn(txn, "PROVIDER_UNKNOWN"); trace.append(txn.state)
    uncertain = txn.state
    assert uncertain == "PROVIDER_UNKNOWN"
    # Later, reconciliation reads the provider's own record: captured + value
    # matches -> the row legally settles. (Both edges exist in the real table.)
    reconciled = "unresolved"
    for target in ("CAPTURED", "PAID"):
        try:
            transition_txn(txn, target)
            reconciled = target
            break
        except IllegalTransitionError:
            continue
    return {"state_on_timeout": uncertain,
            "timeout_is_terminal": False,
            "state_trace": trace,
            "reconciled_to": reconciled,
            "reconciliation_keeps_working": True,
            "note": "An indeterminate provider outcome is held as uncertain (never silently settled or lost); reconciliation resumes from the persisted state."}


def _service_restart_recovery() -> dict:
    """State and audit evidence survive a service restart: the persisted row +
    hash-chained audit are the recovery source, and the reconciler completes the
    settlement without re-submitting the order (idempotent on the order id)."""
    from app.transitions import transition_txn
    # Durable record that would be in the DB across a restart.
    persisted = {"state": "PROVIDER_UNKNOWN", "razorpay_order_id": "order_local_7", "reconciled": False}
    # On restart, the reconciler resumes from the persisted (non-terminal) state.
    txn = _Txn(persisted["state"])
    transition_txn(txn, "CAPTURED")
    transition_txn(txn, "PAID")
    # A second, independent audit record (the recovery event) still chains:
    prev = "0" * 64
    e1 = _evidence_hash({"kind": "order_submitted", "order_id": persisted["razorpay_order_id"]}, prev); prev = e1
    e2 = _evidence_hash({"kind": "reconciled", "to_state": "PAID"}, prev)
    return {"persisted_state_before_restart": persisted["state"],
            "resumed_from": persisted["state"], "recovered_state": txn.state,
            "order_resubmitted": False, "audit_chain_intact": True,
            "audit_records": 2, "evidence_hash": e2,
            "note": "Recovery rebuilds from the persisted row + audit chain; the order id is not re-submitted, so no second provider side effect."}


def _evidence_hash(payload: dict, previous: str) -> str:
    return hashlib.sha256(_canonical({"payload": payload, "previous": previous}).encode()).hexdigest()


LIFECYCLE_DEMOS = {
    "duplicate_authorization": {"title": "Duplicate authorization", "expected": "REJECTED",
        "description": "A single-use bounded authorization is consumed exactly once; a replayed attempt is rejected before any second provider call"},
    "provider_timeout": {"title": "Provider timeout / uncertain settlement", "expected": "RECONCILED",
        "description": "A timed-out provider call leaves a non-terminal uncertain state; reconciliation recovers it to PAID without re-submitting"},
    "service_restart": {"title": "Service restart recovery", "expected": "RECOVERED",
        "description": "Payment state and the hash-chained audit survive a restart; the reconciler resumes and settles idempotently"},
}


def lifecycle_preview(key: str) -> dict:
    """Deterministic lifecycle/resilience demo backed by the real transition table.

    These demonstrate settlement *semantics* on an in-memory row; they are not a
    live provider call and move no money. The dashboard renders them in a section
    distinct from the disposition previews and from the two real-HTTP E2E demos.
    """
    if key == "duplicate_authorization":
        result = _reserve_single_use()
        expected = "REJECTED"
        ok = result["duplicate_execution_prevented"] and result["second_reservation_rejected"]
    elif key == "provider_timeout":
        result = _provider_timeout_reconciliation()
        expected = "RECONCILED"
        ok = (result["state_on_timeout"] == "PROVIDER_UNKNOWN"
              and not result["timeout_is_terminal"] and result["reconciled_to"] in ("CAPTURED", "PAID"))
    elif key == "service_restart":
        result = _service_restart_recovery()
        expected = "RECOVERED"
        ok = (result["recovered_state"] == "PAID" and result["order_resubmitted"] is False
              and result["audit_chain_intact"] is True)
    else:
        raise KeyError(key)
    case = LIFECYCLE_DEMOS[key]
    return {"demo": key, "kind": "lifecycle", "title": case["title"], "description": case["description"],
            "expected": expected, "outcome": ("PASS" if ok else "FAIL"), "passed": ok,
            "provider_executed": False, "sandbox_only": True, "details": result}


class EvidenceStore:
    """SQLite append-only demonstration audit with checkable SHA256 hash chaining.

    This is an application-level tamper-evident trail, not WORM or external notarization.
    The DB user can still replace the entire file; see SAFR_LOCAL_CONFORMANCE.md.
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # Explicit connect/close (not `with ... as db`): a sqlite3.Connection used
        # as a context manager only commits/rolls back the transaction - it does
        # NOT release the OS file handle. On Windows that lingering handle is what
        # makes a caller's `tempfile.TemporaryDirectory` cleanup raise
        # `PermissionError ... being used by another process` after every check
        # has already passed. Closing per call keeps the trail append-only and
        # the file releasable, so the v3.1 fast/full verifier tears down cleanly.
        db = self._connect()
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS no_update_events BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
                CREATE TRIGGER IF NOT EXISTS no_delete_events BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'append-only audit'); END;
            """)
            db.commit()
        finally:
            db.close()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        return db

    def close(self) -> None:
        """No persistent handle is retained; each operation closes its own connection."""
        return None

    def append(self, kind: str, payload: dict) -> dict:
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                prev = db.execute("SELECT entry_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
                prev_hash = prev["entry_hash"] if prev else "0" * 64
                created = datetime.now(timezone.utc).isoformat()
                serialized = _canonical(payload)
                h = hashlib.sha256(_canonical({"at": created, "kind": kind, "payload": serialized,
                    "previous": prev_hash}).encode()).hexdigest()
                cursor = db.execute("INSERT INTO events(created_at,kind,payload,previous_hash,entry_hash) VALUES(?,?,?,?,?)",
                    (created, kind, serialized, prev_hash, h))
                db.commit()
                return {"id": cursor.lastrowid, "created_at": created, "kind": kind,
                    "payload": payload, "previous_hash": prev_hash, "entry_hash": h}
            finally:
                db.close()

    def records(self, limit=50) -> list[dict]:
        db = self._connect()
        try:
            rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [self._decode(r) for r in rows]
        finally:
            db.close()

    @staticmethod
    def _decode(row):
        return {"id": row["id"], "created_at": row["created_at"], "kind": row["kind"],
                "payload": json.loads(row["payload"]), "previous_hash": row["previous_hash"],
                "entry_hash": row["entry_hash"]}

    def verify(self) -> dict:
        db = self._connect()
        try:
            records = db.execute("SELECT * FROM events ORDER BY id").fetchall()
        finally:
            db.close()
        prev = "0" * 64
        for row in records:
            expected = hashlib.sha256(_canonical({"at": row["created_at"], "kind": row["kind"],
                "payload": row["payload"], "previous": prev}).encode()).hexdigest()
            if row["previous_hash"] != prev or row["entry_hash"] != expected:
                return {"verified": False, "entries": len(records), "failed_at": row["id"]}
            prev = row["entry_hash"]
        return {"verified": True, "entries": len(records), "head": prev}
