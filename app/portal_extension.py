"""Read-only parent dashboard feeds and Paari-admin review queue for the product portal.

Additive v3.7.1 integration extension. The existing v3.6 onboarding endpoints remain
responsible for registration, login, agent registration and approval decisions.

Install:
    1. Copy this file to app/portal_extension.py
    2. In app/main.py add:
           from app.portal_extension import router as product_portal_router
           app.include_router(product_portal_router)

The portal UI must be served from the same origin as the API (recommended) or the
operator must configure a strict CORS allowlist. No admin key or parent token is
embedded in the HTML. Parent tokens are submitted by the signed-in parent; the
Paari admin key is entered only in the operations UI and validated server-side.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app import models, security as platform_security
from app.database import get_db
from app.v36 import models as v36_models
from app.v36 import security as v36_security
from app.v36.router import parent_auth

router = APIRouter(prefix="/portal/v1", tags=["product-portal"])


class ParentReviewRequest(BaseModel):
    approve: bool
    identity_checked: bool = False
    contact_checked: bool = False
    representative_authority_checked: bool = False
    reviewer_note: str = Field(min_length=5, max_length=1000)


class ParentPaymentReviewRequest(BaseModel):
    approve: bool
    reviewer_password: SecretStr
    reviewer_note: str = Field(min_length=5, max_length=1000)


def _parent_from_header(authorization: str, db: Session) -> models.ParentAuthority:
    v36_security.sandbox_only()
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Parent login required")
    return parent_auth(authorization[7:].strip(), db)


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if getattr(value, "tzinfo", None) is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


@router.get("/health")
def portal_health():
    return {"service": "paari-product-portal-api", "status": "ok", "version": "3.7.1"}


@router.get("/admin/parents/pending")
def pending_parent_applications(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Return the Paari manual-review queue; raw PAN/GSTIN is never stored/returned."""
    v36_security.sandbox_only()
    if not platform_security.is_admin_key(x_admin_api_key):
        raise HTTPException(401, "Missing or invalid Paari administrator credentials")
    import os
    bound_org = os.environ.get("PAARI_ADMIN_ORG", "").strip()
    query = (
        db.query(models.ParentAuthority, v36_models.ParentAccount)
        .join(v36_models.ParentAccount, v36_models.ParentAccount.parent_pk == models.ParentAuthority.id)
        .filter(models.ParentAuthority.status == models.ParentStatus.PENDING_VERIFICATION)
    )
    if bound_org:
        query = query.filter(models.ParentAuthority.org_id == bound_org)
    rows = query.order_by(models.ParentAuthority.created_at.asc()).limit(200).all()
    return {
        "items": [
            {
                "parent_id": parent.parent_id,
                "name": parent.name,
                "parent_type": account.kind,
                "status": _enum_value(parent.status),
                "trust_tier": parent.trust_tier,
                "identifier_last4": account.identifier_last4,
                "representative_name": account.representative_name,
                "representative_email": account.representative_email,
                "representative_phone": account.representative_phone,
                "address": account.address,
                "created_at": _iso(parent.created_at),
            }
            for parent, account in rows
        ]
    }


@router.post("/admin/parents/{parent_id}/review")
def review_parent_application(
    parent_id: str,
    req: ParentReviewRequest,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Secure portal facade over the same v3.6 manual approval gate."""
    v36_security.sandbox_only()
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent or not db.query(v36_models.ParentAccount).filter_by(parent_pk=parent.id).first():
        raise HTTPException(404, "Onboarded parent not found")
    platform_security.require_admin_org(x_admin_api_key, parent.org_id)
    if parent.status != models.ParentStatus.PENDING_VERIFICATION:
        raise HTTPException(409, "Parent is not awaiting review")
    checks = {
        "identity_checked": req.identity_checked,
        "contact_checked": req.contact_checked,
        "representative_authority_checked": req.representative_authority_checked,
    }
    if req.approve and not all(checks.values()):
        raise HTTPException(422, "Approval requires all manual checklist items")
    parent.status = models.ParentStatus.ACTIVE if req.approve else models.ParentStatus.REJECTED
    parent.trust_tier = "admin_approved" if req.approve else "self_asserted"
    if req.approve:
        from datetime import datetime
        parent.verified_at = datetime.now(timezone.utc)
    db.add(v36_models.ManualApproval(
        subject_type="parent",
        subject_id=parent_id,
        decision="approved" if req.approve else "rejected",
        checks=checks,
        reviewer_note=req.reviewer_note,
    ))
    db.commit()
    return {
        "parent_id": parent_id,
        "status": _enum_value(parent.status),
        "verification_method": "manual_admin_review_not_kyc",
    }


@router.get("/parent/overview")
def parent_overview(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Return the authenticated parent's tenant-scoped account and Paari profile."""
    parent = _parent_from_header(authorization, db)
    account = db.query(v36_models.ParentAccount).filter_by(parent_pk=parent.id).first()
    tenant = db.query(models.Organization).filter_by(org_id=parent.org_id).first()
    provider_account = db.query(models.ProviderAccount).filter_by(org_id=parent.org_id).first()
    agent_rows = db.query(models.Agent).filter_by(parent_pk=parent.id).all()
    agent_ids = [row.agent_id for row in agent_rows]
    intent_q = (db.query(models.PaymentIntent).filter(models.PaymentIntent.agent_id.in_(agent_ids))
                if agent_ids else db.query(models.PaymentIntent).filter(models.PaymentIntent.id == -1))
    total = intent_q.count()
    from sqlalchemy import func
    decision_rows = (
        db.query(models.PaymentIntent.decision, func.count(models.PaymentIntent.id))
        .filter(models.PaymentIntent.agent_id.in_(agent_ids) if agent_ids else models.PaymentIntent.id == -1)
        .group_by(models.PaymentIntent.decision).all()
    )
    decisions = {_enum_value(k): int(v) for k, v in decision_rows}
    pending_reviews = (db.query(models.PaymentIntent)
        .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
        .outerjoin(models.ControlPlaneDecision,
                   models.ControlPlaneDecision.intent_id == models.PaymentIntent.intent_id)
        .filter(models.Agent.parent_pk == parent.id,
                models.PaymentIntent.decision == models.GovernanceDecision.REVIEW)
        .filter((models.PaymentIntent.mfa_required.is_(True)) |
                (models.ControlPlaneDecision.disposition == "ESCALATE"))
        .count())
    return {
        "parent": {
            "parent_id": parent.parent_id,
            "name": parent.name,
            "parent_type": account.kind if account else parent.parent_type,
            "org_id": parent.org_id,
            "status": _enum_value(parent.status),
            "trust_tier": parent.trust_tier,
            "created_at": _iso(parent.created_at),
            "verified_at": _iso(parent.verified_at),
            "account": ({
                "registration_reference": account.registration_ref,
                "registration_id_last4": account.identifier_last4,
                "registration_id_type": "GSTIN" if account.kind == "organization" else "PAN",
                "representative_name": account.representative_name,
                "representative_email": account.representative_email,
                "representative_phone": account.representative_phone,
                "registered_address": account.address,
            } if account else None),
            "tenant": ({
                "tenant_id": tenant.org_id,
                "registered_name": tenant.name,
                "status": tenant.status,
                "created_at": _iso(tenant.created_at),
                "provider_account_configured": bool(provider_account),
                "provider_name": provider_account.provider_name if provider_account else None,
            } if tenant else None),
        },
        "agent_count": len(agent_ids),
        "active_agent_count": sum(1 for row in agent_rows if _enum_value(row.status) == "active"),
        "payment_request_count": total,
        "pending_parent_reviews": pending_reviews,
        "decisions": {
            "allow": decisions.get("allow", 0),
            "review": decisions.get("review", 0),
            "deny": decisions.get("deny", 0),
        },
    }


@router.get("/parent/reviews")
def parent_payment_reviews(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Show only this parent's SAFR escalation and parent-signed step-up queue."""
    parent = _parent_from_header(authorization, db)
    rows = (db.query(models.PaymentIntent, models.Agent, models.ControlPlaneDecision)
        .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
        .outerjoin(models.ControlPlaneDecision,
                   models.ControlPlaneDecision.intent_id == models.PaymentIntent.intent_id)
        .filter(models.Agent.parent_pk == parent.id,
                models.PaymentIntent.decision == models.GovernanceDecision.REVIEW,
                or_(models.PaymentIntent.mfa_required.is_(True),
                    models.ControlPlaneDecision.disposition == "ESCALATE"))
        .order_by(models.PaymentIntent.created_at.asc()).limit(100).all())
    items = []
    for intent, agent, decision in rows:
        is_safr_escalation = bool(decision and str(decision.disposition).upper() == "ESCALATE")
        items.append({
            "intent_id": intent.intent_id,
            "transaction_id": intent.transaction_id,
            "agent_id": agent.agent_id,
            "agent_name": agent.name,
            "merchant": intent.merchant,
            "purpose": intent.purpose,
            "amount_minor_units": intent.amount_minor_units,
            "currency": intent.currency,
            "decision": _enum_value(intent.decision),
            "review_type": "SAFR_ESCALATION" if is_safr_escalation else "PARENT_SIGNED_STEP_UP",
            "safr_disposition": decision.disposition if decision else None,
            "safr_policy": decision.policy_name if decision else None,
            "safr_policy_version": decision.policy_version if decision else None,
            "risk_score_bps": decision.risk_score_bps if decision else None,
            "evidence_quality_bps": decision.evidence_quality_bps if decision else None,
            "reasons": list(dict.fromkeys((intent.reasons or []) + (decision.reason_codes if decision else []))),
            "created_at": _iso(intent.created_at),
            "review_expires_at": _iso(intent.review_expires_at),
        })
    return {"parent_id": parent.parent_id, "org_id": parent.org_id, "items": items}


@router.post("/parent/reviews/{intent_id}/decision")
def decide_parent_payment_review(
    intent_id: str,
    req: ParentPaymentReviewRequest,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Apply a parent decision using fresh password re-auth and the registered parent signing key.

    This is a sandbox bridge around the existing parent-signature review flow. The
    key remains encrypted at rest; the password is never persisted or audited.
    """
    parent = _parent_from_header(authorization, db)
    account = (db.query(v36_models.ParentAccount)
        .filter_by(parent_pk=parent.id).with_for_update().first())
    now = datetime.now(timezone.utc)
    if not account:
        raise HTTPException(401, "Parent password re-authentication failed")
    if account.locked_until and account.locked_until > now:
        raise HTTPException(429, "Parent account is temporarily locked; try again later")
    if not v36_security.check_password(req.reviewer_password.get_secret_value(), account.password_hash):
        account.failed_login_attempts = int(account.failed_login_attempts or 0) + 1
        if account.failed_login_attempts >= 5:
            from datetime import timedelta
            account.locked_until = now + timedelta(minutes=15)
        db.commit()
        raise HTTPException(401, "Parent password re-authentication failed")
    if account.failed_login_attempts or account.locked_until:
        account.failed_login_attempts = 0
        account.locked_until = None
        db.flush()
    row = (db.query(models.PaymentIntent, models.Agent)
        .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
        .filter(models.PaymentIntent.intent_id == intent_id,
                models.Agent.parent_pk == parent.id)
        .with_for_update().first())
    if not row:
        raise HTTPException(404, "Payment review not found for this parent")
    intent, agent = row
    decision = db.query(models.ControlPlaneDecision).filter_by(
        org_id=intent.org_id, intent_id=intent.intent_id).first()
    is_safr_escalation = bool(decision and str(decision.disposition).upper() == "ESCALATE")
    if intent.decision != models.GovernanceDecision.REVIEW or not (intent.mfa_required or is_safr_escalation):
        raise HTTPException(409, "Payment is not awaiting a parent decision")
    if intent.review_expires_at and intent.review_expires_at <= datetime.now(timezone.utc):
        raise HTTPException(410, "Payment review has expired")

    # Each decision gets a fresh, transaction-bound, single-use challenge.
    db.query(models.MFAChallenge).filter_by(intent_id=intent_id, used=False).update(
        {"used": True}, synchronize_session=False)
    challenge = models.MFAChallenge(
        intent_id=intent.intent_id, org_id=intent.org_id,
        expires_at=datetime.now(timezone.utc) + platform_security.MFA_CHALLENGE_TTL,
    )
    db.add(challenge)
    db.flush()
    from app import crypto_utils, schemas as payment_schemas
    context = {
        "challenge_id": challenge.challenge_id,
        "intent_id": intent.intent_id,
        "agent_id": intent.agent_id,
        "transaction_id": intent.transaction_id,
        "merchant": intent.merchant,
        "amount_minor_units": intent.amount_minor_units,
        "currency": intent.currency,
        "nonce": challenge.nonce,
    }
    from app.routers import payments as payment_routes
    if req.approve:
        signed_context = crypto_utils.canonical_json({"purpose": "paari_mfa_step_up", **context})
        signature = v36_security.sign_parent(account.encrypted_signing_key, signed_context)
        result = payment_routes.verify_mfa_challenge(payment_schemas.MFAVerifyRequest(
            intent_id=intent.intent_id, challenge_id=challenge.challenge_id,
            parent_signature_b64=signature), db)
        final_decision = "allow"
        authorization_issued = bool(result.authorization)
    else:
        signed_context = crypto_utils.canonical_json({"purpose": "paari_mfa_step_up_reject", **context})
        signature = v36_security.sign_parent(account.encrypted_signing_key, signed_context)
        result = payment_routes.reject_mfa_challenge(payment_schemas.MFAVerifyRequest(
            intent_id=intent.intent_id, challenge_id=challenge.challenge_id,
            parent_signature_b64=signature), db)
        final_decision = "deny"
        authorization_issued = False

    from app.audit import record_audit
    record_audit(db, transaction_id=intent.transaction_id, agent_id=agent.agent_id,
        parent_id=parent.parent_id, kind="parent_portal_review_note",
        detail={"intent_id": intent.intent_id, "decision": final_decision,
                "review_type": "SAFR_ESCALATION" if is_safr_escalation else "PARENT_SIGNED_STEP_UP",
                "reviewer_note": req.reviewer_note,
                "reviewed_via": "organization_portal_password_reauthentication",
                "authorization_issued": authorization_issued}, org_id=parent.org_id)
    db.commit()
    return {"intent_id": intent.intent_id, "decision": final_decision,
            "authorization_issued": authorization_issued,
            "authorization_expires_at": (result.authorization.get("expires_at") if req.approve and result.authorization else None),
            "agent_authorization_endpoint": f"/payments/intents/{intent.intent_id}/authorization" if authorization_issued else None,
            "message": "Parent decision recorded. The agent runtime can retrieve its bounded authorization using its own authenticated session." if req.approve else "Payment denied by the parent. No authorization was issued."}


@router.get("/parent/agents")
def parent_agents(
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    parent = _parent_from_header(authorization, db)
    rows = (
        db.query(models.Agent, v36_models.AgentRegistration)
        .outerjoin(v36_models.AgentRegistration, v36_models.AgentRegistration.agent_id == models.Agent.agent_id)
        .filter(models.Agent.parent_pk == parent.id)
        .order_by(models.Agent.created_at.desc())
        .limit(200).all()
    )
    return {"items": [
        {
            "agent_id": agent.agent_id,
            "name": agent.name,
            "agent_type": agent.agent_type,
            "purpose": agent.purpose,
            "description": registration.agent_description if registration else "",
            "software_operator": registration.software_operator if registration else "",
            "escalation_contact": {
                "name": registration.approver_name,
                "email": registration.approver_email,
                "phone": registration.approver_phone,
            } if registration else None,
            "status": _enum_value(agent.status),
            "capabilities": agent.granted_capabilities or [],
            "payment_limit_minor_units": agent.payment_limit_minor_units,
            "currency": agent.currency,
            "valid_until": _iso(agent.valid_until),
            "created_at": _iso(agent.created_at),
        }
        for agent, registration in rows
    ]}


@router.get("/parent/transactions")
def parent_transactions(
    limit: int = Query(default=100, ge=1, le=200),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Parent-scoped request feed with persisted decision reasons and provider provenance."""
    parent = _parent_from_header(authorization, db)
    rows = (
        db.query(models.PaymentIntent, models.Agent, models.ProviderTransaction)
        .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
        .outerjoin(models.ProviderTransaction, models.ProviderTransaction.intent_id == models.PaymentIntent.intent_id)
        .filter(models.Agent.parent_pk == parent.id)
        .order_by(models.PaymentIntent.created_at.desc())
        .limit(limit).all()
    )
    return {"items": [
        {
            "intent_id": intent.intent_id,
            "transaction_id": intent.transaction_id,
            "agent_id": intent.agent_id,
            "agent_name": agent.name,
            "merchant": intent.merchant,
            "amount_minor_units": intent.amount_minor_units,
            "currency": intent.currency,
            "purpose": intent.purpose,
            "decision": _enum_value(intent.decision),
            "reasons": intent.reasons or [],
            "created_at": _iso(intent.created_at),
            "mfa_required": bool(intent.mfa_required),
            "mfa_verified": bool(intent.mfa_verified),
            "provider_state": provider_tx.state if provider_tx else None,
            "provider_environment": provider_tx.provider_environment if provider_tx else None,
            "provider_updated_at": _iso(provider_tx.updated_at) if provider_tx else None,
            "reconciled_at": _iso(provider_tx.reconciled_at) if provider_tx else None,
        }
        for intent, agent, provider_tx in rows
    ]}


@router.get("/parent/transactions/{intent_id}")
def parent_transaction_detail(
    intent_id: str,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    parent = _parent_from_header(authorization, db)
    row = (
        db.query(models.PaymentIntent, models.Agent)
        .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
        .filter(models.PaymentIntent.intent_id == intent_id, models.Agent.parent_pk == parent.id)
        .first()
    )
    if not row:
        raise HTTPException(404, "Payment request not found for this parent")
    intent, agent = row
    provider_tx = db.query(models.ProviderTransaction).filter_by(intent_id=intent.intent_id).first()
    events = (
        db.query(models.AuditEvent)
        .filter_by(transaction_id=intent.transaction_id, agent_id=intent.agent_id, org_id=agent.org_id)
        .order_by(models.AuditEvent.id.asc()).all()
    )
    from app.audit import verify_chain
    chain_verified = bool(events) and verify_chain(db, intent.transaction_id)
    return {
        "intent": {
            "intent_id": intent.intent_id,
            "transaction_id": intent.transaction_id,
            "agent_id": intent.agent_id,
            "agent_name": agent.name,
            "merchant": intent.merchant,
            "amount_minor_units": intent.amount_minor_units,
            "currency": intent.currency,
            "purpose": intent.purpose,
            "decision": _enum_value(intent.decision),
            "reasons": intent.reasons or [],
            "created_at": _iso(intent.created_at),
            "mfa_required": bool(intent.mfa_required),
            "mfa_verified": bool(intent.mfa_verified),
        },
        "provider": None if not provider_tx else {
            "state": provider_tx.state,
            "environment": provider_tx.provider_environment,
            "key_id_prefix": provider_tx.provider_key_id_prefix,
            "api_base": provider_tx.provider_api_base,
            "updated_at": _iso(provider_tx.updated_at),
            "reconciled_at": _iso(provider_tx.reconciled_at),
            "attempts": provider_tx.attempts,
            "last_error": provider_tx.last_error,
        },
        "audit": {
            "chain_verified": chain_verified,
            "events": [{
                "event_id": event.id,
                "kind": event.kind,
                "created_at": _iso(event.created_at),
                "detail": event.detail or {},
                "prev_hash": event.prev_hash,
                "event_hash": event.event_hash,
            } for event in events],
        },
    }

# ---------------------------------------------------------------------------
# Agent Card QR and public signature verification
# ---------------------------------------------------------------------------

@router.get("/public/agent-cards/{agent_id}/verify")
def verify_public_agent_card(agent_id: str, db: Session = Depends(get_db)):
    """Return a safe public Agent Card and verify its Paari signature.

    This endpoint intentionally returns only the public Agent Card fields. It never
    returns the agent credential JWT, private key, parent password, or session token.
    The Agent Card itself is already exposed by the core public GET /agents/{id}/card
    route; this facade adds an explicit signature_valid result for QR verification.
    """
    from datetime import datetime
    from app.routers.agents import get_agent_card

    card = get_agent_card(agent_id, db)
    card_data = card.model_dump(mode="json")
    signature = card_data.pop("card_signature_b64", "")
    card_data.pop("paari_public_key_pem", None)
    valid = bool(signature) and platform_security.verify_agent_card(card_data, signature)
    # Public key is not required in the response because verification is performed
    # by the Paari backend against its active configured signing key.
    public_card = card.model_dump(mode="json")
    return {
        "signature_valid": valid,
        "verification_status": "verified" if valid else "invalid",
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "agent_card": public_card,
    }


@router.get("/agent-cards/{agent_id}/qr.svg")
def agent_card_qr_svg(
    agent_id: str,
    request: Request,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Generate a private parent-scoped QR linking to public card verification.

    QR content is a URL containing only the agent ID. It does not encode card
    credentials, authorization tokens, or private key material.
    """
    import io
    from urllib.parse import quote

    parent = _parent_from_header(authorization, db)
    agent = db.query(models.Agent).filter_by(agent_id=agent_id, parent_pk=parent.id).first()
    if not agent:
        # Do not reveal whether an agent ID belongs to another parent.
        raise HTTPException(404, "Agent not found")

    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError as exc:  # pragma: no cover - dependency is included in portal requirements
        raise HTTPException(503, "QR generation is unavailable; install requirements-portal.txt") from exc

    portal_url = str(request.base_url).rstrip("/") + "/organization?verify-agent-card=" + quote(agent_id, safe="")
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(portal_url)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return Response(
        content=output.getvalue(),
        media_type="image/svg+xml",
        headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
    )



# ---------------------------------------------------------------------------
# Paari Platform Console: cross-tenant internal-operations endpoints
# All /platform/* routes require the root Paari administrator key.
# ---------------------------------------------------------------------------

class PlatformAgentRevokeRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=160)


class TenantProvisionRequest(BaseModel):
    parent_id: str
    org_id: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=1, max_length=200)


def _require_platform_admin(x_admin_api_key: str):
    """Inline root-admin gate reused across every /platform/* route."""
    v36_security.sandbox_only()
    if not platform_security.is_admin_key(x_admin_api_key):
        raise HTTPException(401, "Platform administrator credentials required")


@router.get("/platform/overview")
def platform_overview(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Cross-tenant counts, latest audit events and attention items."""
    _require_platform_admin(x_admin_api_key)
    tenants = db.query(models.Organization).count()
    parents = db.query(models.ParentAuthority).count()
    agents = db.query(models.Agent).count()
    intents = db.query(models.PaymentIntent).count()
    pending = db.query(models.ParentAuthority).filter(
        models.ParentAuthority.status == models.ParentStatus.PENDING_VERIFICATION).count()
    paid = (db.query(models.ProviderTransaction)
            .filter(models.ProviderTransaction.state == "PAID",
                    models.ProviderTransaction.reconciled_at.isnot(None))
            .count())
    recent = (db.query(models.AuditEvent)
              .order_by(models.AuditEvent.id.desc()).limit(10).all())

    attention = []
    if pending:
        attention.append({"label": f"{pending} pending parent review(s)",
                          "description": "Parent application(s) awaiting Paari manual review",
                          "status": "pending"})
    unknowns = (db.query(models.ProviderTransaction)
                .filter(models.ProviderTransaction.state == "PROVIDER_UNKNOWN").count())
    if unknowns:
        attention.append({"label": f"{unknowns} unresolved provider outcome(s)",
                          "description": "Provider outcomes requiring reconciliation",
                          "status": "review"})

    return {
        "counts": {"tenants": tenants, "parents": parents, "agents": agents,
                   "payment_intents": intents, "pending_parents": pending,
                   "confirmed_paid": paid},
        "recent_audit": [{"kind": e.kind, "org_id": e.org_id,
                          "transaction_id": e.transaction_id,
                          "created_at": _iso(e.created_at)} for e in recent],
        "attention": attention,
    }


@router.get("/platform/parents")
def platform_parents(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Full parent directory with type, contact, tenant binding and status."""
    _require_platform_admin(x_admin_api_key)
    rows = (db.query(models.ParentAuthority, v36_models.ParentAccount)
            .outerjoin(v36_models.ParentAccount,
                       v36_models.ParentAccount.parent_pk == models.ParentAuthority.id)
            .order_by(models.ParentAuthority.created_at.desc()).limit(500).all())
    items = []
    for parent, account in rows:
        items.append({
            "parent_id": parent.parent_id,
            "name": parent.name,
            "parent_type": account.kind if account else "core",
            "contact": account.representative_email if account else parent.contact,
            "identifier_last4": account.identifier_last4 if account else None,
            "org_id": parent.org_id,
            "trust_tier": parent.trust_tier,
            "status": _enum_value(parent.status),
            "created_at": _iso(parent.created_at),
        })
    return {"items": items}


@router.get("/platform/parents/pending")
def platform_pending_parents(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Cross-tenant pending parent queue for the platform console."""
    _require_platform_admin(x_admin_api_key)
    rows = (db.query(models.ParentAuthority, v36_models.ParentAccount)
            .join(v36_models.ParentAccount,
                  v36_models.ParentAccount.parent_pk == models.ParentAuthority.id)
            .filter(models.ParentAuthority.status == models.ParentStatus.PENDING_VERIFICATION)
            .order_by(models.ParentAuthority.created_at.asc()).limit(500).all())
    return {"items": [
        {
            "parent_id": p.parent_id,
            "name": p.name,
            "parent_type": a.kind,
            "status": _enum_value(p.status),
            "identifier_last4": a.identifier_last4,
            "representative_name": a.representative_name,
            "representative_email": a.representative_email,
            "representative_phone": a.representative_phone,
            "created_at": _iso(p.created_at),
        }
        for p, a in rows
    ]}


@router.post("/platform/parents/{parent_id}/review")
def platform_review_parent(
    parent_id: str,
    req: ParentReviewRequest,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Platform-console version of the parent approval gate (no org scoping)."""
    _require_platform_admin(x_admin_api_key)
    parent = db.query(models.ParentAuthority).filter_by(parent_id=parent_id).first()
    if not parent:
        raise HTTPException(404, "Parent not found")
    if parent.status != models.ParentStatus.PENDING_VERIFICATION:
        raise HTTPException(409, "Parent is not awaiting review")
    checks = {
        "identity_checked": req.identity_checked,
        "contact_checked": req.contact_checked,
        "representative_authority_checked": req.representative_authority_checked,
    }
    if req.approve and not all(checks.values()):
        raise HTTPException(422, "Approval requires all manual checklist items")
    parent.status = models.ParentStatus.ACTIVE if req.approve else models.ParentStatus.REJECTED
    parent.trust_tier = "admin_approved" if req.approve else "self_asserted"
    if req.approve:
        parent.verified_at = datetime.now(timezone.utc)
    db.add(v36_models.ManualApproval(
        subject_type="parent", subject_id=parent_id,
        decision="approved" if req.approve else "rejected",
        checks=checks, reviewer_note=req.reviewer_note,
    ))
    db.commit()
    return {"parent_id": parent_id, "status": _enum_value(parent.status)}


@router.get("/platform/providers/pending")
def platform_pending_providers(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    rows = (db.query(v36_models.ProviderApplication)
            .filter(v36_models.ProviderApplication.status.in_(["pending_approval", "pending"]))
            .order_by(v36_models.ProviderApplication.created_at.asc()).all())
    return {"items": [
        {"provider_id": p.provider_id, "legal_name": p.legal_name,
         "registration_number": p.registration_number,
         "contact_email": p.contact_email,
         "representative_name": p.representative_name,
         "payment_rail": p.payment_rail,
         "currencies": p.currencies or [],
         "status": p.status,
         "created_at": _iso(p.created_at)}
        for p in rows
    ]}


@router.post("/platform/providers/{provider_id}/review")
def platform_review_provider(
    provider_id: str,
    req: ParentReviewRequest,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    row = db.query(v36_models.ProviderApplication).filter_by(provider_id=provider_id).first()
    if not row:
        raise HTTPException(404, "Provider application not found")
    checks = {
        "identity_checked": req.identity_checked,
        "contact_checked": req.contact_checked,
        "representative_authority_checked": req.representative_authority_checked,
    }
    if req.approve and not all(checks.values()):
        raise HTTPException(422, "Provider approval requires all manual checklist items")
    row.status = "approved" if req.approve else "rejected"
    db.commit()
    return {"provider_id": provider_id, "status": row.status}


@router.get("/platform/tenants")
def platform_tenants(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    rows = db.query(models.Organization).order_by(models.Organization.created_at.desc()).all()
    items = []
    for org in rows:
        parent_count = (db.query(models.ParentAuthority)
                       .filter(models.ParentAuthority.org_id == org.org_id).count())
        agent_count = (db.query(models.Agent)
                      .filter(models.Agent.org_id == org.org_id).count())
        req_count = (db.query(models.PaymentIntent)
                     .filter(models.PaymentIntent.org_id == org.org_id).count())
        has_provider = bool(db.query(models.ProviderAccount)
                            .filter_by(org_id=org.org_id).first())
        items.append({
            "org_id": org.org_id, "name": org.name,
            "status": org.status,
            "parent_count": parent_count,
            "agent_count": agent_count,
            "payment_request_count": req_count,
            "provider_account_configured": has_provider,
            "created_at": _iso(org.created_at),
        })
    return {"items": items}


@router.post("/platform/tenants/provision")
def platform_provision_tenant(
    req: TenantProvisionRequest,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Provision an Organization tenant and bind an approved parent.

    Fails closed if the parent is not ACTIVE or already has registered agents.
    """
    _require_platform_admin(x_admin_api_key)
    if db.query(models.Organization).filter_by(org_id=req.org_id).first():
        raise HTTPException(409, f"Organization '{req.org_id}' already exists")
    parent = db.query(models.ParentAuthority).filter_by(parent_id=req.parent_id).first()
    if not parent:
        raise HTTPException(404, "Parent not found")
    if parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(409, "Parent is not approved (must be ACTIVE before tenant provisioning)")
    existing_agents = db.query(models.Agent).filter_by(parent_pk=parent.id).count()
    if existing_agents:
        raise HTTPException(409, "Parent already has registered agents; migrate via portability instead")
    org = models.Organization(org_id=req.org_id, name=req.name, status="ACTIVE")
    db.add(org)
    parent.org_id = req.org_id
    db.flush()
    db.commit()
    return {"org_id": req.org_id, "status": "ACTIVE", "parent_id": req.parent_id,
            "message": "Tenant created and parent bound"}


@router.get("/platform/agents")
def platform_agents(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    rows = (db.query(models.Agent, models.ParentAuthority)
            .join(models.ParentAuthority,
                  models.ParentAuthority.id == models.Agent.parent_pk)
            .order_by(models.Agent.created_at.desc()).limit(500).all())
    items = []
    for agent, parent in rows:
        items.append({
            "agent_id": agent.agent_id, "name": agent.name,
            "parent_name": parent.name, "parent_id": parent.parent_id,
            "org_id": agent.org_id,
            "capabilities": agent.granted_capabilities or [],
            "payment_limit_minor_units": agent.payment_limit_minor_units,
            "currency": agent.currency,
            "status": _enum_value(agent.status),
            "created_at": _iso(agent.created_at),
        })
    return {"items": items}


@router.post("/platform/agents/{agent_id}/revoke")
def platform_revoke_agent(
    agent_id: str,
    req: PlatformAgentRevokeRequest,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Emergency platform-level agent revocation: invalidates credentials and
    outstanding authorizations (same effect as the control-plane fleet revoke)."""
    _require_platform_admin(x_admin_api_key)
    agent = db.query(models.Agent).filter_by(agent_id=agent_id).with_for_update().first()
    if not agent:
        raise HTTPException(404, "Agent not found")
    before = _enum_value(agent.status)
    agent.status = models.AgentStatus.REVOKED
    db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).update(
        {"revoked": True}, synchronize_session=False)
    now = datetime.now(timezone.utc)
    db.query(models.ResourceAccessGrant).filter_by(
        org_id=agent.org_id, subject_type="agent", subject_id=agent_id, status="ACTIVE"
    ).update({"status": "REVOKED", "revoked_at": now}, synchronize_session=False)
    outstanding = (db.query(models.BoundedAuthorization).filter_by(agent_id=agent_id)
                   .filter(models.BoundedAuthorization.usage_count
                            < models.BoundedAuthorization.max_usage).all())
    invalidated = 0
    for auth in outstanding:
        if auth.expires_at > now:
            auth.expires_at = now
            auth.usage_count = auth.max_usage
            invalidated += 1
    db.commit()
    return {"agent_id": agent_id, "previous_status": before,
            "status": "revoked",
            "pending_authorizations_invalidated": invalidated,
            "reason": req.reason}


@router.get("/platform/payments")
def platform_payments(
    limit: int = Query(default=200, ge=1, le=500),
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    rows = (db.query(models.PaymentIntent, models.Agent, models.ProviderTransaction)
            .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
            .outerjoin(models.ProviderTransaction,
                       models.ProviderTransaction.intent_id == models.PaymentIntent.intent_id)
            .order_by(models.PaymentIntent.created_at.desc()).limit(limit).all())
    items = []
    for intent, agent, ptx in rows:
        items.append({
            "intent_id": intent.intent_id,
            "transaction_id": intent.transaction_id,
            "org_id": intent.org_id,
            "agent_id": intent.agent_id,
            "agent_name": agent.name,
            "parent_name": agent.parent.name if agent.parent else "",
            "merchant": intent.merchant,
            "purpose": intent.purpose,
            "amount_minor_units": intent.amount_minor_units,
            "currency": intent.currency,
            "decision": _enum_value(intent.decision),
            "provider_state": ptx.state if ptx else None,
            "provider_environment": ptx.provider_environment if ptx else None,
            "created_at": _iso(intent.created_at),
        })
    return {"items": items}


@router.get("/platform/payments/{intent_id}")
def platform_payment_detail(
    intent_id: str,
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    row = (db.query(models.PaymentIntent, models.Agent, models.ProviderTransaction)
           .join(models.Agent, models.Agent.agent_id == models.PaymentIntent.agent_id)
           .outerjoin(models.ProviderTransaction,
                      models.ProviderTransaction.intent_id == models.PaymentIntent.intent_id)
           .filter(models.PaymentIntent.intent_id == intent_id).first())
    if not row:
        raise HTTPException(404, "Payment intent not found")
    intent, agent, ptx = row
    events = (db.query(models.AuditEvent)
              .filter_by(transaction_id=intent.transaction_id, agent_id=intent.agent_id)
              .order_by(models.AuditEvent.id.asc()).all())
    from app.audit import verify_chain
    audit_verified = bool(events) and verify_chain(db, intent.transaction_id)
    control_decision = db.query(models.ControlPlaneDecision).filter_by(intent_id=intent.intent_id).first()
    return {
        "payment": {
            "intent_id": intent.intent_id,
            "transaction_id": intent.transaction_id,
            "org_id": intent.org_id,
            "parent_name": agent.parent.name if agent.parent else "",
            "parent_id": agent.parent.parent_id if agent.parent else "",
            "agent_id": intent.agent_id,
            "agent_name": agent.name,
            "merchant": intent.merchant,
            "purpose": intent.purpose,
            "amount_minor_units": intent.amount_minor_units,
            "currency": intent.currency,
            "decision": _enum_value(intent.decision),
            "reasons": intent.reasons or [],
            "reason_codes": list(dict.fromkeys((intent.reason_codes or []) +
                (control_decision.reason_codes or [] if control_decision else []))),
            "reason_evidence": ({**(intent.reason_evidence or {}),
                "control_plane_evidence": control_decision.reason_evidence or {}}
                if control_decision else (intent.reason_evidence or {})),
            "reason_catalog_version": (control_decision.reason_catalog_version
                if control_decision else intent.reason_catalog_version),
            "provider_state": ptx.state if ptx else None,
            "provider_environment": ptx.provider_environment if ptx else None,
            "created_at": _iso(intent.created_at),
        },
        "audit_events": [{
            "kind": e.kind,
            "transaction_id": e.transaction_id,
            "agent_id": e.agent_id,
            "org_id": e.org_id,
            "event_hash": e.event_hash,
            "created_at": _iso(e.created_at),
        } for e in events],
        "audit_verified": audit_verified,
    }


@router.get("/platform/governance")
def platform_governance(
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    policies = (db.query(models.PolicyBundle)
                .order_by(models.PolicyBundle.created_at.desc()).limit(100).all())
    decisions = (db.query(models.ControlPlaneDecision)
                 .order_by(models.ControlPlaneDecision.created_at.desc()).limit(100).all())
    return {
        "policies": [{
            "org_id": p.org_id, "policy_name": p.policy_name,
            "version": p.version, "status": p.status,
            "activated_at": _iso(p.activated_at),
        } for p in policies],
        "decisions": [{
            "org_id": d.org_id, "policy_name": d.policy_name,
            "disposition": d.disposition,
            "reason_codes": d.reason_codes or [],
            "reason_evidence": d.reason_evidence or {},
            "reason_catalog_version": d.reason_catalog_version,
            "intent_id": d.intent_id,
            "created_at": _iso(d.created_at),
        } for d in decisions],
    }


@router.get("/platform/audit")
def platform_audit(
    limit: int = Query(default=200, ge=1, le=1000),
    x_admin_api_key: str = Header(default=""),
    db: Session = Depends(get_db),
):
    _require_platform_admin(x_admin_api_key)
    rows = (db.query(models.AuditEvent)
            .order_by(models.AuditEvent.id.desc()).limit(limit).all())
    return {"items": [{
        "kind": e.kind, "org_id": e.org_id,
        "transaction_id": e.transaction_id,
        "agent_id": e.agent_id, "parent_id": e.parent_id,
        "event_hash": e.event_hash, "prev_hash": e.prev_hash,
        "detail": e.detail or {},
        "created_at": _iso(e.created_at),
    } for e in rows]}
