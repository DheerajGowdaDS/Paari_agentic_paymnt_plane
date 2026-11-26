"""Tenant-scoped control-plane administration API.

These routes never accept a tenant identity from the JSON body. Root-only key
issuance uses the platform admin key; organization operations use a high-entropy,
organization-bound X-Paari-Control-Key whose hash (not plaintext) is stored in DB.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import crypto_utils, models, security
from app.database import get_db
from app.control_plane import schemas
from app.safr.envelope import GovernanceEnvelope

router = APIRouter(prefix="/control/v1", tags=["institutional-control-plane"])

_SECRETISH = re.compile(r"(secret|password|passwd|token|cvv|cvc|pan|pin|private.?key|access.?key|api.?key)", re.I)
_ALLOWED_ACTIONS = {"resource:read", "payment:execute", "payment:refund", "data:read", "data:write", "api:invoke"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tenant(db: Session, control_key: str, org_id: str, required_scope: str = "control:write") -> str:
    if not org_id.strip():
        raise HTTPException(status_code=400, detail="X-Paari-Org is required")
    if not control_key:
        raise HTTPException(status_code=401, detail="X-Paari-Control-Key is required")
    digest = hashlib.sha256(control_key.encode("utf-8")).hexdigest()
    key = db.query(models.OrganizationAdminKey).filter_by(key_hash=digest, org_id=org_id, status="ACTIVE").first()
    now = _now()
    if not key or key.expires_at <= now:
        raise HTTPException(status_code=401, detail="Invalid or expired organization control key")
    if required_scope not in (key.scopes or []):
        raise HTTPException(status_code=403, detail="Organization control key lacks required scope")
    organization = db.query(models.Organization).filter_by(org_id=org_id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    if organization.status != "ACTIVE":
        raise HTTPException(status_code=403, detail="Organization is suspended")
    key.last_used_at = now
    db.commit()  # persist last-use metadata before the business operation begins
    return org_id


def _audit(db: Session, *, org_id: str, action: str, target: str, detail: dict) -> None:
    from app.audit import record_audit
    record_audit(db, transaction_id=f"control:{target}", agent_id="", parent_id=None,
                 kind=action, detail=detail, org_id=org_id)


def _principal_view(row: models.PrincipalIdentity) -> dict:
    return {"principal_id": row.principal_id, "org_id": row.org_id,
            "external_subject_id": row.external_subject_id, "identity_provider": row.identity_provider,
            "display_name": row.display_name, "status": row.status,
            "assurance_level": row.assurance_level,
            "identity_verification_status": getattr(row, "identity_verification_status", "UNVERIFIED"),
            "verification_provider_id": getattr(row, "verification_provider_id", None),
            "verification_expires_at": getattr(row, "verification_expires_at", None),
            "created_at": row.created_at, "attested_at": row.attested_at}


def _resource_view(row: models.GovernedResource) -> dict:
    return {"resource_id": row.resource_id, "org_id": row.org_id,
            "resource_type": row.resource_type, "provider_id": row.provider_id,
            "external_resource_ref": row.external_resource_ref,
            "owner_principal_id": row.owner_principal_id, "currency": row.currency,
            "classification": row.classification, "status": row.status,
            "metadata": row.resource_metadata or {}, "created_at": row.created_at}


def _grant_view(row: models.ResourceAccessGrant) -> dict:
    return {"grant_id": row.grant_id, "org_id": row.org_id, "resource_id": row.resource_id,
            "subject_type": row.subject_type, "subject_id": row.subject_id,
            "actions": row.actions or [], "consent_reference": row.consent_reference,
            "status": row.status, "valid_from": row.valid_from,
            "valid_until": row.valid_until, "created_at": row.created_at}


def _decision_view(row: models.ControlPlaneDecision) -> dict:
    return {"decision_id": row.decision_id, "intent_id": row.intent_id, "org_id": row.org_id,
            "principal_id": row.principal_id, "resource_id": row.resource_id,
            "policy_name": row.policy_name, "policy_version": row.policy_version,
            "disposition": row.disposition, "reason_codes": row.reason_codes or [],
            "reason_evidence": row.reason_evidence or {},
            "reason_catalog_version": row.reason_catalog_version,
            "risk_score_bps": row.risk_score_bps, "evidence_quality_bps": row.evidence_quality_bps,
            "transaction_digest": row.transaction_digest, "created_at": row.created_at}


def _policy_view(row: models.PolicyBundle) -> dict:
    return {"policy_id": row.policy_id, "org_id": row.org_id, "policy_name": row.policy_name,
            "version": row.version, "status": row.status, "rules": row.rules or {},
            "created_at": row.created_at, "activated_at": row.activated_at}


def _trusted_portability_issuers() -> dict[str, str]:
    """Load pinned issuer keys from a separate trust channel, never the package.

    PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON must be a JSON object mapping issuer
    key IDs to PEM public keys. This prevents an imported package from
    establishing trust in its own embedded signing key.
    """
    raw = os.environ.get("PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON", "").strip()
    if not raw:
        raise HTTPException(status_code=503,
                            detail="Portability import is disabled: configure out-of-band PAARI_PORTABILITY_TRUSTED_ISSUERS_JSON")
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail="Portability issuer trust store is not valid JSON") from exc
    if not isinstance(loaded, dict) or not loaded or any(
        not isinstance(key, str) or not key.strip() or not isinstance(value, str) or "PUBLIC KEY" not in value
        for key, value in loaded.items()
    ):
        raise HTTPException(status_code=503, detail="Portability issuer trust store must map key IDs to PEM public keys")
    return loaded


@router.post("/organizations/{org_id}/status")
def set_organization_status(org_id: str, req: schemas.OrganizationStatusUpdate,
                            x_admin_api_key: str = Header(default=""), db: Session = Depends(get_db)):
    """Root-admin-only emergency tenant suspension/reactivation with audit."""
    security.require_admin(x_admin_api_key)
    org = db.query(models.Organization).filter_by(org_id=org_id).with_for_update().first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    before = org.status
    org.status = req.status
    if req.status == "SUSPENDED":
        db.query(models.OrganizationAdminKey).filter_by(org_id=org_id, status="ACTIVE").update(
            {"status": "REVOKED", "revoked_at": _now()}, synchronize_session=False)
    _audit(db, org_id=org_id, action="organization_status_changed", target=org_id,
           detail={"previous_status": before, "status": req.status, "reason": req.reason.strip()})
    db.commit()
    return {"org_id": org_id, "status": req.status, "previous_status": before}


@router.post("/admin-keys", response_model=schemas.AdminKeyIssued, status_code=201)
def issue_admin_key(req: schemas.AdminKeyCreate, x_admin_api_key: str = Header(default=""),
                    db: Session = Depends(get_db)):
    """Root-admin-only issuance; raw organization key is returned exactly once."""
    security.require_admin(x_admin_api_key)
    now = _now()
    if req.expires_at <= now or (req.expires_at - now).total_seconds() > 366 * 24 * 3600:
        raise HTTPException(status_code=422, detail="Admin key expiry must be in the next 366 days")
    if not db.query(models.Organization).filter_by(org_id=req.org_id).first():
        raise HTTPException(status_code=404, detail="Organization not found")
    raw_secret = secrets.token_urlsafe(40)
    key_prefix = raw_secret[:12]
    row = models.OrganizationAdminKey(org_id=req.org_id, key_hash=hashlib.sha256(raw_secret.encode()).hexdigest(),
                                      key_prefix=key_prefix, scopes=sorted(set(req.scopes)), status="ACTIVE",
                                      expires_at=req.expires_at, created_by="root-admin")
    db.add(row); db.flush()
    _audit(db, org_id=req.org_id, action="organization_admin_key_issued", target=row.key_id,
           detail={"key_id": row.key_id, "key_prefix": key_prefix, "scopes": row.scopes,
                   "expires_at": row.expires_at.isoformat()})
    db.commit(); db.refresh(row)
    return {"key_id": row.key_id, "org_id": row.org_id, "key_prefix": row.key_prefix,
            "scopes": row.scopes, "expires_at": row.expires_at, "secret": raw_secret}


@router.post("/admin-keys/{key_id}/revoke")
def revoke_admin_key(key_id: str, x_admin_api_key: str = Header(default=""),
                     db: Session = Depends(get_db)):
    security.require_admin(x_admin_api_key)
    row = db.query(models.OrganizationAdminKey).filter_by(key_id=key_id).with_for_update().first()
    if not row:
        raise HTTPException(status_code=404, detail="Organization admin key not found")
    row.status = "REVOKED"; row.revoked_at = _now()
    _audit(db, org_id=row.org_id, action="organization_admin_key_revoked", target=key_id,
           detail={"key_id": key_id, "key_prefix": row.key_prefix})
    db.commit()
    return {"key_id": key_id, "org_id": row.org_id, "status": row.status}


@router.post("/principals", response_model=schemas.PrincipalView, status_code=201)
def create_principal(req: schemas.PrincipalCreate,
                     x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                     db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    row = models.PrincipalIdentity(org_id=org_id, external_subject_id=req.external_subject_id,
                                   identity_provider=req.identity_provider, display_name=req.display_name,
                                   assurance_level="low", status="PENDING")
    db.add(row)
    try:
        db.flush()
        _audit(db, org_id=org_id, action="principal_registered", target=row.principal_id,
               detail={"principal_id": row.principal_id, "identity_provider": row.identity_provider,
                       "status": row.status, "assurance_level": row.assurance_level})
        db.commit(); db.refresh(row)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Principal already registered for this identity provider") from exc
    return _principal_view(row)


@router.post("/principals/{principal_id}/verify", response_model=schemas.PrincipalView)
def verify_principal_identity(principal_id: str, body: schemas.PrincipalVerifyRequest,
                              x_paari_control_key: str = Header(default=""),
                              x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    """Run a provider-backed principal verification and persist bound evidence.

    Parent/admin attestations remain a separate low-assurance workflow. This
    endpoint never treats a client-supplied case ID, assurance level or status
    as evidence; the configured, explicitly pinned provider supplies the result.
    """
    from app.identity_providers.contracts import VerificationKind, VerificationStatus, VerificationRequest, subject_reference_digest
    from app.identity_providers.runtime import (
        IdentityProviderError, require_identity_provider, validate_verification_result,
    )

    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    principal = db.query(models.PrincipalIdentity).filter_by(org_id=org_id, principal_id=principal_id).with_for_update().first()
    if not principal:
        raise HTTPException(status_code=404, detail="Principal not found")
    if principal.status == "REVOKED":
        raise HTTPException(status_code=409, detail="Revoked principal cannot be reactivated by identity re-verification")
    try:
        provider = require_identity_provider()
    except IdentityProviderError as exc:
        raise HTTPException(status_code=503, detail="Trusted identity verification adapter is not configured, pinned and healthy") from exc

    kind = VerificationKind(body.verification_kind)
    verification_request = VerificationRequest(
        verification_id=secrets.token_urlsafe(18), organization_id=org_id,
        subject_reference=principal.external_subject_id, kind=kind,
        jurisdiction=body.jurisdiction,
    )
    try:
        result = provider.verify(verification_request)
    except Exception as exc:
        _audit(db, org_id=org_id, action="principal_identity_verification_unavailable", target=principal_id,
               detail={"principal_id": principal_id, "provider_id": provider.provider_id,
                       "reason_code": "IDENTITY_PROVIDER_REQUEST_FAILED"})
        db.commit()
        raise HTTPException(status_code=502, detail="Trusted identity provider request failed; principal remains unverified") from exc

    expected_subject_digest = subject_reference_digest(org_id, principal.external_subject_id)
    # Even a non-verified status must be tied to this tenant, subject, kind,
    # provider and jurisdiction. Otherwise it could be a valid case for another person.
    if (result.provider_id != provider.provider_id
            or not result.provider_case_reference.strip()
            or result.jurisdiction != body.jurisdiction
            or result.subject_reference_digest != expected_subject_digest
            or result.verification_kind is not kind):
        _audit(db, org_id=org_id, action="principal_identity_verification_rejected", target=principal_id,
               detail={"principal_id": principal_id, "provider_id": provider.provider_id,
                       "reason_code": "IDENTITY_RESULT_BINDING_MISMATCH"})
        db.commit()
        raise HTTPException(status_code=502, detail="Identity provider result failed subject/tenant/purpose binding checks")

    now = _now()
    accepted, reason_code = validate_verification_result(
        result, provider_id=provider.provider_id, organization_id=org_id,
        subject_reference=principal.external_subject_id, kind=kind,
        jurisdiction=body.jurisdiction, now=now,
    )
    principal.identity_verification_status = result.status.value
    principal.verification_provider_id = provider.provider_id
    principal.verification_case_reference = result.provider_case_reference
    principal.verification_kind = kind.value
    principal.verification_subject_digest = expected_subject_digest
    principal.verification_evidence_digest = result.evidence_digest if accepted else None
    principal.verification_retrieved_at = result.evidence_retrieved_at if accepted else None
    principal.verification_expires_at = result.expires_at if accepted else None
    if accepted:
        principal.status = "ACTIVE"
        principal.assurance_level = result.assurance_level
        principal.attested_at = result.evidence_retrieved_at
    else:
        principal.assurance_level = "low"
        principal.status = "REVOKED" if result.status is VerificationStatus.REVOKED else "PENDING"

    _audit(db, org_id=org_id, action="principal_identity_verification_result", target=principal_id,
           detail={"principal_id": principal_id, "provider_id": provider.provider_id,
                   "provider_case_reference": result.provider_case_reference,
                   "verification_kind": kind.value, "jurisdiction": body.jurisdiction,
                   "identity_verification_status": result.status.value,
                   "assurance_level": principal.assurance_level,
                   "evidence_digest": result.evidence_digest if accepted else None,
                   "expires_at": result.expires_at.isoformat() if accepted and result.expires_at else None,
                   "accepted": accepted, "reason_code": reason_code,
                   "reason_codes": list(result.reason_codes)})
    db.commit(); db.refresh(principal)
    return _principal_view(principal)


@router.post("/principals/{principal_id}/attest", response_model=schemas.PrincipalView)
def attest_principal(principal_id: str, body: schemas.PrincipalAttest, x_paari_control_key: str = Header(default=""),
                     x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    reference = body.attestation_reference.strip()
    if not reference or len(reference) > 256 or _SECRETISH.search(reference):
        raise HTTPException(status_code=422, detail="A non-secret organization attestation reference is required")
    row = db.query(models.PrincipalIdentity).filter_by(org_id=org_id, principal_id=principal_id).with_for_update().first()
    if not row:
        raise HTTPException(status_code=404, detail="Principal not found")
    if row.status == "REVOKED":
        raise HTTPException(status_code=409, detail="Revoked principal cannot be reactivated")
    row.status = "ACTIVE"
    row.attestation_reference = reference
    row.attested_at = _now()
    _audit(db, org_id=org_id, action="principal_attested_by_organization", target=principal_id,
           detail={"principal_id": principal_id, "attestation_reference": reference,
                   "assurance_level": row.assurance_level})
    db.commit(); db.refresh(row)
    return _principal_view(row)


@router.post("/principals/{principal_id}/revoke", response_model=schemas.PrincipalView)
def revoke_principal(principal_id: str, x_paari_control_key: str = Header(default=""),
                     x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    row = db.query(models.PrincipalIdentity).filter_by(org_id=org_id, principal_id=principal_id).with_for_update().first()
    if not row:
        raise HTTPException(status_code=404, detail="Principal not found")
    row.status = "REVOKED"
    db.query(models.ResourceAccessGrant).filter_by(org_id=org_id, subject_type="principal", subject_id=principal_id, status="ACTIVE").update({"status": "REVOKED", "revoked_at": _now()})
    _audit(db, org_id=org_id, action="principal_revoked", target=principal_id,
           detail={"principal_id": principal_id, "reason": "operator_revocation"})
    db.commit(); db.refresh(row)
    return _principal_view(row)


@router.post("/resources", response_model=schemas.ResourceView, status_code=201)
def create_resource(req: schemas.ResourceCreate, x_paari_control_key: str = Header(default=""),
                    x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    if _SECRETISH.search(req.external_resource_ref):
        raise HTTPException(status_code=422, detail="Resource reference appears to contain a secret; use an opaque provider reference")
    for key, value in req.metadata.items():
        if _SECRETISH.search(key) or (isinstance(value, str) and _SECRETISH.search(value)):
            raise HTTPException(status_code=422, detail="Resource metadata must not contain credentials or secrets")
    owner = None
    if req.owner_principal_id:
        owner = db.query(models.PrincipalIdentity).filter_by(org_id=org_id, principal_id=req.owner_principal_id, status="ACTIVE").first()
        if not owner:
            raise HTTPException(status_code=422, detail="Resource owner principal must exist and be active in this organization")
    row = models.GovernedResource(org_id=org_id, resource_type=req.resource_type,
                                  provider_id=req.provider_id, external_resource_ref=req.external_resource_ref,
                                  owner_principal_id=req.owner_principal_id, currency=req.currency,
                                  classification=req.classification, status="ACTIVE", resource_metadata=req.metadata)
    db.add(row)
    try:
        db.flush()
        _audit(db, org_id=org_id, action="resource_registered", target=row.resource_id,
               detail={"resource_id": row.resource_id, "resource_type": row.resource_type,
                       "provider_id": row.provider_id, "classification": row.classification,
                       "owner_principal_id": row.owner_principal_id})
        db.commit(); db.refresh(row)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Resource reference already registered in this organization") from exc
    return _resource_view(row)


@router.get("/resources", response_model=list[schemas.ResourceView])
def list_resources(x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                   db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    rows = db.query(models.GovernedResource).filter_by(org_id=org_id).order_by(models.GovernedResource.created_at.desc()).limit(500).all()
    return [_resource_view(row) for row in rows]


@router.post("/resources/{resource_id}/grants", response_model=schemas.ResourceGrantView, status_code=201)
def grant_resource_access(resource_id: str, req: schemas.ResourceGrantCreate,
                          x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                          db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    now = _now()
    if req.valid_from.tzinfo is None or req.valid_until.tzinfo is None or req.valid_until <= req.valid_from:
        raise HTTPException(status_code=422, detail="Grant validity must be timezone-aware and valid_until must be later than valid_from")
    if (req.valid_until - req.valid_from).total_seconds() > 366 * 24 * 3600:
        raise HTTPException(status_code=422, detail="Resource grants may not exceed 366 days")
    if not set(req.actions).issubset(_ALLOWED_ACTIONS):
        raise HTTPException(status_code=422, detail="Grant contains an unsupported action")
    resource = db.query(models.GovernedResource).filter_by(org_id=org_id, resource_id=resource_id, status="ACTIVE").first()
    if not resource:
        raise HTTPException(status_code=404, detail="Active resource not found")
    if req.subject_type == "agent":
        subject = db.query(models.Agent).filter_by(org_id=org_id, agent_id=req.subject_id, status=models.AgentStatus.ACTIVE).first()
    else:
        subject = db.query(models.PrincipalIdentity).filter_by(org_id=org_id, principal_id=req.subject_id, status="ACTIVE").first()
    if not subject:
        raise HTTPException(status_code=422, detail="Grant subject must exist and be active in the same organization")
    row = models.ResourceAccessGrant(org_id=org_id, resource_id=resource_id, subject_type=req.subject_type,
                                     subject_id=req.subject_id, actions=sorted(set(req.actions)),
                                     consent_reference=req.consent_reference, status="ACTIVE",
                                     valid_from=req.valid_from, valid_until=req.valid_until,
                                     created_by=f"admin:{org_id}")
    db.add(row)
    db.flush()
    _audit(db, org_id=org_id, action="resource_access_granted", target=row.grant_id,
           detail={"grant_id": row.grant_id, "resource_id": resource_id, "subject_type": req.subject_type,
                   "subject_id": req.subject_id, "actions": row.actions, "consent_reference": req.consent_reference,
                   "valid_from": req.valid_from.isoformat(), "valid_until": req.valid_until.isoformat()})
    db.commit(); db.refresh(row)
    return _grant_view(row)


@router.post("/grants/{grant_id}/revoke", response_model=schemas.ResourceGrantView)
def revoke_resource_grant(grant_id: str, x_paari_control_key: str = Header(default=""),
                          x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    row = db.query(models.ResourceAccessGrant).filter_by(org_id=org_id, grant_id=grant_id).with_for_update().first()
    if not row:
        raise HTTPException(status_code=404, detail="Grant not found")
    row.status = "REVOKED"; row.revoked_at = _now()
    _audit(db, org_id=org_id, action="resource_access_revoked", target=grant_id,
           detail={"grant_id": grant_id, "resource_id": row.resource_id, "subject_type": row.subject_type,
                   "subject_id": row.subject_id})
    db.commit(); db.refresh(row)
    return _grant_view(row)


@router.post("/policies", response_model=schemas.PolicyView, status_code=201)
def create_policy(req: schemas.PolicyCreate, x_paari_control_key: str = Header(default=""),
                  x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    existing = db.query(models.PolicyBundle).filter_by(org_id=org_id, policy_name=req.policy_name, version=req.version).first()
    if existing:
        raise HTTPException(status_code=409, detail="Policy version already exists; policy versions are immutable")
    now = _now()
    if req.activate:
        # Retire the old version inside this DB transaction before inserting the
        # new ACTIVE version; the partial unique index is the concurrency guard.
        active_rows = db.query(models.PolicyBundle).filter_by(org_id=org_id, policy_name=req.policy_name, status="ACTIVE").with_for_update().all()
        for active in active_rows:
            active.status = "RETIRED"
    rules = {"min_evidence_quality_bps": req.min_evidence_quality_bps,
             "observe_threshold_bps": req.observe_threshold_bps,
             "escalate_threshold_bps": req.escalate_threshold_bps,
             "deny_threshold_bps": req.deny_threshold_bps,
             "require_signed_mandate": req.require_signed_mandate,
             "allow_signed_review_release": req.allow_signed_review_release,
             "scoring_model": "rule-risk-v1"}
    row = models.PolicyBundle(org_id=org_id, policy_name=req.policy_name, version=req.version,
                              status="ACTIVE" if req.activate else "DRAFT", rules=rules,
                              created_by=f"admin:{org_id}", activated_at=now if req.activate else None)
    db.add(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy activation conflict; retry with a fresh version") from exc
    _audit(db, org_id=org_id, action="policy_published" if req.activate else "policy_created",
           target=f"{req.policy_name}:{req.version}", detail={"policy_name": req.policy_name,
           "version": req.version, "status": row.status, "rules": rules})
    db.commit(); db.refresh(row)
    return _policy_view(row)


@router.get("/policies/active", response_model=list[schemas.PolicyView])
def get_active_policies(x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                        db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    rows = db.query(models.PolicyBundle).filter_by(org_id=org_id, status="ACTIVE").order_by(models.PolicyBundle.policy_name.asc()).all()
    return [_policy_view(row) for row in rows]


@router.get("/decisions", response_model=list[schemas.ControlPlaneDecisionView])
def list_control_plane_decisions(
    disposition: str | None = Query(default=None, pattern=r"^(DENY|ESCALATE|AUTO_EXECUTE|OBSERVE)$"),
    limit: int = Query(default=100, ge=1, le=500),
    x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Tenant-scoped risk/disposition history; the filter cannot widen tenant scope."""
    org_id = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    query = db.query(models.ControlPlaneDecision).filter_by(org_id=org_id)
    if disposition:
        query = query.filter_by(disposition=disposition)
    rows = query.order_by(models.ControlPlaneDecision.created_at.desc()).limit(limit).all()
    return [_decision_view(row) for row in rows]


@router.get("/decisions/{decision_id}", response_model=schemas.ControlPlaneDecisionView)
def get_control_plane_decision(
    decision_id: str, x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""), db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    row = db.query(models.ControlPlaneDecision).filter_by(org_id=org_id, decision_id=decision_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Control-plane decision not found")
    return _decision_view(row)

# ---------------------------------------------------------------------------
# SAFR Governance Envelope ingress and signed Agent Card portability.
# These routes are intentionally validation/export only: neither issues a
# bounded authorization nor transfers active authority to another tenant.
# ---------------------------------------------------------------------------

@router.post("/governance/envelopes/validate")
def validate_governance_envelope(
    req: GovernanceEnvelope,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Validate a signed, fresh Governance Envelope and persist anti-replay receipt.

    This confirms the envelope's integrity and binding to current Paari records.
    It does NOT evaluate the entire applicable policy stack, mint authorization,
    or grant execution permission. Financial execution must still traverse the
    existing payment-intent and bounded-authorization path.
    """
    from app.safr.envelope import envelope_digest, verify_envelope_signature
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    if req.tenant_id != org_id:
        raise HTTPException(status_code=403, detail="Envelope tenant does not match authenticated organization")

    now = _now()
    agent = db.query(models.Agent).filter_by(org_id=org_id, agent_id=req.agent_id).first()
    if not agent or agent.status != models.AgentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Envelope agent is unknown, inactive or outside this organization")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk, org_id=org_id).first()
    if not parent or parent.parent_id != req.parent_id or parent.status != models.ParentStatus.ACTIVE:
        raise HTTPException(status_code=401, detail="Envelope parent binding is invalid or inactive")

    delegation = db.query(models.DelegationRecord).filter_by(
        org_id=org_id, delegation_id=agent.delegation_id, parent_pk=parent.id
    ).first()
    if not delegation or not delegation.delegation_signature_b64:
        raise HTTPException(status_code=409, detail="Stored parent-signed delegation is unavailable; reissue delegation before SAFR envelope ingress")
    from app.portability import delegation_payload_from_record
    delegation_payload = delegation_payload_from_record(delegation, parent.parent_id)
    if not security_crypto_verify(parent.public_key_pem, delegation_payload, delegation.delegation_signature_b64):
        raise HTTPException(status_code=401, detail="Registered parent delegation signature is invalid")
    if delegation.expires_at <= now:
        raise HTTPException(status_code=401, detail="Parent delegation has expired")
    # Fail closed if current registry material drifted from the signed artifact.
    if (set(delegation_payload["granted_capabilities"]) != set(agent.granted_capabilities or [])
            or int(delegation_payload["payment_limit_minor_units"]) != int(agent.payment_limit_minor_units)
            or delegation_payload["currency"] != agent.currency):
        raise HTTPException(status_code=409, detail="Agent authority differs from its persisted parent-signed delegation")
    if security_crypto_fingerprint(agent.public_key_pem).lower() != delegation_payload["agent_public_key_fingerprint"].lower():
        raise HTTPException(status_code=409, detail="Current agent key is not the key bound by its latest signed delegation")

    # Current key is preferred. A previous key is allowed only inside its explicit rotation grace.
    presented_public_key = None
    current_fingerprint = security_crypto_fingerprint(agent.public_key_pem)
    if current_fingerprint.lower() == req.signing_key_fingerprint.lower():
        presented_public_key = agent.public_key_pem
    elif (agent.old_public_key_pem and agent.key_sunset_at and agent.key_sunset_at > now
          and security_crypto_fingerprint(agent.old_public_key_pem).lower() == req.signing_key_fingerprint.lower()):
        presented_public_key = agent.old_public_key_pem
    if not presented_public_key:
        raise HTTPException(status_code=401, detail="Envelope signing key is not the active or grace-period agent key")
    try:
        verify_envelope_signature(req, presented_public_key)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=f"Governance Envelope verification failed: {str(exc)}") from exc

    principal = db.query(models.PrincipalIdentity).filter_by(
        org_id=org_id, principal_id=req.principal_id, status="ACTIVE"
    ).first()
    if not principal:
        raise HTTPException(status_code=403, detail="Envelope principal must be active in the authenticated organization")
    resource = db.query(models.GovernedResource).filter_by(
        org_id=org_id, resource_id=req.resource_id, status="ACTIVE"
    ).first()
    if not resource:
        raise HTTPException(status_code=403, detail="Envelope resource must be active in the authenticated organization")

    action_map = {
        "payment.execute": "payment:execute",
        "payment.refund": "payment:refund",
        "data.read": "data:read",
        "data.write": "data:write",
        "api.invoke": "api:invoke",
    }
    required_action = action_map[req.action_type]
    allowed_capabilities = {
        "payment.execute": {"make_payment", "payment:execute"},
        "payment.refund": {"refund_payment", "payment:refund"},
        "data.read": {"data.read", "data:read", "read_data", "resource:read"},
        "data.write": {"data.write", "data:write", "write_data"},
        "api.invoke": {"api:invoke"},
    }[req.action_type]
    if not (set(agent.granted_capabilities or []) & allowed_capabilities):
        raise HTTPException(status_code=403, detail="Agent delegation does not grant this action type")

    def has_grant(subject_type: str, subject_id: str) -> bool:
        grants = db.query(models.ResourceAccessGrant).filter_by(
            org_id=org_id, resource_id=resource.resource_id,
            subject_type=subject_type, subject_id=subject_id, status="ACTIVE",
        ).all()
        return any(g.valid_from <= now < g.valid_until and required_action in (g.actions or []) for g in grants)

    if not has_grant("agent", agent.agent_id):
        raise HTTPException(status_code=403, detail="Active resource grant for agent/action is missing")
    if not has_grant("principal", principal.principal_id):
        raise HTTPException(status_code=403, detail="Active resource grant for principal/action is missing")

    if req.action_type.startswith("payment."):
        if not req.mandate_id:
            raise HTTPException(status_code=403, detail="Payment envelope requires a signed user mandate")
        mandate = db.query(models.UserPaymentMandate).filter_by(
            org_id=org_id, mandate_id=req.mandate_id, agent_id=agent.agent_id,
            status=models.MandateStatus.ACTIVE,
        ).first()
        if (not mandate or mandate.user_id != principal.external_subject_id
                or not mandate.valid_from <= now < mandate.expires_at):
            raise HTTPException(status_code=403, detail="Envelope mandate is missing, inactive, expired or bound to another principal")
        from app.mandate_signing import verify_mandate_signature
        mandate_sig = verify_mandate_signature(mandate)
        if not mandate_sig.signature_valid:
            raise HTTPException(status_code=403, detail="Envelope mandate signature is invalid")
        context = req.action_context
        if context.amount_minor_units is None or context.amount_minor_units > mandate.max_per_transaction:
            raise HTTPException(status_code=403, detail="Envelope amount exceeds the active mandate limit")
        if context.currency != mandate.currency:
            raise HTTPException(status_code=403, detail="Envelope currency does not match mandate")
        if mandate.allowed_merchants and (not context.merchant or context.merchant.casefold() not in {str(x).casefold() for x in mandate.allowed_merchants}):
            raise HTTPException(status_code=403, detail="Envelope merchant is outside mandate scope")
        binding = db.query(models.PaymentInstrumentBinding).filter_by(
            org_id=org_id, mandate_id=mandate.mandate_id, source_resource_id=resource.resource_id, status="active"
        ).all()
        if not any((b.expires_at is None or b.expires_at > now)
                   and b.currency == context.currency
                   and b.max_amount_minor_units >= context.amount_minor_units
                   and (not context.provider_id or b.provider.casefold() == context.provider_id.casefold())
                   for b in binding):
            raise HTTPException(status_code=403, detail="No active payment-instrument binding matches envelope resource and action")

    # Evidence references are agent-supplied claims. They are captured by digest
    # for later independent verification; this ingress does not mark them trusted.
    envelope_hash = envelope_digest(req)
    receipt = models.GovernanceEnvelopeReceipt(
        org_id=org_id,
        envelope_id=req.envelope_id,
        agent_id=agent.agent_id,
        action_type=req.action_type,
        action_digest=req.action_digest,
        envelope_digest=envelope_hash,
        validation_status="VALIDATED_ONLY",
        expires_at=req.expires_at,
    )
    db.add(receipt)
    try:
        db.flush()
        _audit(db, org_id=org_id, action="safr_governance_envelope_validated_only", target=receipt.receipt_id,
               detail={"receipt_id": receipt.receipt_id, "envelope_id": req.envelope_id,
                       "agent_id": agent.agent_id, "principal_id": principal.principal_id,
                       "resource_id": resource.resource_id, "action_type": req.action_type,
                       "action_digest": req.action_digest, "envelope_digest": envelope_hash,
                       "evidence_reference_count": len(req.evidence_refs),
                       "evidence_references_independently_verified": False,
                       "policy_evaluated": False, "authorization_issued": False})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Governance Envelope ID has already been received for this organization") from exc
    return {
        "receipt_id": receipt.receipt_id,
        "envelope_id": req.envelope_id,
        "validation_status": "VALIDATED_ONLY",
        "action_digest": req.action_digest,
        "envelope_digest": envelope_hash,
        "identity_binding_verified": True,
        "parent_delegation_verified": True,
        "principal_and_resource_active": True,
        "required_resource_grants_verified": True,
        "mandate_verified": req.action_type.startswith("payment."),
        "evidence_reference_count": len(req.evidence_refs),
        "evidence_references_independently_verified": False,
        "policy_evaluated": False,
        "authorization_issued": False,
        "execution_permitted": False,
        "next_step": "Submit the payment intent through the authenticated Paari runtime; use /governance/envelopes/process to bind this envelope to its persisted policy decision. This validation receipt is not authority to execute.",
    }


@router.post("/governance/envelopes/process")
def process_governance_envelope(
    req: GovernanceEnvelope,
    transaction_id: str | None = Query(default=None, min_length=1, max_length=100),
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Bind a signed envelope to the real payment runtime's saved disposition.

    This endpoint is deliberately not a second payment engine. It verifies the
    envelope through the same ingress checks, binds it to exactly one persisted
    PaymentIntent + ControlPlaneDecision, then observes the existing bounded
    authorization. Execution still requires the authenticated one-time consume
    endpoint. Non-payment actions are denied until their governed executors are
    registered; a signed envelope alone can never cause data/API side effects.
    """
    from app.control_plane.runtime import _digest as compute_runtime_digest
    from app.safr.envelope import beneficiary_reference_digest

    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    intent = None
    cp_decision = None
    if req.action_type == "payment.execute":
        if not transaction_id:
            raise HTTPException(status_code=422, detail="payment.execute envelopes require transaction_id to bind the saved intent")
        candidates = db.query(models.PaymentIntent).filter_by(
            org_id=org_id, agent_id=req.agent_id, transaction_id=transaction_id
        ).all()
        if len(candidates) != 1:
            raise HTTPException(status_code=409, detail="Exactly one tenant/agent payment intent must exist before envelope disposition")
        intent = candidates[0]
        cp_decision = db.query(models.ControlPlaneDecision).filter_by(
            org_id=org_id, intent_id=intent.intent_id
        ).first()
        if not cp_decision:
            raise HTTPException(status_code=409, detail="No persisted institutional policy decision exists; enable strict control-plane enforcement and submit a fresh intent")

    # Reuse the full signed-ingress checks rather than re-implementing identity,
    # delegation, grants, mandate and provider-binding validation here.
    validation = validate_governance_envelope(req, x_paari_control_key, x_paari_org, db)
    receipt = db.query(models.GovernanceEnvelopeReceipt).filter_by(
        org_id=org_id, envelope_id=req.envelope_id
    ).first()
    if not receipt:
        raise HTTPException(status_code=500, detail="Validated Governance Envelope receipt was not persisted")

    if req.action_type != "payment.execute":
        # Important fail-closed behaviour: grants may prove a data/API action is
        # in scope, but this release has no integrated data/API execution gateway.
        # Do not convert a valid signature into an ungoverned side effect.
        receipt.validation_status = "DENY_NO_EXECUTOR"
        _audit(db, org_id=org_id, action="safr_action_disposition", target=receipt.receipt_id,
               detail={"receipt_id": receipt.receipt_id, "envelope_id": req.envelope_id,
                       "action_type": req.action_type, "disposition": "DENY",
                       "reason_codes": ["GOVERNED_EXECUTOR_NOT_REGISTERED"],
                       "authorization_issued": False, "execution_permitted": False})
        db.commit()
        return {"receipt_id": receipt.receipt_id, "envelope_id": req.envelope_id,
                "validation_status": receipt.validation_status, "disposition": "DENY",
                "reason_codes": ["GOVERNED_EXECUTOR_NOT_REGISTERED"],
                "policy_evaluated": False, "authorization_issued": False,
                "execution_permitted": False,
                "next_step": "Register a governed executor for this action class; this request was not executed."}

    context = req.action_context
    expected_digest = compute_runtime_digest(
        org_id=intent.org_id, agent_id=intent.agent_id, mandate_id=intent.mandate_id,
        transaction_id=intent.transaction_id, merchant=intent.merchant,
        amount_minor=intent.amount_minor_units, currency=intent.currency,
        action=intent.action, purpose=intent.purpose,
        merchant_category=intent.merchant_category,
    )
    # PaymentIntent currently carries a merchant alias rather than a bank-level
    # beneficiary identifier. In this checkout-compatible path that alias is the
    # beneficiary reference; no raw account number can enter the envelope.
    exact_context = (
        req.agent_id == intent.agent_id
        and req.mandate_id == intent.mandate_id
        and req.principal_id == cp_decision.principal_id
        and req.resource_id == cp_decision.resource_id
        and context.amount_minor_units == intent.amount_minor_units
        and context.currency == intent.currency
        and (context.merchant or "").casefold() == intent.merchant.casefold()
        and (context.purpose or "").strip() == (intent.purpose or "").strip()
        and context.operation.casefold() in {intent.action.casefold(), "payment.execute", "payment.create"}
        and context.request_context_digest.lower() == expected_digest.lower()
        and context.beneficiary_ref_digest.lower() == beneficiary_reference_digest(intent.merchant).lower()
    )
    if not exact_context:
        raise HTTPException(status_code=403, detail="Governance Envelope does not bind to the persisted intent's exact amount, currency, purpose, merchant, principal, resource and request digest")

    disposition = cp_decision.disposition
    now = _now()
    auth = db.query(models.BoundedAuthorization).filter_by(
        org_id=org_id, intent_id=intent.intent_id
    ).first()
    if disposition in {"DENY", "ESCALATE"}:
        if auth and auth.usage_count < auth.max_usage:
            # Revoke any unexpected/unconsumed artifact if persisted state and
            # disposition disagree. Consumption still rechecks the DB row.
            auth.expires_at = now
            auth.usage_count = auth.max_usage
        if disposition == "DENY" and intent.decision != models.GovernanceDecision.DENY:
            raise HTTPException(status_code=409, detail="Persisted DENY disposition conflicts with the payment intent state")
        if disposition == "ESCALATE" and intent.decision != models.GovernanceDecision.REVIEW:
            raise HTTPException(status_code=409, detail="Escalation hold conflicts with the payment intent state")
        authorization_issued = False
        execution_permitted = False
    elif disposition in {"AUTO_EXECUTE", "OBSERVE"}:
        if intent.decision != models.GovernanceDecision.ALLOW or not auth:
            raise HTTPException(status_code=409, detail="Permitting disposition requires the existing runtime's ALLOW intent and bounded authorization")
        if (auth.agent_id != intent.agent_id or auth.amount_minor_units != intent.amount_minor_units
                or auth.currency != intent.currency or auth.transaction_id != intent.transaction_id
                or auth.mandate_id != intent.mandate_id):
            raise HTTPException(status_code=409, detail="Bounded authorization does not match the governed intent")
        # Preserve the saved policy outcome even when this endpoint is called
        # after consume. A spent/expired authorization is not a new escalation;
        # it simply cannot be consumed again.
        authorization_issued = True
        execution_permitted = auth.expires_at > now and auth.usage_count < auth.max_usage
    else:
        raise HTTPException(status_code=409, detail="Unsupported persisted policy disposition")

    receipt.validation_status = f"DECISION_{disposition}"
    receipt.bound_intent_id = intent.intent_id
    receipt.bound_transaction_id = intent.transaction_id
    receipt.bound_decision_id = cp_decision.decision_id
    receipt.bound_authorization_id = auth.authorization_id if authorization_issued and auth else None
    receipt.bound_request_context_digest = expected_digest
    reason_codes = list(cp_decision.reason_codes or [])
    audit_action = "safr_escalation_hold_created" if disposition == "ESCALATE" else "safr_governance_disposition"
    _audit(db, org_id=org_id, action=audit_action, target=receipt.receipt_id,
           detail={"receipt_id": receipt.receipt_id, "envelope_id": req.envelope_id,
                   "intent_id": intent.intent_id, "transaction_id": intent.transaction_id,
                   "decision_id": cp_decision.decision_id, "policy_name": cp_decision.policy_name,
                   "policy_version": cp_decision.policy_version, "disposition": disposition,
                   "reason_codes": reason_codes,
                   "reason_evidence": cp_decision.reason_evidence or {},
                   "reason_catalog_version": cp_decision.reason_catalog_version,
                   "risk_score_bps": cp_decision.risk_score_bps,
                   "evidence_quality_bps": cp_decision.evidence_quality_bps,
                   "request_context_digest": expected_digest,
                   "authorization_id": auth.authorization_id if auth and authorization_issued else None,
                   "authorization_issued": authorization_issued,
                   "execution_permitted": execution_permitted,
                   "execution_performed_by_this_route": False})
    db.commit()
    return {"receipt_id": receipt.receipt_id, "envelope_id": req.envelope_id,
            "validation_status": receipt.validation_status, "intent_id": intent.intent_id,
            "transaction_id": intent.transaction_id, "decision_id": cp_decision.decision_id,
            "policy_name": cp_decision.policy_name, "policy_version": cp_decision.policy_version,
            "disposition": disposition, "reason_codes": reason_codes,
            "reason_evidence": cp_decision.reason_evidence or {},
            "reason_catalog_version": cp_decision.reason_catalog_version,
            "risk_score_bps": cp_decision.risk_score_bps,
            "evidence_quality_bps": cp_decision.evidence_quality_bps,
            "authorization_issued": authorization_issued,
            "authorization": ({"authorization_id": auth.authorization_id,
                                "expires_at": auth.expires_at.isoformat(),
                                "max_usage": auth.max_usage, "usage_count": auth.usage_count,
                                "status": ("CONSUMABLE" if auth.expires_at > now and auth.usage_count < auth.max_usage
                                           else "CONSUMED" if auth.usage_count >= auth.max_usage else "EXPIRED"),
                                "consume_endpoint": f"/v1/payments/authorizations/{auth.authorization_id}/consume"}
                               if auth and authorization_issued else None),
            "execution_permitted": execution_permitted,
            "execution_performed_by_this_route": False,
            "next_step": ("Consume the existing one-time authorization through the authenticated payment endpoint."
                          if execution_permitted else
                          "Keep execution on hold; an authorised reviewer or a new policy decision is required." if disposition == "ESCALATE"
                          else "This authorization is already consumed or expired; do not retry it. Obtain a fresh decision if a new payment is required." if auth and authorization_issued
                          else "No authorization exists; do not execute this intent.")}


@router.get("/organizations/{org_id}/fleet/risk-summary")
def fleet_risk_summary(
    org_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Tenant-scoped treasury fleet exposure, recent disposition and per-agent risk."""
    authenticated_org = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    if authenticated_org != org_id:
        raise HTTPException(status_code=403, detail="URL organization differs from authenticated organization")
    now = _now()
    cutoff = now - timedelta(hours=24)
    agents = db.query(models.Agent).filter_by(org_id=org_id).order_by(models.Agent.agent_id.asc()).all()
    recent = db.query(models.ControlPlaneDecision).filter(
        models.ControlPlaneDecision.org_id == org_id,
        models.ControlPlaneDecision.created_at >= cutoff,
    ).order_by(models.ControlPlaneDecision.created_at.desc()).all()
    decisions_by_agent: dict[str, list] = {a.agent_id: [] for a in agents}
    intents_by_id = {i.intent_id: i for i in db.query(models.PaymentIntent).filter_by(org_id=org_id).all()}
    for dec in recent:
        intent = intents_by_id.get(dec.intent_id)
        if intent and intent.agent_id in decisions_by_agent:
            decisions_by_agent[intent.agent_id].append(dec)

    auth_rows = db.query(models.BoundedAuthorization).filter_by(org_id=org_id).all()
    txn_rows = db.query(models.ProviderTransaction).filter_by(org_id=org_id).all()
    pending_states = {"AUTHORIZED", "PROVIDER_SUBMITTED", "PROVIDER_AUTHORIZED", "PROVIDER_UNKNOWN", "PAYMENT_PENDING"}
    inflight_auth_ids = {t.authorization_id for t in txn_rows if t.state in pending_states}
    auth_by_agent: dict[str, dict[str, int]] = {a.agent_id: {} for a in agents}
    total_exposure: dict[str, int] = {}
    pending_count_by_agent: dict[str, int] = {a.agent_id: 0 for a in agents}
    for auth in auth_rows:
        unconsumed = auth.usage_count < auth.max_usage and auth.expires_at > now
        in_flight = auth.authorization_id in inflight_auth_ids
        if not (unconsumed or in_flight) or auth.agent_id not in auth_by_agent:
            continue
        currency = auth.currency
        auth_by_agent[auth.agent_id][currency] = auth_by_agent[auth.agent_id].get(currency, 0) + int(auth.amount_minor_units)
        total_exposure[currency] = total_exposure.get(currency, 0) + int(auth.amount_minor_units)
        pending_count_by_agent[auth.agent_id] += 1

    per_agent = []
    for agent in agents:
        decs = decisions_by_agent.get(agent.agent_id, [])
        latest = decs[0] if decs else None
        latest_risk = latest.risk_score_bps if latest else None
        statuses = {d.disposition for d in decs}
        if agent.status != models.AgentStatus.ACTIVE:
            risk_status = "BLOCKED"
        elif latest is None:
            risk_status = "UNASSESSED"
        elif latest.disposition in {"DENY", "ESCALATE"} or latest_risk is not None and latest_risk >= 6000:
            risk_status = "HIGH"
        elif latest.disposition == "OBSERVE" or latest_risk is not None and latest_risk >= 2500:
            risk_status = "WATCH"
        else:
            risk_status = "NORMAL"
        per_agent.append({
            "agent_id": agent.agent_id,
            "name": agent.name,
            "status": agent.status.value if hasattr(agent.status, "value") else str(agent.status),
            "risk_status": risk_status,
            "latest_disposition": latest.disposition if latest else None,
            "latest_risk_score_bps": latest_risk,
            "latest_evidence_quality_bps": latest.evidence_quality_bps if latest else None,
            "decisions_last_24h": len(decs),
            "denials_last_24h": sum(d.disposition == "DENY" for d in decs),
            "escalations_last_24h": sum(d.disposition == "ESCALATE" for d in decs),
            "outstanding_authorization_count": pending_count_by_agent[agent.agent_id],
            "outstanding_exposure_by_currency_minor_units": auth_by_agent[agent.agent_id],
        })
    return {"org_id": org_id, "as_of": now.isoformat(), "window_hours": 24,
            "fleet": {"total_agents": len(agents),
                      "active_agents": sum(a.status == models.AgentStatus.ACTIVE for a in agents),
                      "revoked_or_inactive_agents": sum(a.status != models.AgentStatus.ACTIVE for a in agents),
                      "agents_high_risk": sum(x["risk_status"] == "HIGH" for x in per_agent),
                      "agents_unassessed": sum(x["risk_status"] == "UNASSESSED" for x in per_agent),
                      "outstanding_authorization_count": sum(pending_count_by_agent.values()),
                      "outstanding_exposure_by_currency_minor_units": total_exposure},
            "agents": per_agent,
            "exposure_semantics": "Unconsumed, unexpired authorizations plus unsettled provider transactions; amounts are minor units and grouped by currency."}


@router.post("/organizations/{org_id}/agents/{agent_id}/revoke")
def revoke_fleet_agent(
    org_id: str, agent_id: str,
    reason: str = Query(default="fleet_risk_revoke", min_length=5, max_length=160),
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Emergency tenant-scoped fleet revocation; invalidates credentials and pending authority."""
    authenticated_org = _tenant(db, x_paari_control_key, x_paari_org)
    if authenticated_org != org_id:
        raise HTTPException(status_code=403, detail="URL organization differs from authenticated organization")
    agent = db.query(models.Agent).filter_by(org_id=org_id, agent_id=agent_id).with_for_update().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in this organization")
    before = agent.status.value if hasattr(agent.status, "value") else str(agent.status)
    agent.status = models.AgentStatus.REVOKED
    db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).update(
        {"revoked": True}, synchronize_session=False)
    db.query(models.ResourceAccessGrant).filter_by(
        org_id=org_id, subject_type="agent", subject_id=agent_id, status="ACTIVE"
    ).update({"status": "REVOKED", "revoked_at": _now()}, synchronize_session=False)
    now = _now()
    outstanding = db.query(models.BoundedAuthorization).filter_by(
        org_id=org_id, agent_id=agent_id
    ).filter(models.BoundedAuthorization.usage_count < models.BoundedAuthorization.max_usage).all()
    invalidated = 0
    for auth in outstanding:
        if auth.expires_at > now:
            auth.expires_at = now
            auth.usage_count = auth.max_usage
            invalidated += 1
    _audit(db, org_id=org_id, action="fleet_agent_revoked", target=agent_id,
           detail={"agent_id": agent_id, "previous_status": before, "status": "revoked",
                   "reason": reason, "credentials_revoked": True,
                   "pending_authorizations_invalidated": invalidated})
    db.commit()
    return {"org_id": org_id, "agent_id": agent_id, "previous_status": before,
            "status": "revoked", "credentials_revoked": True,
            "active_agent_grants_revoked": True,
            "pending_authorizations_invalidated": invalidated,
            "reason": reason}


@router.post("/portability/import/validate")
def validate_portability_import(
    req: schemas.PortabilityImportValidate,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Verify a source package and stage identity metadata under destination controls.

    The package's own public key is not a trust anchor. Staging requires a
    separately pinned Paari issuer key and destination parent, principal,
    resource and consent grant. It never activates the imported agent or moves
    source-tenant authority.
    """
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    from app.portability import validate_agent_portability_package, PortabilityValidationError
    try:
        trusted = _trusted_portability_issuers()
        verified = validate_agent_portability_package(req.package, trusted_issuer_keys=trusted)
    except PortabilityValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Portability package verification failed: {exc}") from exc

    parent = db.query(models.ParentAuthority).filter_by(
        org_id=org_id, parent_id=req.destination_parent_id,
        status=models.ParentStatus.ACTIVE,
    ).first()
    if not parent or parent.trust_tier not in {"admin_approved", "kyb_verified"}:
        raise HTTPException(status_code=403, detail="Destination parent must be active and locally trust-approved")
    principal = db.query(models.PrincipalIdentity).filter_by(
        org_id=org_id, principal_id=req.destination_principal_id, status="ACTIVE"
    ).first()
    if (not principal or not principal.attested_at or principal.assurance_level not in {"substantial", "high"}
            or any(term in (principal.identity_provider or "").casefold() for term in ("synthetic", "sandbox", "test", "fixture"))):
        raise HTTPException(status_code=403, detail="Destination principal requires non-synthetic, attested substantial/high assurance")
    resource = db.query(models.GovernedResource).filter_by(
        org_id=org_id, resource_id=req.destination_resource_id, status="ACTIVE"
    ).first()
    if not resource:
        raise HTTPException(status_code=403, detail="Destination governed resource must be active")
    now = _now()
    grants = db.query(models.ResourceAccessGrant).filter_by(
        org_id=org_id, resource_id=resource.resource_id, subject_type="principal",
        subject_id=principal.principal_id, status="ACTIVE", consent_reference=req.consent_reference,
    ).all()
    valid_grant = any(g.valid_from <= now < g.valid_until and set(g.actions or []) &
                      {"payment:execute", "resource:read", "data:read", "api:invoke"} for g in grants)
    if not valid_grant:
        raise HTTPException(status_code=403, detail="Destination-local consent and a current principal resource grant are required")

    package_digest = hashlib.sha256(crypto_utils.canonical_json(req.package).encode("utf-8")).hexdigest()
    prior = db.query(models.AgentPortabilityImport).filter_by(org_id=org_id, package_digest=package_digest).first()
    if prior:
        raise HTTPException(status_code=409, detail=f"Portability package is already staged as import {prior.import_id}")
    issuer = req.package.get("issuer") or {}
    card = req.package.get("agent_card") or {}
    parent_identity = req.package.get("parent_identity") or {}
    row = models.AgentPortabilityImport(
        org_id=org_id, package_digest=package_digest,
        source_org_id=(req.package.get("source_organization") or {}).get("org_id"),
        source_agent_id=str(card.get("agent_id") or verified.get("agent_id") or ""),
        source_parent_id=str(parent_identity.get("parent_id") or verified.get("parent_id") or ""),
        destination_parent_id=parent.parent_id, destination_principal_id=principal.principal_id,
        destination_resource_id=resource.resource_id, consent_reference=req.consent_reference,
        state="STAGED", verification_evidence={
            "source_package_signatures_verified": verified.get("signatures_verified", []),
            "source_issuer_key_id": issuer.get("key_id"),
            "destination_parent_status": "ACTIVE",
            "destination_parent_trust_tier": parent.trust_tier,
            "destination_principal_status": "ACTIVE",
            "destination_principal_assurance": principal.assurance_level,
            "destination_resource_status": "ACTIVE",
            "destination_consent_grant_verified": True,
            "authority_transferred": False,
            "destination_agent_registration_required": True,
        }
    )
    db.add(row)
    try:
        db.flush()
        _audit(db, org_id=org_id, action="agent_portability_import_staged", target=row.import_id,
               detail={"import_id": row.import_id, "package_digest": package_digest,
                       "source_agent_id": row.source_agent_id, "source_parent_id": row.source_parent_id,
                       "destination_parent_id": parent.parent_id,
                       "destination_principal_id": principal.principal_id,
                       "destination_resource_id": resource.resource_id,
                       "state": row.state, "authority_transferred": False})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Portability package was already staged for this organization") from exc
    return {"import_id": row.import_id, "org_id": org_id, "state": row.state,
            "package_digest": package_digest, "source_agent_id": row.source_agent_id,
            "source_parent_id": row.source_parent_id,
            "destination_checks": row.verification_evidence,
            "authority_transferred": False,
            "credentials_imported": False, "mandate_imported": False,
            "resource_grants_imported": False,
            "next_step": "Register the agent under the destination parent, issue fresh credentials, create new local grants/mandates, and obtain a new transaction-bound authorization."}


@router.get("/portability/imports/{import_id}")
def get_portability_import(import_id: str,
                          x_paari_control_key: str = Header(default=""),
                          x_paari_org: str = Header(default=""),
                          db: Session = Depends(get_db)):
    org_id = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    row = db.query(models.AgentPortabilityImport).filter_by(org_id=org_id, import_id=import_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Portability import not found")
    return {"import_id": row.import_id, "org_id": org_id, "state": row.state,
            "package_digest": row.package_digest, "source_agent_id": row.source_agent_id,
            "source_parent_id": row.source_parent_id,
            "destination_parent_id": row.destination_parent_id,
            "destination_principal_id": row.destination_principal_id,
            "destination_resource_id": row.destination_resource_id,
            "verification_evidence": row.verification_evidence,
            "authority_transferred": False, "created_at": row.created_at}


@router.get("/organizations/{org_id}/agents/{agent_id}/portability-export")
def export_agent_portability_package(
    org_id: str,
    agent_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Export signed identity/delegation metadata; active authority is never transferred."""
    authenticated_org = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    if authenticated_org != org_id:
        raise HTTPException(status_code=403, detail="URL organization differs from authenticated organization")
    agent = db.query(models.Agent).filter_by(org_id=org_id, agent_id=agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found in this organization")
    parent = db.query(models.ParentAuthority).filter_by(id=agent.parent_pk, org_id=org_id).first()
    if not parent:
        raise HTTPException(status_code=409, detail="Agent parent record is missing")
    delegation = db.query(models.DelegationRecord).filter_by(
        org_id=org_id, delegation_id=agent.delegation_id, parent_pk=parent.id
    ).first()
    if not delegation:
        raise HTTPException(status_code=409, detail="Agent's delegation record is missing")
    active_credential = db.query(models.Credential).filter_by(agent_pk=agent.id, revoked=False).order_by(models.Credential.issued_at.desc()).first()
    from app.portability import build_agent_portability_package, PortabilityValidationError
    # Keep card signature bytes canonical: sign the exact string-valued fields
    # used on the Agent Card wire, including the original ISO timestamp form.
    card_fields = {
        "agent_id": agent.agent_id,
        "name": agent.name,
        "agent_type": agent.agent_type,
        "parent_id": parent.parent_id,
        "parent_name": parent.name,
        "identity_status": agent.status.value,
        "public_key_reference": agent.public_key_pem,
        "granted_capabilities": list(agent.granted_capabilities or []),
        "payment_limit_minor_units": int(agent.payment_limit_minor_units),
        "currency": agent.currency,
        "valid_until": agent.valid_until.isoformat() if agent.valid_until else None,
        "credential_id": active_credential.credential_id if active_credential else "",
        "paari_endpoint": "/agents",
    }
    card = {**card_fields, "card_signature_b64": security.sign_agent_card(card_fields),
            "paari_public_key_pem": security.paari_public_key_pem()}
    try:
        return build_agent_portability_package(
            agent=agent, parent=parent, delegation_record=delegation,
            agent_card=card,
        )
    except PortabilityValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def security_crypto_verify(public_key_pem: str, payload: dict, signature_b64: str) -> bool:
    from app import crypto_utils
    return crypto_utils.verify_signature(public_key_pem, crypto_utils.canonical_json(payload), signature_b64)


def security_crypto_fingerprint(public_key_pem: str) -> str:
    from app import crypto_utils
    return crypto_utils.public_key_fingerprint(public_key_pem)
