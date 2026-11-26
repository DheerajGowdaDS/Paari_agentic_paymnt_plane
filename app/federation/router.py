"""v3.5 operator-facing federation agreements and payment context evidence.

All registry mutations require tenant-scoped control credentials. The USER
signer enrollment is a local organizational assertion, NOT external eKYC.
A receiver's signature uses the separately pinned v3.4 receiver key.
"""
from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app import crypto_utils, models
from app.audit import record_audit
from app.database import get_db
from app.control_plane.router import _tenant
from app.federation.contracts import SignerRegistration, SignedAgreement, RevokeReason
from app.federation import policy

router = APIRouter(prefix="/control/v1/federation", tags=["federated-governance"])


def _authorize(db: Session, key: str, org: str, scope="control:read") -> str:
    return _tenant(db, key, org, required_scope=scope)


def _audit(db: Session, org: str, kind: str, ref: str, detail: dict) -> None:
    record_audit(db, org_id=org, transaction_id=f"federation:{ref}", agent_id="",
                 parent_id=None, kind=kind, detail=detail)


@router.get("/requirements")
def requirements(x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                 db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org)
    return {"org_id": org, "policy_digest": policy.policy_digest(db, org),
            "required_signed_roles": ["SENDER_ORG", "USER", "RECEIVER"],
            "strict_enforcement": policy.enforced(),
            "authority_transferred_by_agent_card": False,
            "requirements": "signed agreements do not replace user mandates, receiver checks or bounded authorizations"}


@router.post("/signers", status_code=201)
def enroll_signer(req: SignerRegistration, x_paari_control_key: str = Header(default=""),
                  x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org, "control:write")
    if req.subject_type == "SENDER_ORG" and req.subject_id != org:
        raise HTTPException(403, "organization signer must use the authenticated org ID")
    algorithm = (req.public_key_algorithm or "ed25519").strip().lower()
    if algorithm == "ed25519":
        # Legacy path: must be a valid Ed25519 PEM.
        try:
            key_obj = serialization.load_pem_public_key(req.public_key_pem.encode())
            if not isinstance(key_obj, Ed25519PublicKey):
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(422, "Signer public key must be Ed25519 PEM")
    elif algorithm in {"ml-dsa-65", "slh-dsa-sha2-128s"}:
        # PQC path: base64 raw key material. Validate length so clearly-bad
        # material is rejected early; the actual signature check happens at
        # agreement ingest time in policy.verify_agreement.
        if len(req.public_key_pem) < 100:
            raise HTTPException(422, "PQC public key material too short")
    else:
        raise HTTPException(422, "Unsupported signer public key algorithm")
    row = models.FederationSigner(org_id=org, subject_type=req.subject_type,
             subject_id=req.subject_id, public_key_pem=req.public_key_pem,
             public_key_algorithm=algorithm)
    db.add(row)
    try:
        db.flush()
        _audit(db, org, "federation_signer_enrolled", row.signer_id,
              {"subject_type": row.subject_type, "subject_id": row.subject_id,
               "public_key_fingerprint": crypto_utils.public_key_fingerprint(
                   req.public_key_pem, algorithm=algorithm),
               "public_key_algorithm": algorithm,
               "assurance": "operator_registered_not_external_identity_verified"})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Signer already registered; revoke before changing signing authority")
    return {"signer_id": row.signer_id, "subject_type": row.subject_type, "subject_id": row.subject_id,
            "key_fingerprint": crypto_utils.public_key_fingerprint(row.public_key_pem, algorithm=algorithm),
            "public_key_algorithm": algorithm, "status": row.status,
            "assurance": "operator_registered_not_external_identity_verified"}


@router.post("/signers/{signer_id}/revoke")
def revoke_signer(signer_id: str, req: RevokeReason, x_paari_control_key: str = Header(default=""),
                  x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org, "control:write")
    row = db.query(models.FederationSigner).filter_by(org_id=org, signer_id=signer_id).with_for_update().first()
    if not row: raise HTTPException(404, "Signer not found")
    if row.status != "ACTIVE": raise HTTPException(409, "Signer already inactive")
    row.status = "REVOKED"; row.revoked_at = policy.now()
    _audit(db, org, "federation_signer_revoked", signer_id, {"reason": req.reason})
    db.commit()
    return {"signer_id": signer_id, "status": "REVOKED"}


@router.post("/agreements", status_code=201)
def ingest_agreement(req: SignedAgreement, x_paari_control_key: str = Header(default=""),
                     x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org, "control:write")
    c = req.claims
    if c.org_id != org: raise HTTPException(403, "Agreement org is not the authenticated tenant")
    ok, reason, fingerprint, sig_algorithm = policy.verify_agreement(db, c, req.signature_b64)
    if not ok: raise HTTPException(403, reason)
    payload = c.model_dump(mode="json")
    row = models.FederationAgreement(agreement_id=c.agreement_id, org_id=org,
        agent_id=c.agent_id, beneficiary_id=c.beneficiary_id, subject_type=c.subject_type,
        subject_id=c.subject_id, payload=payload, payload_digest=policy.digest_json(payload),
        signature_b64=req.signature_b64, signer_fingerprint=fingerprint,
        signature_algorithm=sig_algorithm)
    db.add(row)
    try:
        db.flush()
        _audit(db, org, "federation_agreement_accepted", row.agreement_id,
               {"type": c.subject_type, "agent_id": c.agent_id, "beneficiary_id": c.beneficiary_id,
                "policy_digest": c.policy_digest, "document_digest": c.document_digest,
                "signer_fingerprint": fingerprint, "expires_at": c.expires_at.isoformat()})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Agreement ID already used; signed receipts are single-ingest")
    return {"agreement_id": row.agreement_id, "status": row.status, "subject_type": row.subject_type,
            "signature_verified": True, "expires_at": c.expires_at, "policy_digest": c.policy_digest}


@router.get("/agreements")
def list_agreements(x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                    db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org)
    return [{"agreement_id": r.agreement_id, "agent_id": r.agent_id,
             "beneficiary_id": r.beneficiary_id, "subject_type": r.subject_type,
             "subject_id": r.subject_id, "status": r.status, "policy_digest": r.payload.get("policy_digest"),
             "expires_at": r.payload.get("expires_at"), "created_at": r.created_at}
            for r in db.query(models.FederationAgreement).filter_by(org_id=org).order_by(
                models.FederationAgreement.id.desc()).limit(200).all()]


@router.post("/agreements/{agreement_id}/revoke")
def revoke_agreement(agreement_id: str, req: RevokeReason,
                     x_paari_control_key: str = Header(default=""), x_paari_org: str = Header(default=""),
                     db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org, "control:write")
    row = db.query(models.FederationAgreement).filter_by(org_id=org,
         agreement_id=agreement_id).with_for_update().first()
    if not row: raise HTTPException(404, "Agreement not found")
    if row.status != "ACTIVE": raise HTTPException(409, "Agreement already inactive")
    row.status = "REVOKED"; row.revoked_at = policy.now()
    _audit(db, org, "federation_agreement_revoked", agreement_id, {"reason": req.reason})
    db.commit()
    return {"agreement_id": agreement_id, "status": "REVOKED"}


@router.get("/contexts/{intent_id}")
def inspect_context(intent_id: str, x_paari_control_key: str = Header(default=""),
                    x_paari_org: str = Header(default=""), db: Session = Depends(get_db)):
    org = _authorize(db, x_paari_control_key, x_paari_org)
    intent = db.query(models.PaymentIntent).filter_by(org_id=org, intent_id=intent_id).first()
    if not intent: raise HTTPException(404, "Payment intent not found")
    record = db.query(models.PaymentContextEnvelope).filter_by(org_id=org, intent_id=intent_id).first()
    if not record: raise HTTPException(404, "No signed payment context for this intent")
    return {"context_id": record.context_id, "intent_id": intent_id, "payload": record.payload,
            "payload_digest": record.payload_digest, "signature_b64": record.signature_b64,
            "issuer_key_id": record.issuer_key_id, "signature_valid": policy.verify_context(record, intent),
            "settlement_evidence": False, "execution_authorization": False,
            "created_at": record.created_at}
