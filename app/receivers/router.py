"""Organization-bound receiver registry and externally signed acknowledgement API.

The approval API asserts LOCAL ADMIN APPROVAL only, never external KYB.
Receiver evidence does NOT settle or mutate provider transactions.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import hashlib
import re
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app import models, security, crypto_utils
from app.audit import record_audit
from app.database import get_db
from app.control_plane.router import _tenant

router = APIRouter(prefix="/control/v1/receivers", tags=["receiver-control-plane"])

def _now(): return datetime.now(timezone.utc)

def _org(db: Session, key: str, org: str, scope="control:read"):
    return _tenant(db, key, org, required_scope=scope)

def _view_inst(i):
    return {"receiver_id": i.receiver_id, "external_id":i.external_id,"name": i.name,
            "rail": i.rail,"status": i.status,"identity_assurance": i.identity_assurance,
            "public_key_fingerprint": crypto_utils.public_key_fingerprint(i.public_key_pem),
            "verification_reference": i.verification_reference, "created_at": i.created_at,
            "verified_at": i.verified_at}

def _view_beneficiary(b):
    return {"beneficiary_id": b.beneficiary_id,"receiver_id":b.receiver_id,"alias":b.alias,
            "currency":b.currency,"max_payment_minor_units":b.max_payment_minor_units,
            "status":b.status,"account_fingerprint":b.account_fingerprint,"created_at":b.created_at}

class CreateInstitution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    external_id: str = Field(min_length=3,max_length=128)
    name: str = Field(min_length=3,max_length=200)
    rail: Literal["BANK", "OPEN_FINANCE", "TREASURY", "STABLECOIN", "SANDBOX"]
    public_key_pem: str = Field(min_length=50,max_length=4000)

class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["SUSPENDED", "REVOKED"]
    reason: str = Field(min_length=8,max_length=300)

class ApproveInstitution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verification_reference: str = Field(min_length=8,max_length=200)
    # This is merely local administrative approval, not a KYB claim.

class CreateBeneficiary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    receiver_id: str = Field(min_length=1,max_length=64)
    alias: str = Field(min_length=2,max_length=200)
    account_reference: str = Field(min_length=8,max_length=400)
    currency: str = Field(pattern=r"^[A-Z]{3,10}$")
    max_payment_minor_units: int = Field(gt=0,le=2_000_000_000)

class BlockBeneficiary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=8,max_length=300)

class ReceiverClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=8,max_length=64)
    receiver_id: str = Field(min_length=1,max_length=64)
    beneficiary_id: str = Field(min_length=1,max_length=64)
    intent_id: str = Field(min_length=1,max_length=64)
    result: Literal["ACCEPTED", "REJECTED", "CREDIT_ATTESTED"]
    provider_reference: str = Field(min_length=1,max_length=128)
    amount_minor_units: int = Field(gt=0,le=2_000_000_000)
    currency: str = Field(pattern=r"^[A-Z]{3,10}$")
    signed_at: datetime

class SignedClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claim: ReceiverClaim
    signature_b64: str = Field(min_length=32,max_length=256)

@router.post("/institutions",status_code=201)
def create_institution(req:CreateInstitution,x_paari_control_key:str=Header(default=""),
                       x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    org = _org(db,x_paari_control_key,x_paari_org,"control:write")
    try:
        key = serialization.load_pem_public_key(req.public_key_pem.encode())
        if not isinstance(key,Ed25519PublicKey): raise ValueError()
    except Exception:
        raise HTTPException(422,"Receiver key must be a valid Ed25519 public key")
    inst=models.ReceiverInstitution(org_id=org,external_id=req.external_id.strip(),name=req.name.strip(),
                                   rail=req.rail,public_key_pem=req.public_key_pem,status="PENDING")
    db.add(inst)
    try:
        db.flush()
        record_audit(db,transaction_id=f"receiver:{inst.receiver_id}",agent_id="",parent_id=None,
                     kind="receiver_registered",org_id=org,
                     detail={"receiver_id":inst.receiver_id,"rail":inst.rail,
                             "key_fingerprint":crypto_utils.public_key_fingerprint(inst.public_key_pem)})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409,"Institution already registered")
    return _view_inst(inst)

@router.get("/institutions")
def list_institutions(x_paari_control_key:str=Header(default=""),x_paari_org:str=Header(default=""),
                      db:Session=Depends(get_db)):
    org=_org(db,x_paari_control_key,x_paari_org)
    return [_view_inst(i) for i in db.query(models.ReceiverInstitution).filter_by(org_id=org).order_by(models.ReceiverInstitution.id.desc()).all()]

@router.post("/institutions/{receiver_id}/approve")
def approve_institution(receiver_id:str,req:ApproveInstitution,x_admin_api_key:str=Header(default=""),
                        x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    security.require_admin(x_admin_api_key)
    if not x_paari_org: raise HTTPException(400,"X-Paari-Org required")
    i=db.query(models.ReceiverInstitution).filter_by(org_id=x_paari_org,receiver_id=receiver_id).with_for_update().first()
    if not i:raise HTTPException(404,"Receiver not found")
    if i.status!="PENDING": raise HTTPException(409,"Only pending receiver can be approved")
    i.status="ACTIVE"; i.identity_assurance="ADMIN_APPROVED"
    i.verification_reference=req.verification_reference; i.verified_at=_now()
    record_audit(db,transaction_id=f"receiver:{receiver_id}",agent_id="",parent_id=None,
                 kind="receiver_admin_approved",org_id=i.org_id,
                 detail={"receiver_id":receiver_id,"verification_reference":req.verification_reference,"assurance":"ADMIN_APPROVED_NOT_KYB"})
    db.commit();return _view_inst(i)

@router.post("/institutions/{receiver_id}/status")
def status_institution(receiver_id:str,req:StatusChange,x_paari_control_key:str=Header(default=""),
                       x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    org=_org(db,x_paari_control_key,x_paari_org,"control:write")
    i=db.query(models.ReceiverInstitution).filter_by(org_id=org,receiver_id=receiver_id).with_for_update().first()
    if not i:raise HTTPException(404,"Receiver not found")
    i.status=req.status
    record_audit(db,transaction_id=f"receiver:{receiver_id}",agent_id="",parent_id=None,
                 kind="receiver_restricted",org_id=org,
                 detail={"receiver_id":receiver_id,"status":req.status,"reason":req.reason})
    db.commit();return _view_inst(i)

@router.post("/beneficiaries",status_code=201)
def create_beneficiary(req:CreateBeneficiary,x_paari_control_key:str=Header(default=""),
                       x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    org=_org(db,x_paari_control_key,x_paari_org,"control:write")
    inst=db.query(models.ReceiverInstitution).filter_by(receiver_id=req.receiver_id,org_id=org).first()
    if not inst or inst.status!="ACTIVE":raise HTTPException(403,"Receiving institution is not active")
    # keyed salt must be supplied for stable pseudonymous account references
    import os
    salt=os.environ.get("PAARI_BENEFICIARY_HASH_SECRET","")
    if len(salt)<32: raise HTTPException(503,"PAARI_BENEFICIARY_HASH_SECRET must be configured")
    import hmac
    fingerprint=hmac.new(salt.encode(),(req.receiver_id+":"+req.account_reference).encode(),hashlib.sha256).hexdigest()
    row=models.ReceiverBeneficiary(org_id=org,receiver_id=req.receiver_id,alias=req.alias.strip(),
                                   account_fingerprint=fingerprint,currency=req.currency,
                                   max_payment_minor_units=req.max_payment_minor_units,status="ACTIVE")
    db.add(row)
    try:
        db.flush()
        record_audit(db,transaction_id=f"beneficiary:{row.beneficiary_id}",agent_id="",parent_id=None,
                     kind="beneficiary_registered",org_id=org,
                     detail={"beneficiary_id":row.beneficiary_id,"receiver_id":req.receiver_id,"currency":req.currency,"limit":req.max_payment_minor_units})
        db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,"Beneficiary account already registered")
    return _view_beneficiary(row)

@router.get("/beneficiaries")
def list_beneficiaries(x_paari_control_key:str=Header(default=""),x_paari_org:str=Header(default=""),
                      db:Session=Depends(get_db)):
    org=_org(db,x_paari_control_key,x_paari_org)
    return [_view_beneficiary(b) for b in db.query(models.ReceiverBeneficiary).filter_by(org_id=org).order_by(models.ReceiverBeneficiary.id.desc()).all()]

@router.post("/beneficiaries/{beneficiary_id}/block")
def block_beneficiary(beneficiary_id:str,req:BlockBeneficiary,x_paari_control_key:str=Header(default=""),
                      x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    org=_org(db,x_paari_control_key,x_paari_org,"control:write")
    b=db.query(models.ReceiverBeneficiary).filter_by(org_id=org,beneficiary_id=beneficiary_id).with_for_update().first()
    if not b:raise HTTPException(404,"Beneficiary not found")
    b.status="BLOCKED"
    record_audit(db,transaction_id=f"beneficiary:{beneficiary_id}",agent_id="",parent_id=None,
                 kind="beneficiary_blocked",org_id=org,detail={"beneficiary_id":beneficiary_id,"reason":req.reason})
    db.commit();return _view_beneficiary(b)

@router.post("/attestations",status_code=201)
def submit_attestation(req:SignedClaim,db:Session=Depends(get_db)):
    """The receiver authenticates with its PINNED signing key, not a payer admin key.

    Evidence is accepted only for a payer org where the beneficiary/intent
    binding already exists, and the signed payload matches that payment.
    """
    c=req.claim
    inst=db.query(models.ReceiverInstitution).filter_by(receiver_id=c.receiver_id,status="ACTIVE",identity_assurance="ADMIN_APPROVED").first()
    if not inst:raise HTTPException(403,"Receiver not approved or inactive")
    ben=db.query(models.ReceiverBeneficiary).filter_by(beneficiary_id=c.beneficiary_id,
                                                      receiver_id=c.receiver_id,org_id=inst.org_id,status="ACTIVE").first()
    if not ben:raise HTTPException(403,"Beneficiary missing or disabled")
    intent=db.query(models.PaymentIntent).filter_by(intent_id=c.intent_id,org_id=inst.org_id,beneficiary_id=c.beneficiary_id).first()
    if not intent or intent.decision!=models.GovernanceDecision.ALLOW:
        raise HTTPException(403,"No allowed intent bound to beneficiary")
    if (c.amount_minor_units!=intent.amount_minor_units or c.currency!=intent.currency or
        c.currency!=ben.currency):raise HTTPException(403,"Receiver claim does not match payment bounds")
    # ACCEPTED/REJECTED are receiver pre-execution acknowledgements. They
    # may be recorded while the sender's authorization is still awaiting
    # consumption. CREDIT_ATTESTED is strictly post-capture evidence and never
    # changes provider settlement state.
    txn=db.query(models.ProviderTransaction).filter_by(intent_id=intent.intent_id,org_id=inst.org_id).first()
    if not txn:
        raise HTTPException(409,"Payment authorization record is unavailable")
    if c.result in {"ACCEPTED", "REJECTED"} and txn.state not in {
        "AUTHORIZED", "PROVIDER_SUBMITTED", "PROVIDER_UNKNOWN",
        "PROVIDER_AUTHORIZED", "CAPTURED", "PAID", "REFUNDED"
    }:
        raise HTTPException(409,"Receiver acknowledgement is not valid for the current payment state")
    if c.result=="CREDIT_ATTESTED" and txn.state not in {"CAPTURED", "PAID", "REFUNDED"}:
        raise HTTPException(409,"Credit evidence requires provider capture or reconciliation")
    signed_at=c.signed_at if c.signed_at.tzinfo else c.signed_at.replace(tzinfo=timezone.utc)
    if abs((_now()-signed_at).total_seconds())>300:raise HTTPException(403,"Receiver claim timestamp outside five-minute window")
    payload=c.model_dump(mode="json")
    canonical=crypto_utils.canonical_json(payload)
    if not crypto_utils.verify_signature(inst.public_key_pem,canonical,req.signature_b64):
        raise HTTPException(403,"Receiver signature invalid")
    row=models.ReceiverAttestation(org_id=inst.org_id,receiver_id=c.receiver_id,beneficiary_id=c.beneficiary_id,
        intent_id=c.intent_id,event_id=c.event_id,result=c.result,provider_reference=c.provider_reference,
        amount_minor_units=c.amount_minor_units,currency=c.currency,signed_at=signed_at,
        signature_b64=req.signature_b64,payload_digest=hashlib.sha256(canonical.encode()).hexdigest())
    db.add(row)
    try:
        db.flush()
        record_audit(db,transaction_id=intent.transaction_id,agent_id=intent.agent_id,parent_id=None,
                     kind="receiver_attestation_ingested",org_id=inst.org_id,
                     detail={"receiver_id":c.receiver_id,"beneficiary_id":c.beneficiary_id,
                             "intent_id":c.intent_id,"event_id":c.event_id,"result":c.result,
                             "claim_digest":row.payload_digest,"settlement_authority":"EVIDENCE_ONLY_NOT_SETTLEMENT"})
        db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,"Receiver attestation replayed")
    return {"attestation_id":row.attestation_id,"intent_id":row.intent_id,"result":row.result,
            "payload_digest":row.payload_digest,"receiver_signature_verified":True,
            "settlement_confirmed":False,"received_at":row.received_at}

@router.get("/attestations/{intent_id}")
def list_attestations(intent_id:str,x_paari_control_key:str=Header(default=""),
                      x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    org=_org(db,x_paari_control_key,x_paari_org)
    return [{"attestation_id":e.attestation_id,"intent_id":e.intent_id,"result":e.result,
             "receiver_id":e.receiver_id,"beneficiary_id":e.beneficiary_id,
             "payload_digest":e.payload_digest,"signed_at":e.signed_at,"received_at":e.received_at,
             "settlement_confirmed":False}
            for e in db.query(models.ReceiverAttestation).filter_by(org_id=org,intent_id=intent_id).order_by(models.ReceiverAttestation.id).all()]

@router.get("/payment-evidence/{intent_id}")
def get_receiver_payment_evidence(intent_id:str,x_paari_control_key:str=Header(default=""),
                                  x_paari_org:str=Header(default=""),db:Session=Depends(get_db)):
    """Tenant-authorized read of actual sender/receiver state; no state mutation.

    Keep provider settlement and beneficiary-credit attestation as independent
    evidence dimensions, not one all-purpose 'success' boolean.
    """
    org=_org(db,x_paari_control_key,x_paari_org)
    intent=db.query(models.PaymentIntent).filter_by(intent_id=intent_id,org_id=org).first()
    if not intent:raise HTTPException(404,"Payment intent not found in this organization")
    ben=(db.query(models.ReceiverBeneficiary).filter_by(org_id=org,
        beneficiary_id=intent.beneficiary_id).first() if intent.beneficiary_id else None)
    inst=(db.query(models.ReceiverInstitution).filter_by(org_id=org,
        receiver_id=ben.receiver_id).first() if ben else None)
    auth=db.query(models.BoundedAuthorization).filter_by(intent_id=intent_id,org_id=org).first()
    txn=(db.query(models.ProviderTransaction).filter_by(authorization_id=auth.authorization_id,
        org_id=org).first() if auth else None)
    events=db.query(models.AuditEvent).filter_by(org_id=org,transaction_id=intent.transaction_id).order_by(models.AuditEvent.id).all()
    others=db.query(models.PaymentIntent).filter_by(transaction_id=intent.transaction_id).count()
    from app.audit import verify_chain
    chain_valid=verify_chain(db,intent.transaction_id) if others==1 else None
    attestations=db.query(models.ReceiverAttestation).filter_by(org_id=org,intent_id=intent_id).order_by(models.ReceiverAttestation.id).all()
    env=(getattr(txn,"provider_environment",None) or "unknown") if txn else None
    review_audit=[e for e in events if e.kind in {
        "human_review_challenge_issued", "human_review_approved", "human_review_rejected"}]
    latest_review=review_audit[-1] if review_audit else None
    review_status=("APPROVED" if latest_review and latest_review.kind=="human_review_approved" else
                   "REJECTED" if latest_review and latest_review.kind=="human_review_rejected" else
                   "PENDING" if intent.decision == models.GovernanceDecision.REVIEW else
                   "NOT_REQUIRED")
    # Provider statuses remain provider statuses; a receiver's credit is not
    # independently corroborated by this endpoint.
    return {
      "intent_id":intent_id,"transaction_id":intent.transaction_id,"org_id":org,
      "agent_id":intent.agent_id,"beneficiary_id":intent.beneficiary_id,
      "merchant":intent.merchant,"amount_minor_units":intent.amount_minor_units,"currency":intent.currency,
      "decision":intent.decision.value,"reasons":intent.reasons or [],"created_at":intent.created_at,
      "human_review":{"status":review_status,
          "authority":"REGISTERED_PARENT_SIGNING_KEY" if review_audit else None,
          "last_event_at":latest_review.created_at if latest_review else None,
          "challenge_id":(latest_review.detail or {}).get("challenge_id") if latest_review else None,
          "authorization_from_review":bool(latest_review and latest_review.kind=="human_review_approved" and auth),
          "review_events":[{"kind":e.kind,"created_at":e.created_at,
              "event_hash":e.event_hash} for e in review_audit]},
      "receiver":{"receiver_id":inst.receiver_id,"name":inst.name,"status":inst.status,
                  "identity_assurance":inst.identity_assurance,"rail":inst.rail} if inst else None,
      "beneficiary":{"alias":ben.alias,"status":ben.status,"currency":ben.currency,
                     "max_payment_minor_units":ben.max_payment_minor_units} if ben else None,
      "authorization":{"authorization_id":auth.authorization_id,"expires_at":auth.expires_at,
                       "usage_count":auth.usage_count,"max_usage":auth.max_usage} if auth else None,
    "provider":{"name":txn.provider_name,"state":txn.state,"environment":env,
            "provider_payment_id":txn.provider_payment_id or txn.razorpay_payment_id,
            "order_id":txn.provider_order_id or txn.razorpay_order_id,"webhook_event_id":txn.webhook_event_id,
                  "reconciled_at":txn.reconciled_at} if txn else None,
      "provider_settlement_status":"PROVIDER_CONFIRMED" if txn and txn.state=="PAID" and env in {"test","live"} else (
          "SIMULATED_PAID" if txn and txn.state=="PAID" and env=="simulated" else "UNCONFIRMED"),
      "receiver_credit_independently_verified":False,
      "receiver_attestations":[{"attestation_id":a.attestation_id,"result":a.result,
                                  "payload_digest":a.payload_digest,"signed_at":a.signed_at,
                                  "received_at":a.received_at} for a in attestations],
      "audit_chain_valid":chain_valid,
      "audit_events":[{"kind":a.kind,"created_at":a.created_at,"event_hash":a.event_hash,
                       "previous_state":(a.detail or {}).get("previous_state") if isinstance(a.detail,dict) else None,
                       "current_state":(a.detail or {}).get("current_state") if isinstance(a.detail,dict) else None,
                       "reasons":(a.detail or {}).get("reasons",[]) if isinstance(a.detail,dict) else []}
                      for a in events],
    }
