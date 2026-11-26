"""Fail-closed federated agreements and Paari-signed context evidence.

The recipient's signed ACCEPTANCE is a policy agreement, NOT a deposit receipt.
No portable agent identity grants destination payment authority. Context
signatures NEVER substitute for bounded, single-use payment authorization.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import hmac
import os
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app import crypto_utils, models, security
from app.federation.contracts import AgreementClaims


def now():
    return datetime.now(timezone.utc)


def enforced() -> bool:
    return os.environ.get("PAARI_FEDERATION_ENFORCEMENT") == "1" or os.environ.get("PAARI_LIVE") == "1" or os.environ.get("PAARI_ENV", "").lower() in {"prod", "prod-live"}


def digest_json(data: dict) -> str:
    return sha256(crypto_utils.canonical_json(data).encode()).hexdigest()


def policy_digest(db: Session, org_id: str) -> str:
    """Bind agreements to the current ACTIVE institution policy snapshot."""
    bundles = db.query(models.PolicyBundle).filter_by(org_id=org_id, status="ACTIVE").order_by(
        models.PolicyBundle.policy_name, models.PolicyBundle.version).all()
    return digest_json({"org_id": org_id, "active_policies": [
        {"policy_name": b.policy_name, "version": b.version, "rules": b.rules}
        for b in bundles]})


def _pubkey(db: Session, claims: AgreementClaims) -> tuple[str | None, str]:
    """Return (public_key_material, algorithm) for the signer that must have
    signed the agreement. The algorithm is read from the stored row so PQC
    signers verify under their own algorithm; ed25519 stays the default."""
    if claims.subject_type == "RECEIVER":
        receiver = db.query(models.ReceiverInstitution).filter_by(
            org_id=claims.org_id, receiver_id=claims.subject_id, status="ACTIVE",
            identity_assurance="ADMIN_APPROVED").first()
        if not receiver:
            return None, "ed25519"
        return receiver.public_key_pem, getattr(receiver, "public_key_algorithm", "ed25519") or "ed25519"
    signer = db.query(models.FederationSigner).filter_by(
        org_id=claims.org_id, subject_type=claims.subject_type,
        subject_id=claims.subject_id, status="ACTIVE").first()
    if not signer:
        return None, "ed25519"
    return signer.public_key_pem, getattr(signer, "public_key_algorithm", "ed25519") or "ed25519"


def verify_agreement(db: Session, claims: AgreementClaims, signature: str) -> tuple[bool, str, str, str]:
    """Verify a signed agreement under the signer's stored algorithm.

    Returns (ok, reason, fingerprint, algorithm). The algorithm is the one the
    stored signer row declares, so PQC signatures verify against PQC keys and
    an Ed25519-tagged signer rejects a PQC signature (and vice-versa)."""
    moment = now()
    if claims.issued_at.tzinfo is None or claims.expires_at.tzinfo is None:
        return False, "timestamps must be timezone-aware", ""
    if claims.issued_at > moment + timedelta(minutes=5):
        return False, "agreement issued in the future", ""
    if claims.expires_at <= moment or claims.expires_at <= claims.issued_at:
        return False, "agreement expired or invalid", ""
    if (claims.expires_at - claims.issued_at).days > 366:
        return False, "agreement lifetime exceeds policy maximum", ""
    if claims.policy_digest != policy_digest(db, claims.org_id):
        return False, "institution policy changed or policy digest mismatch", ""
    if claims.subject_type == "SENDER_ORG" and claims.subject_id != claims.org_id:
        return False, "sending organization identity mismatch", ""
    beneficiary = db.query(models.ReceiverBeneficiary).filter_by(
        org_id=claims.org_id, beneficiary_id=claims.beneficiary_id, status="ACTIVE").first()
    if not beneficiary:
        return False, "beneficiary is missing or blocked", ""
    if claims.subject_type == "RECEIVER" and beneficiary.receiver_id != claims.subject_id:
        return False, "receiving institution does not own beneficiary registration", ""
    agent = db.query(models.Agent).filter_by(org_id=claims.org_id, agent_id=claims.agent_id).first()
    if not agent:
        return False, "agent does not belong to organization", ""
    public_key, algorithm = _pubkey(db, claims)
    if not public_key:
        return False, "agreement signer is not enrolled and active", "", algorithm
    try:
        verified = crypto_utils.verify_signature(
            public_key, crypto_utils.canonical_json(claims.model_dump(mode="json")),
            signature, algorithm=algorithm)
        if not verified:
            return False, "agreement signature failed for the signer's stored algorithm", "", algorithm
    except crypto_utils.PQCBackendUnavailable:
        return False, "agreement signature cannot be verified; PQC backend unavailable", "", algorithm
    except (ValueError, TypeError):
        return False, "agreement signature or signer key is invalid", "", algorithm
    return True, "signed policy agreement verified", crypto_utils.public_key_fingerprint(public_key, algorithm=algorithm), algorithm


def evaluate(db: Session, *, org_id: str, agent_id: str, beneficiary_id: str | None,
             amount_minor_units: int, currency: str, purpose: str, user_id: str | None = None) -> tuple[bool, str, list[str]]:
    """Intersect Paari, sender institution, user and receiver evidence.

    Missing/expired/revoked/rekeyed agreements fail closed. Only verified
    user identity matching the live mandate may satisfy USER consent.
    """
    if not beneficiary_id or not purpose.strip() or not user_id:
        return False, "signed beneficiary, nonempty payment purpose and active user mandate are required", []
    beneficiary = db.query(models.ReceiverBeneficiary).filter_by(
        org_id=org_id, beneficiary_id=beneficiary_id, status="ACTIVE").first()
    if not beneficiary:
        return False, "destination beneficiary no longer active", []
    now_ts = now()
    policy_hash = policy_digest(db, org_id)
    matched = []
    for role, expected in (("SENDER_ORG", org_id), ("USER", user_id), ("RECEIVER", beneficiary.receiver_id)):
        candidates = db.query(models.FederationAgreement).filter_by(
            org_id=org_id, agent_id=agent_id, beneficiary_id=beneficiary_id,
            subject_type=role, subject_id=expected, status="ACTIVE").order_by(
            models.FederationAgreement.id.desc()).all()
        accepted = None
        for item in candidates:
            try:
                claims = AgreementClaims.model_validate(item.payload)
                if (claims.expires_at <= now_ts or claims.issued_at > now_ts or
                    claims.max_amount_minor_units < amount_minor_units or
                    claims.currency != currency or claims.purpose != purpose or
                    claims.policy_digest != policy_hash):
                    continue
                ok, _, fingerprint, _algorithm = verify_agreement(db, claims, item.signature_b64)
                if not ok or not hmac.compare_digest(item.signer_fingerprint, fingerprint):
                    continue
                # A USER signature must be backed by the SAME user key as the
                # currently governing cryptographically signed payment mandate.
                # Operator-enrolling an unrelated key cannot silently change
                # the effective user who authorized payment.
                if role == "USER":
                    from app.mandates import active_mandate
                    governing = active_mandate(db, agent_id=agent_id, org_id=org_id)
                    if not governing or governing.user_id != expected or not governing.user_public_key_pem:
                        continue
                    actual = crypto_utils.public_key_fingerprint(governing.user_public_key_pem)
                    if not hmac.compare_digest(actual, fingerprint):
                        continue
                if not hmac.compare_digest(item.payload_digest, digest_json(item.payload)):
                    continue
                accepted = item.agreement_id
                break
            except (ValueError, TypeError):
                continue
        if not accepted:
            return False, f"{role} signed agreement is absent, expired, revoked, or outside payment/policy scope", matched
        matched.append(accepted)
    return True, "Paari, sender, user and receiver signed-policy intersection passed", matched


def require_execution(db: Session, *, authorization: models.BoundedAuthorization) -> None:
    if not enforced():
        return
    intent = db.query(models.PaymentIntent).filter_by(org_id=authorization.org_id,
                                                       intent_id=authorization.intent_id).first()
    if intent is None or intent.beneficiary_id is None or not intent.mandate_id:
        raise HTTPException(403, "Federation revalidation: missing original intent/mandate/receiver")
    mandate = db.query(models.UserPaymentMandate).filter_by(mandate_id=intent.mandate_id).first()
    if mandate is None:
        raise HTTPException(403, "Federation revalidation: original user mandate missing")
    from app.mandates import check_mandate_signature, MandateState, evaluate_mandate
    sig_ok, _ = check_mandate_signature(mandate, require_signed=True)
    if not sig_ok:
        raise HTTPException(403, "Federation revalidation: user payment mandate signature missing or invalid")
    # Re-evaluate the complete mandate intersection, not just one historical row.
    agent = db.query(models.Agent).filter_by(org_id=authorization.org_id, agent_id=authorization.agent_id).first()
    if agent is None:
        raise HTTPException(403, "Federation revalidation: agent no longer registered")
    current = evaluate_mandate(db, agent=agent, merchant=intent.merchant,
        amount_minor_units=authorization.amount_minor_units, currency=authorization.currency,
        merchant_category=intent.merchant_category, now=now(), require_signed=True)
    if current.state is not MandateState.ACTIVE or not current.ok:
        raise HTTPException(403, "Federation revalidation: user mandate is no longer valid")
    ok, reason, _ = evaluate(db, org_id=authorization.org_id, agent_id=authorization.agent_id,
                             beneficiary_id=intent.beneficiary_id, amount_minor_units=authorization.amount_minor_units,
                             currency=authorization.currency, purpose=intent.purpose,
                             user_id=mandate.user_id)
    if not ok:
        raise HTTPException(403, "Federation revalidation failed: " + reason)
    context = db.query(models.PaymentContextEnvelope).filter_by(org_id=intent.org_id, intent_id=intent.intent_id).first()
    if not context or not verify_context(context, intent):
        raise HTTPException(403, "Payment context signature or immutable payment bounds are invalid")


def seal_context(db: Session, intent: models.PaymentIntent, agent: models.Agent) -> models.PaymentContextEnvelope:
    """Create signed evidence of what the server ACTUALLY decided, no authority granted."""
    p = {
        "type": "paari.payment-context.v1", "intent_id": intent.intent_id,
        "transaction_id": intent.transaction_id, "org_id": intent.org_id,
        "agent_id": agent.agent_id,
        "agent_public_key_fingerprint": crypto_utils.public_key_fingerprint(agent.public_key_pem),
        "parent_id": agent.parent.parent_id if agent.parent else None, "mandate_id": intent.mandate_id,
        "beneficiary_id": intent.beneficiary_id, "merchant": intent.merchant,
        "amount_minor_units": int(intent.amount_minor_units), "currency": intent.currency,
        "action": intent.action, "purpose": intent.purpose,
        "policy_digest": policy_digest(db, intent.org_id),
        "decision": intent.decision.value if hasattr(intent.decision, "value") else str(intent.decision),
        "issued_at": now().isoformat(),
        "execution_authority": False,
        "data_disclosure": "minimal identifiers only; no customer bank details or LLM conversation",
    }
    row = models.PaymentContextEnvelope(org_id=intent.org_id, intent_id=intent.intent_id,
         payload=p, payload_digest=digest_json(p), signature_b64=security.sign_agent_card(p),
         signature_algorithm=getattr(security._signing_backend, "algorithm", "ed25519"),
         issuer_key_id=security.signing_backend_status()["key_id"])
    db.add(row)
    db.flush()
    return row


def verify_context(row: models.PaymentContextEnvelope, intent: models.PaymentIntent) -> bool:
    p = row.payload
    expected = {"intent_id":intent.intent_id,"transaction_id":intent.transaction_id,
                "org_id":intent.org_id,"agent_id":intent.agent_id,"mandate_id":intent.mandate_id,
                "beneficiary_id":intent.beneficiary_id,"merchant":intent.merchant,
                "amount_minor_units":intent.amount_minor_units,"currency":intent.currency,
                "action":intent.action,"purpose":intent.purpose}
    return (all(p.get(k) == v for k, v in expected.items()) and
            p.get("execution_authority") is False and
            hmac.compare_digest(row.payload_digest, digest_json(p)) and
            security.verify_agent_card(p, row.signature_b64,
                                       algorithm=getattr(row, "signature_algorithm", "ed25519") or "ed25519"))
