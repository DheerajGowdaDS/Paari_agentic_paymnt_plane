"""Tenant-bound Setu AA consent and data-session lifecycle operations."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.exc import IntegrityError

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app import models
from app.audit import record_audit
from app.integrations.setu.client import SetuAAClient, SetuAAUpstreamError


_CONSENT_STATUSES = {"PENDING", "ACTIVE", "REVOKED", "EXPIRED", "FAILED"}
_SESSION_STATUSES = {"PENDING", "PARTIAL", "COMPLETED", "FAILED", "REVOKED"}
_SNAPSHOT_STATUSES = {"AVAILABLE", "PARTIAL", "REVOKED", "FAILED"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _context_key() -> bytes:
    # A dedicated secret is preferred. The v3.7 data-encryption secret remains
    # a sandbox-only migration fallback so existing local environments can
    # exercise the lifecycle without silently falling back to plaintext.
    secret = (os.getenv("PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET")
              or os.getenv("PAARI_V37_DATA_ENCRYPTION_SECRET", "")).strip()
    if len(secret) < 32:
        raise HTTPException(503, "Financial-context encryption is not configured; set PAARI_FINANCIAL_CONTEXT_ENCRYPTION_SECRET")
    return hashlib.sha256(("paari-setu-financial-context-v1:" + secret).encode("utf-8")).digest()


def _encrypt_payload(payload: dict, *, aad: str) -> str:
    try:
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HTTPException(502, "Setu financial data is not valid JSON") from exc
    nonce = os.urandom(12)
    ciphertext = AESGCM(_context_key()).encrypt(nonce, plaintext, aad.encode("utf-8"))
    return "aesgcm:v1:" + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def _provider_datetime(payload: Any, *keys: str) -> datetime | None:
    value = _provider_value(payload, *keys)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _context_source_freshness(normalized: dict[str, Any]) -> datetime | None:
    """Use the oldest source balance timestamp; retrieval time is not freshness."""
    accounts = normalized.get("accounts", []) if isinstance(normalized, dict) else []
    timestamps: list[datetime] = []
    for account in accounts if isinstance(accounts, list) else []:
        if not isinstance(account, dict) or not isinstance(account.get("balance_timestamp"), str):
            return None
        value = account["balance_timestamp"]
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        timestamps.append(parsed.astimezone(timezone.utc))
    return min(timestamps) if timestamps else None


def _provider_value(payload: Any, *keys: str) -> str | None:
    if not isinstance(payload, dict):
        return None
    containers = [payload]
    data = payload.get("data")
    if isinstance(data, dict):
        containers.append(data)
        nested = data.get("data")
        if isinstance(nested, dict):
            containers.append(nested)
    for container in containers:
        for key in keys:
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _provider_status(payload: Any, *, allowed: set[str], fallback: str) -> str:
    status = _provider_value(payload, "status", "state")
    if status:
        normalized = status.upper()
        if normalized in allowed:
            return normalized
    return fallback


def _parse_date_range(data_range: dict[str, str]) -> None:
    if set(data_range) != {"from", "to"}:
        raise HTTPException(422, "data_range must contain only from and to")
    try:
        start = datetime.fromisoformat(data_range["from"])
        end = datetime.fromisoformat(data_range["to"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "data_range values must be ISO-8601 dates") from exc
    if start > end:
        raise HTTPException(422, "data_range from must not be later than to")


def _consent_view(consent: models.SetuConsent) -> dict[str, Any]:
    return {
        "setu_consent_id": consent.setu_consent_id,
        "org_id": consent.org_id,
        "subject_user_id": consent.subject_user_id,
        "provider_consent_id": consent.provider_consent_id,
        "status": consent.status,
        "consent_expires_at": consent.consent_expires_at,
        "created_at": consent.created_at,
        "updated_at": consent.updated_at,
    }


def _session_view(session: models.SetuDataSession) -> dict[str, Any]:
    return {
        "data_session_id": session.data_session_id,
        "org_id": session.org_id,
        "setu_consent_id": session.setu_consent_id,
        "provider_session_id": session.provider_session_id,
        "status": session.status,
        "created_at": session.created_at,
        "updated_at": session.updated_at,
    }


def _consent_for_org(db: Session, *, org_id: str, setu_consent_id: str) -> models.SetuConsent:
    consent = db.query(models.SetuConsent).filter_by(
        org_id=org_id, setu_consent_id=setu_consent_id
    ).with_for_update().first()
    if consent is None:
        raise HTTPException(404, "Setu consent not found")
    return consent


def _session_for_org(db: Session, *, org_id: str, data_session_id: str) -> models.SetuDataSession:
    session = db.query(models.SetuDataSession).filter_by(
        org_id=org_id, data_session_id=data_session_id
    ).with_for_update().first()
    if session is None:
        raise HTTPException(404, "Setu data session not found")
    return session


def _record_transition(db: Session, *, org_id: str, kind: str, target: str, detail: dict[str, Any]) -> None:
    record_audit(
        db,
        transaction_id=f"setu:{target}",
        agent_id="",
        parent_id=None,
        kind=kind,
        org_id=org_id,
        detail=detail,
    )


def create_consent(
    db: Session,
    *,
    client: SetuAAClient,
    org_id: str,
    subject_user_id: str,
    purpose: str,
    provider_request: dict[str, Any],
) -> dict[str, Any]:
    payload = client.create_consent(provider_request)
    provider_consent_id = _provider_value(payload, "id", "consentId")
    if not provider_consent_id:
        raise HTTPException(502, "Setu AA consent response did not contain a consent identifier")

    consent = models.SetuConsent(
        org_id=org_id,
        subject_user_id=subject_user_id,
        provider_consent_id=provider_consent_id,
        status=_provider_status(payload, allowed=_CONSENT_STATUSES, fallback="PENDING"),
        purpose_digest=_digest(purpose),
        consent_expires_at=_provider_datetime(payload, "expiresAt", "expiryDateTime", "consentExpiry"),
    )
    db.add(consent)
    db.flush()
    _record_transition(
        db,
        org_id=org_id,
        kind="setu_consent_created",
        target=consent.setu_consent_id,
        detail={
            "setu_consent_id": consent.setu_consent_id,
            "provider_consent_id_digest": _digest(provider_consent_id),
            "status": consent.status,
        },
    )
    db.commit()
    db.refresh(consent)
    return _consent_view(consent)


def refresh_consent(
    db: Session, *, client: SetuAAClient, org_id: str, setu_consent_id: str
) -> dict[str, Any]:
    consent = _consent_for_org(db, org_id=org_id, setu_consent_id=setu_consent_id)
    payload = client.get_consent(consent.provider_consent_id)
    provider_consent_id = _provider_value(payload, "id", "consentId")
    if provider_consent_id and provider_consent_id != consent.provider_consent_id:
        raise HTTPException(502, "Setu AA consent response did not match the requested consent")
    previous_status = consent.status
    consent.status = _provider_status(payload, allowed=_CONSENT_STATUSES, fallback=previous_status)
    consent.consent_expires_at = _provider_datetime(payload, "expiresAt", "expiryDateTime", "consentExpiry") or consent.consent_expires_at
    consent.updated_at = _now()
    _record_transition(
        db,
        org_id=org_id,
        kind="setu_consent_polled",
        target=consent.setu_consent_id,
        detail={
            "setu_consent_id": consent.setu_consent_id,
            "previous_status": previous_status,
            "status": consent.status,
        },
    )
    db.commit()
    db.refresh(consent)
    return _consent_view(consent)


def revoke_consent(
    db: Session, *, client: SetuAAClient, org_id: str, setu_consent_id: str
) -> dict[str, Any]:
    consent = _consent_for_org(db, org_id=org_id, setu_consent_id=setu_consent_id)
    # Commit local revocation BEFORE making a network call. Even if Setu times
    # out, Paari immediately blocks this consent, every binding, and every
    # snapshot. Provider-side revocation is a separate retryable operation.
    previous_status = consent.status
    consent.status = "REVOKED"
    consent.updated_at = _now()
    db.query(models.SetuConsentMandateBinding).filter_by(
        org_id=org_id, setu_consent_id=consent.setu_consent_id, status="ACTIVE"
    ).update({"status": "REVOKED", "revoked_at": _now()}, synchronize_session=False)
    db.query(models.FinancialContextSnapshot).filter_by(
        org_id=org_id, setu_consent_id=consent.setu_consent_id
    ).filter(models.FinancialContextSnapshot.status != "REVOKED").update(
        {"status": "REVOKED"}, synchronize_session=False
    )
    _record_transition(
        db, org_id=org_id, kind="setu_consent_revoked", target=consent.setu_consent_id,
        detail={
            "setu_consent_id": consent.setu_consent_id,
            "previous_status": previous_status,
            "status": "REVOKED",
            "local_access_blocked": True,
        },
    )
    db.commit()
    db.refresh(consent)

    provider_revocation_confirmed = False
    try:
        provider_response = client.revoke_consent(consent.provider_consent_id)
        provider_revocation_confirmed = not (
            isinstance(provider_response, dict) and provider_response.get("success") is False
        )
    except SetuAAUpstreamError:
        provider_revocation_confirmed = False
    _record_transition(
        db, org_id=org_id, kind="setu_provider_revocation_result",
        target=consent.setu_consent_id, detail={
            "setu_consent_id": consent.setu_consent_id,
            "provider_revocation_confirmed": provider_revocation_confirmed,
            "provider_revocation_pending": not provider_revocation_confirmed,
            "local_access_blocked": True,
        },
    )
    db.commit()
    db.refresh(consent)
    return {**_consent_view(consent),
            "provider_revocation_confirmed": provider_revocation_confirmed,
            "provider_revocation_pending": not provider_revocation_confirmed}


def _require_active_binding(db: Session, *, consent: models.SetuConsent) -> None:
    binding = db.query(models.SetuConsentMandateBinding).filter_by(
        org_id=consent.org_id,
        setu_consent_id=consent.setu_consent_id,
        subject_user_id=consent.subject_user_id,
        status="ACTIVE",
    ).first()
    if binding is None:
        raise HTTPException(403, "An active consent binding for this organization and user is required")

    mandate = db.query(models.UserPaymentMandate).filter_by(
        mandate_id=binding.mandate_id,
        org_id=consent.org_id,
        user_id=consent.subject_user_id,
        status=models.MandateStatus.ACTIVE,
    ).first()
    now = _now()
    if mandate is None or mandate.valid_from > now or mandate.expires_at <= now:
        raise HTTPException(403, "An active consent binding for this organization and user is required")
    if os.getenv("SETU_AA_REQUIRE_SIGNED_MANDATE", "1").strip().lower() in {"1", "true", "yes"}:
        from app.mandate_signing import verify_mandate_signature
        if not verify_mandate_signature(mandate).signature_valid:
            raise HTTPException(403, "Setu financial context requires a cryptographically signed user mandate")


def _binding_view(binding: models.SetuConsentMandateBinding) -> dict[str, Any]:
    return {
        "binding_id": binding.binding_id,
        "org_id": binding.org_id,
        "setu_consent_id": binding.setu_consent_id,
        "mandate_id": binding.mandate_id,
        "subject_user_id": binding.subject_user_id,
        "status": binding.status,
        "created_at": binding.created_at,
        "revoked_at": binding.revoked_at,
    }


def create_consent_mandate_binding(
    db: Session, *, org_id: str, setu_consent_id: str, mandate_id: str
) -> dict[str, Any]:
    consent = _consent_for_org(db, org_id=org_id, setu_consent_id=setu_consent_id)
    if consent.status != "ACTIVE":
        raise HTTPException(409, "Only an ACTIVE Setu consent can be bound to a payment mandate")
    if consent.consent_expires_at and consent.consent_expires_at <= _now():
        consent.status = "EXPIRED"
        consent.updated_at = _now()
        db.commit()
        raise HTTPException(409, "Setu consent has expired")
    mandate = db.query(models.UserPaymentMandate).filter_by(
        org_id=org_id, mandate_id=mandate_id, user_id=consent.subject_user_id
    ).with_for_update().first()
    now = _now()
    if (mandate is None or mandate.status != models.MandateStatus.ACTIVE
            or mandate.valid_from > now or mandate.expires_at <= now):
        raise HTTPException(403, "An active mandate for the same organization and consent subject is required")
    from app.mandate_signing import verify_mandate_signature
    signature = verify_mandate_signature(mandate)
    require_signed = os.getenv("SETU_AA_REQUIRE_SIGNED_MANDATE", "1").strip().lower() in {"1", "true", "yes"}
    if require_signed and not signature.signature_valid:
        raise HTTPException(403, "Setu financial context requires a cryptographically signed user mandate")
    existing = db.query(models.SetuConsentMandateBinding).filter_by(
        org_id=org_id, setu_consent_id=consent.setu_consent_id, mandate_id=mandate.mandate_id
    ).first()
    if existing:
        if existing.status == "ACTIVE":
            return _binding_view(existing)
        raise HTTPException(409, "A revoked Setu consent-to-mandate binding cannot be reactivated; create a new consent")
    binding = models.SetuConsentMandateBinding(
        org_id=org_id, setu_consent_id=consent.setu_consent_id,
        mandate_id=mandate.mandate_id, subject_user_id=consent.subject_user_id,
        purpose_digest=consent.purpose_digest, status="ACTIVE",
    )
    db.add(binding)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Setu consent-to-mandate binding already exists") from exc
    _record_transition(db, org_id=org_id, kind="setu_consent_mandate_bound",
        target=binding.binding_id, detail={
            "binding_id": binding.binding_id, "setu_consent_id": consent.setu_consent_id,
            "mandate_id": mandate.mandate_id, "subject_user_id_digest": _digest(consent.subject_user_id),
            "purpose_digest": consent.purpose_digest, "mandate_signature_verified": signature.signature_valid,
        })
    db.commit()
    db.refresh(binding)
    return _binding_view(binding)


def revoke_consent_mandate_binding(
    db: Session, *, org_id: str, binding_id: str
) -> dict[str, Any]:
    binding = db.query(models.SetuConsentMandateBinding).filter_by(
        org_id=org_id, binding_id=binding_id
    ).with_for_update().first()
    if binding is None:
        raise HTTPException(404, "Setu consent-to-mandate binding not found")
    if binding.status == "ACTIVE":
        binding.status = "REVOKED"
        binding.revoked_at = _now()
        remaining = db.query(models.SetuConsentMandateBinding).filter_by(
            org_id=org_id, setu_consent_id=binding.setu_consent_id, status="ACTIVE"
        ).count()
        if remaining == 0:
            db.query(models.FinancialContextSnapshot).filter_by(
                org_id=org_id, setu_consent_id=binding.setu_consent_id
            ).filter(models.FinancialContextSnapshot.status != "REVOKED").update(
                {"status": "REVOKED"}, synchronize_session=False
            )
        _record_transition(db, org_id=org_id, kind="setu_consent_mandate_binding_revoked",
            target=binding.binding_id, detail={
                "binding_id": binding.binding_id, "setu_consent_id": binding.setu_consent_id,
                "mandate_id": binding.mandate_id, "status": "REVOKED",
            })
        db.commit()
        db.refresh(binding)
    return _binding_view(binding)


def create_data_session(
    db: Session,
    *,
    client: SetuAAClient,
    org_id: str,
    setu_consent_id: str,
    data_range: dict[str, str],
    data_format: str,
) -> dict[str, Any]:
    _parse_date_range(data_range)
    consent = _consent_for_org(db, org_id=org_id, setu_consent_id=setu_consent_id)
    if consent.status != "ACTIVE":
        raise HTTPException(409, "Setu consent must be ACTIVE before creating a data session")
    _require_active_binding(db, consent=consent)

    payload = client.create_data_session(consent.provider_consent_id, data_range, data_format)
    provider_session_id = _provider_value(payload, "id", "sessionId")
    if not provider_session_id:
        raise HTTPException(502, "Setu AA session response did not contain a session identifier")
    session = models.SetuDataSession(
        org_id=org_id,
        setu_consent_id=consent.setu_consent_id,
        provider_session_id=provider_session_id,
        status=_provider_status(payload, allowed=_SESSION_STATUSES, fallback="PENDING"),
    )
    db.add(session)
    db.flush()
    _record_transition(
        db,
        org_id=org_id,
        kind="setu_data_session_created",
        target=session.data_session_id,
        detail={
            "data_session_id": session.data_session_id,
            "setu_consent_id": consent.setu_consent_id,
            "provider_session_id_digest": _digest(provider_session_id),
            "status": session.status,
        },
    )
    db.commit()
    db.refresh(session)
    return _session_view(session)


def refresh_data_session(
    db: Session, *, client: SetuAAClient, org_id: str, data_session_id: str
) -> dict[str, Any]:
    session = _session_for_org(db, org_id=org_id, data_session_id=data_session_id)
    consent = _consent_for_org(db, org_id=org_id, setu_consent_id=session.setu_consent_id)
    if consent.status != "ACTIVE":
        raise HTTPException(403, "Setu consent is no longer active; financial context retrieval is blocked")
    _require_active_binding(db, consent=consent)
    payload = client.get_data_session(session.provider_session_id)
    provider_session_id = _provider_value(payload, "id", "sessionId")
    if provider_session_id and provider_session_id != session.provider_session_id:
        raise HTTPException(502, "Setu AA session response did not match the requested session")
    provider_consent_id = _provider_value(payload, "consentId", "consent_id")
    if provider_consent_id and provider_consent_id != consent.provider_consent_id:
        raise HTTPException(502, "Setu AA data response was not bound to the stored consent")
    previous_status = session.status
    session.status = _provider_status(payload, allowed=_SESSION_STATUSES, fallback=previous_status)
    session.updated_at = _now()
    snapshot_view = None
    if session.status in {"COMPLETED", "PARTIAL"}:
        from app.financial_context.normalizer import normalize_setu_data_session
        normalized = normalize_setu_data_session(payload)
        normalized_accounts = normalized.get("accounts", [])
        if not isinstance(normalized_accounts, list):
            normalized_accounts = []
        completeness = "COMPLETE" if normalized_accounts and all(
            isinstance(account, dict) and account.get("currency")
            and account.get("balance") is not None and account.get("balance_timestamp")
            for account in normalized_accounts
        ) else ("PARTIAL" if normalized_accounts else "EMPTY")
        source_freshness_at = _context_source_freshness(normalized)
        # A provider-partial session, incomplete account summary or missing
        # source timestamp cannot satisfy the strict freshness requirement.
        snapshot_status = ("AVAILABLE" if session.status == "COMPLETED"
                           and completeness == "COMPLETE" and source_freshness_at is not None
                           else "PARTIAL")
        snapshot = db.query(models.FinancialContextSnapshot).filter_by(
            org_id=org_id, data_session_id=session.data_session_id
        ).order_by(models.FinancialContextSnapshot.created_at.desc()).first()
        aad = f"{org_id}|{consent.setu_consent_id}|{session.data_session_id}"
        encrypted = _encrypt_payload(payload if isinstance(payload, dict) else {"payload": payload}, aad=aad)
        if snapshot is None:
            snapshot = models.FinancialContextSnapshot(
                org_id=org_id, setu_consent_id=consent.setu_consent_id,
                data_session_id=session.data_session_id, status=snapshot_status,
                raw_payload_ciphertext=encrypted, raw_payload_digest=_digest(json.dumps(payload, sort_keys=True, default=str)),
                normalized_context=normalized, normalized_context_version="1.0",
                source_freshness_at=source_freshness_at, completeness=completeness,
            )
            db.add(snapshot)
        else:
            snapshot.status = snapshot_status
            snapshot.raw_payload_ciphertext = encrypted
            snapshot.raw_payload_digest = _digest(json.dumps(payload, sort_keys=True, default=str))
            snapshot.normalized_context = normalized
            snapshot.source_freshness_at = source_freshness_at
            snapshot.completeness = completeness
        db.flush()
        snapshot_view = _snapshot_view(snapshot)
        _record_transition(db, org_id=org_id, kind="setu_financial_context_snapshot_created",
            target=snapshot.snapshot_id, detail={
                "snapshot_id": snapshot.snapshot_id, "setu_consent_id": consent.setu_consent_id,
                "data_session_id": session.data_session_id, "status": snapshot.status,
                "completeness": snapshot.completeness, "account_count": len(normalized_accounts),
                "raw_payload_digest": snapshot.raw_payload_digest,
            })
    _record_transition(
        db, org_id=org_id, kind="setu_data_session_polled", target=session.data_session_id,
        detail={
            "data_session_id": session.data_session_id, "previous_status": previous_status,
            "status": session.status, "financial_context_persisted": snapshot_view is not None,
        },
    )
    db.commit()
    db.refresh(session)
    return {**_session_view(session), "financial_context": snapshot_view}


def _snapshot_view(snapshot: models.FinancialContextSnapshot) -> dict[str, Any]:
    context = snapshot.normalized_context if isinstance(snapshot.normalized_context, dict) else {}
    return {
        "snapshot_id": snapshot.snapshot_id,
        "org_id": snapshot.org_id,
        "setu_consent_id": snapshot.setu_consent_id,
        "data_session_id": snapshot.data_session_id,
        "status": snapshot.status,
        "completeness": snapshot.completeness,
        "source_freshness_at": snapshot.source_freshness_at,
        "normalized_context_version": snapshot.normalized_context_version,
        "account_count": len(context.get("accounts", [])) if isinstance(context.get("accounts"), list) else 0,
        "normalized_context": context,
        "raw_payload_encrypted": bool(snapshot.raw_payload_ciphertext),
        "raw_payload_digest": snapshot.raw_payload_digest,
        "created_at": snapshot.created_at,
    }


def get_mandate_financial_context(
    db: Session, *, org_id: str, mandate_id: str
) -> dict[str, Any]:
    binding = db.query(models.SetuConsentMandateBinding).filter_by(
        org_id=org_id, mandate_id=mandate_id, status="ACTIVE"
    ).order_by(models.SetuConsentMandateBinding.created_at.desc()).first()
    if binding is None:
        raise HTTPException(404, "No active Setu financial-context binding exists for this mandate")
    consent = db.query(models.SetuConsent).filter_by(
        org_id=org_id, setu_consent_id=binding.setu_consent_id, status="ACTIVE"
    ).first()
    if consent is None or (consent.consent_expires_at and consent.consent_expires_at <= _now()):
        raise HTTPException(409, "Setu consent is no longer active")
    snapshot = db.query(models.FinancialContextSnapshot).filter_by(
        org_id=org_id, setu_consent_id=consent.setu_consent_id, status="AVAILABLE"
    ).order_by(models.FinancialContextSnapshot.source_freshness_at.desc()).first()
    if snapshot is None:
        raise HTTPException(404, "No completed Setu financial-context snapshot is available")
    _require_active_binding(db, consent=consent)
    return _snapshot_view(snapshot)
