"""Admin-gated Setu AA sandbox endpoints.

Setu AA financial data is consented context only. These endpoints never initiate
payments and do not treat account data as payment authority.
"""
from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, RootModel
from sqlalchemy.orm import Session

from app.control_plane.router import _tenant
from app.database import get_db
from app.integrations.setu import service
from app.integrations.setu.client import SetuAAClient, SetuAAConfigError, SetuAAUpstreamError


router = APIRouter(prefix="/integrations/setu-aa", tags=["Setu Account Aggregator sandbox"])


def _enabled() -> bool:
    return os.getenv("SETU_AA_ENABLED", "false").lower() in {"1", "true", "yes"}


def _admin(key: str | None) -> None:
    expected = os.getenv("PAARI_ADMIN_API_KEY", "")
    if not expected or not key or not hmac.compare_digest(key, expected):
        raise HTTPException(401, "Admin authentication required")


def _client() -> SetuAAClient:
    if not _enabled():
        raise HTTPException(503, "Setu AA integration disabled")
    try:
        return SetuAAClient()
    except SetuAAConfigError as exc:
        raise HTTPException(503, str(exc)) from exc


def _call(operation):
    try:
        return operation()
    except SetuAAUpstreamError as exc:
        raise HTTPException(502, "Setu AA sandbox request failed") from exc


class MobileNumberRequest(BaseModel):
    mobile_number: str = Field(min_length=10, max_length=15)


class ConsentRequest(RootModel[dict[str, Any]]):
    pass


class DataSessionRequest(BaseModel):
    consent_id: str = Field(min_length=1, max_length=200)
    data_range: dict[str, str]
    data_format: str = Field(default="json", pattern="^(json|xml)$")


class LifecycleConsentRequest(BaseModel):
    subject_user_id: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=500)
    consent: dict[str, Any]


class LifecycleDataSessionRequest(BaseModel):
    setu_consent_id: str = Field(min_length=1, max_length=64)
    data_range: dict[str, str]
    data_format: str = Field(default="json", pattern="^(json|xml)$")


class ConsentMandateBindingRequest(BaseModel):
    mandate_id: str = Field(min_length=1, max_length=64)


@router.get("/status")
def status():
    return {
        "enabled": _enabled(),
        "credentials_configured": all(
            os.getenv(name)
            for name in ("SETU_AA_CLIENT_ID", "SETU_AA_CLIENT_SECRET", "SETU_AA_PRODUCT_INSTANCE_ID")
        ),
        "mode": os.getenv("SETU_AA_ENV", "sandbox"),
    }


@router.post("/account-availability")
def account_availability(body: MobileNumberRequest, x_paari_admin_key: str | None = Header(None)):
    _admin(x_paari_admin_key)
    return _call(lambda: _client().account_availability(body.mobile_number))


@router.post("/consents")
def create_consent(body: ConsentRequest, x_paari_admin_key: str | None = Header(None)):
    _admin(x_paari_admin_key)
    return _call(lambda: _client().create_consent(body.root))


@router.get("/consents/{consent_id}")
def get_consent(consent_id: str, x_paari_admin_key: str | None = Header(None)):
    _admin(x_paari_admin_key)
    return _call(lambda: _client().get_consent(consent_id))


@router.post("/consents/{consent_id}/revoke")
def revoke_consent(consent_id: str, x_paari_admin_key: str | None = Header(None)):
    _admin(x_paari_admin_key)
    return _call(lambda: _client().revoke_consent(consent_id))


@router.post("/sessions")
def create_data_session(body: DataSessionRequest, x_paari_admin_key: str | None = Header(None)):
    _admin(x_paari_admin_key)
    return _call(lambda: _client().create_data_session(body.consent_id, body.data_range, body.data_format))


@router.get("/sessions/{session_id}")
def get_data_session(session_id: str, x_paari_admin_key: str | None = Header(None)):
    _admin(x_paari_admin_key)
    return _call(lambda: _client().get_data_session(session_id))


# Additive tenant lifecycle API. The legacy sandbox proxy routes above remain
# intentionally unchanged for compatibility; they never gain persistence.
@router.post("/v1/consents", status_code=201)
def create_lifecycle_consent(
    body: LifecycleConsentRequest,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return _call(lambda: service.create_consent(
        db,
        client=_client(),
        org_id=org_id,
        subject_user_id=body.subject_user_id,
        purpose=body.purpose,
        provider_request=body.consent,
    ))


@router.post("/v1/consents/{setu_consent_id}/refresh")
def refresh_lifecycle_consent(
    setu_consent_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return _call(lambda: service.refresh_consent(
        db, client=_client(), org_id=org_id, setu_consent_id=setu_consent_id
    ))


@router.post("/v1/consents/{setu_consent_id}/revoke")
def revoke_lifecycle_consent(
    setu_consent_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return _call(lambda: service.revoke_consent(
        db, client=_client(), org_id=org_id, setu_consent_id=setu_consent_id
    ))


@router.post("/v1/sessions", status_code=201)
def create_lifecycle_data_session(
    body: LifecycleDataSessionRequest,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return _call(lambda: service.create_data_session(
        db,
        client=_client(),
        org_id=org_id,
        setu_consent_id=body.setu_consent_id,
        data_range=body.data_range,
        data_format=body.data_format,
    ))


@router.get("/v1/sessions/{data_session_id}")
def refresh_lifecycle_data_session(
    data_session_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return _call(lambda: service.refresh_data_session(
        db, client=_client(), org_id=org_id, data_session_id=data_session_id
    ))


@router.post("/v1/consents/{setu_consent_id}/mandate-binding", status_code=201)
def bind_lifecycle_consent_to_mandate(
    setu_consent_id: str,
    body: ConsentMandateBindingRequest,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    """Bind consented financial context to one active, same-user payment mandate."""
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return service.create_consent_mandate_binding(
        db, org_id=org_id, setu_consent_id=setu_consent_id, mandate_id=body.mandate_id
    )


@router.post("/v1/bindings/{binding_id}/revoke")
def revoke_lifecycle_binding(
    binding_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org)
    return service.revoke_consent_mandate_binding(db, org_id=org_id, binding_id=binding_id)


@router.get("/v1/mandates/{mandate_id}/financial-context")
def get_mandate_financial_context(
    mandate_id: str,
    x_paari_control_key: str = Header(default=""),
    x_paari_org: str = Header(default=""),
    db: Session = Depends(get_db),
):
    org_id = _tenant(db, x_paari_control_key, x_paari_org, required_scope="control:read")
    return service.get_mandate_financial_context(db, org_id=org_id, mandate_id=mandate_id)
