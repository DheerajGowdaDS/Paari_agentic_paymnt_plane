"""Runtime loader and trust policy for institution-configured identity adapters.

A module path alone is not trusted. Operators must explicitly pin approved
provider IDs, the adapter must implement the typed contract, and its healthcheck
must pass. The bundled sandbox provider can never establish legal identity.
"""
from __future__ import annotations

import importlib
import os
from datetime import datetime, timezone
from typing import Any

from app.identity_providers.contracts import (
    IdentityVerificationProvider,
    SandboxIdentityVerificationProvider,
    VerificationKind,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
    subject_reference_digest,
)


class IdentityProviderError(RuntimeError):
    """Identity adapter is absent, untrusted, unhealthy, or contract-invalid."""


def _trusted_provider_ids() -> set[str]:
    return {item.strip() for item in os.environ.get("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS", "").split(",") if item.strip()}


def _load_factory(spec: str):
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name.strip() or not attribute.strip():
        raise IdentityProviderError("PAARI_IDENTITY_PROVIDER_ADAPTER must be module.path:factory_name")
    try:
        module = importlib.import_module(module_name.strip())
        factory = getattr(module, attribute.strip())
    except Exception as exc:
        raise IdentityProviderError("Unable to load configured identity-provider adapter") from exc
    if not callable(factory):
        raise IdentityProviderError("Configured identity-provider factory is not callable")
    return factory


def load_identity_provider() -> IdentityVerificationProvider:
    spec = os.environ.get("PAARI_IDENTITY_PROVIDER_ADAPTER", "").strip()
    if not spec:
        raise IdentityProviderError("No identity-provider adapter is configured")
    factory = _load_factory(spec)
    try:
        provider = factory()
    except Exception as exc:
        raise IdentityProviderError("Identity-provider adapter initialization failed") from exc
    if isinstance(provider, SandboxIdentityVerificationProvider):
        raise IdentityProviderError("The synthetic sandbox identity provider cannot be used as a trusted provider")
    for method in ("verify", "get_status", "healthcheck"):
        if not callable(getattr(provider, method, None)):
            raise IdentityProviderError(f"Identity-provider adapter is missing required method: {method}")
    provider_id = str(getattr(provider, "provider_id", "")).strip()
    if not provider_id:
        raise IdentityProviderError("Identity-provider adapter must declare provider_id")
    if provider_id not in _trusted_provider_ids():
        raise IdentityProviderError("Identity-provider ID is not included in PAARI_TRUSTED_IDENTITY_PROVIDER_IDS")
    return provider


def identity_provider_status() -> dict[str, Any]:
    spec = os.environ.get("PAARI_IDENTITY_PROVIDER_ADAPTER", "").strip()
    pinned = sorted(_trusted_provider_ids())
    if not spec:
        return {"provider": None, "configured": False, "trusted_evidence": False,
                "healthy": False, "status": "not_configured", "trusted_provider_ids": pinned}
    try:
        factory = _load_factory(spec)
        provider = factory()
        if isinstance(provider, SandboxIdentityVerificationProvider):
            return {"provider": getattr(provider, "provider_id", None), "configured": True,
                    "trusted_evidence": False, "healthy": bool(provider.healthcheck()),
                    "status": "synthetic_provider_forbidden", "trusted_provider_ids": pinned}
        provider_id = str(getattr(provider, "provider_id", "")).strip()
        methods_ok = all(callable(getattr(provider, method, None)) for method in ("verify", "get_status", "healthcheck"))
        healthy = bool(methods_ok and provider.healthcheck())
        trusted = bool(provider_id and provider_id in _trusted_provider_ids() and methods_ok)
        status = "ready" if trusted and healthy else "not_trusted_or_unhealthy"
        return {"provider": provider_id or None, "configured": bool(methods_ok),
                "trusted_evidence": trusted and healthy, "healthy": healthy,
                "status": status, "trusted_provider_ids": pinned}
    except Exception as exc:
        # Health endpoints should describe blockers without exposing exception
        # details, provider responses, tokens or identity evidence.
        return {"provider": None, "configured": False, "trusted_evidence": False,
                "healthy": False, "status": "adapter_unavailable", "trusted_provider_ids": pinned}


def require_identity_provider() -> IdentityVerificationProvider:
    provider = load_identity_provider()
    try:
        healthy = bool(provider.healthcheck())
    except Exception as exc:
        raise IdentityProviderError("Identity-provider healthcheck failed") from exc
    if not healthy:
        raise IdentityProviderError("Identity-provider healthcheck failed")
    return provider


def validate_verification_result(
    result: VerificationResult,
    *,
    provider_id: str,
    organization_id: str,
    subject_reference: str,
    kind: VerificationKind,
    jurisdiction: str,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Validate evidence-to-request binding. Never elevate on status alone."""
    now = now or datetime.now(timezone.utc)
    expected_digest = subject_reference_digest(organization_id, subject_reference)
    if result.provider_id != provider_id:
        return False, "IDENTITY_PROVIDER_ID_MISMATCH"
    if result.provider_case_reference.strip() == "":
        return False, "IDENTITY_CASE_REFERENCE_MISSING"
    if result.jurisdiction != jurisdiction:
        return False, "IDENTITY_JURISDICTION_MISMATCH"
    if result.subject_reference_digest != expected_digest:
        return False, "IDENTITY_SUBJECT_BINDING_MISMATCH"
    if result.verification_kind is not kind:
        return False, "IDENTITY_VERIFICATION_KIND_MISMATCH"
    if result.status is not VerificationStatus.VERIFIED:
        return False, f"IDENTITY_STATUS_{result.status.value}"
    if result.assurance_level not in {"substantial", "high"}:
        return False, "IDENTITY_ASSURANCE_INSUFFICIENT"
    if not result.evidence_digest or len(result.evidence_digest) != 64:
        return False, "IDENTITY_EVIDENCE_DIGEST_INVALID"
    if not result.evidence_retrieved_at or result.evidence_retrieved_at.tzinfo is None:
        return False, "IDENTITY_RETRIEVAL_TIMESTAMP_INVALID"
    if result.evidence_retrieved_at > now:
        return False, "IDENTITY_EVIDENCE_FROM_FUTURE"
    if result.expires_at is None or result.expires_at <= now:
        return False, "IDENTITY_EVIDENCE_EXPIRED_OR_NO_EXPIRY"
    return True, "IDENTITY_EVIDENCE_VERIFIED"


def verify_current_principal(principal, *, now: datetime | None = None) -> tuple[bool, str]:
    """Refresh provider case state before production payment authorization/execution."""
    now = now or datetime.now(timezone.utc)
    try:
        provider = require_identity_provider()
        if principal.verification_provider_id != provider.provider_id or not principal.verification_case_reference:
            return False, "IDENTITY_CASE_NOT_BOUND_TO_TRUSTED_PROVIDER"
        kind = VerificationKind(str(principal.verification_kind or "INDIVIDUAL"))
        result = provider.get_status(principal.verification_case_reference)
        if result.provider_case_reference != principal.verification_case_reference:
            return False, "IDENTITY_CASE_REFERENCE_MISMATCH"
        valid, reason = validate_verification_result(
            result, provider_id=provider.provider_id, organization_id=principal.org_id,
            subject_reference=principal.external_subject_id, kind=kind,
            jurisdiction=os.environ.get("PAARI_HOME_JURISDICTION", "AE").strip().upper(), now=now,
        )
        if not valid:
            principal.identity_verification_status = result.status.value
            principal.assurance_level = "low"
            if result.status is VerificationStatus.REVOKED:
                principal.status = "REVOKED"
            elif principal.status != "REVOKED":
                principal.status = "PENDING"
            return False, reason
        principal.identity_verification_status = "VERIFIED"
        principal.verification_evidence_digest = result.evidence_digest
        principal.verification_retrieved_at = result.evidence_retrieved_at
        principal.verification_expires_at = result.expires_at
        principal.assurance_level = result.assurance_level
        principal.status = "ACTIVE"
        return True, "IDENTITY_EVIDENCE_CURRENT"
    except Exception:
        return False, "TRUSTED_IDENTITY_PROVIDER_UNAVAILABLE"
