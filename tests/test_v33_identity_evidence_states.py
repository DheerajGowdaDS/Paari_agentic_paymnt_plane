"""v3.3 §4: identity simulator must expose all required evidence states, failing
closed for every state that is not a currently-valid VERIFIED result.

The dev-only SandboxIdentityVerificationProvider now supports an explicit
evidence_state override so the local SAFR acceptance workflow can exercise:
  active / expired / revoked / unavailable / rejected
against the real validate_verification_result contract.

These tests do NOT use the paari_client fixture because the identity simulator
is a pure in-memory object with no database dependency. The last test pins the
trust boundary: the trusted loader must refuse a sandbox provider regardless of
its configured evidence_state.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.identity_providers.contracts import (
    SandboxIdentityVerificationProvider,
    VerificationKind,
    VerificationRequest,
    VerificationStatus,
    subject_reference_digest,
)
from app.identity_providers.runtime import (
    IdentityProviderError,
    load_identity_provider,
    validate_verification_result,
)


def _validation_now() -> datetime:
    """Validate one second *after* the provider stamped the evidence retrieval.

    The sandbox provider stamps `evidence_retrieved_at` at call time; a
    validator that runs a moment later (the correct real-world ordering) sees it
    as past, not from the future. Validating "before" retrieval would be
    temporally impossible and is not what the production flow does.
    """
    return datetime.now(timezone.utc) + timedelta(seconds=1)


def _request(kind: VerificationKind = VerificationKind.INDIVIDUAL) -> VerificationRequest:
    return VerificationRequest(
        verification_id="v33-sandbox",
        organization_id="org-v33",
        subject_reference="dev-local-subject",
        kind=kind,
        jurisdiction="AE",
    )


# ---------------------------------------------------------------------------
# 1. Default sandbox provider still refuses to produce VERIFIED
# ---------------------------------------------------------------------------
def test_default_sandbox_provider_never_returns_verified():
    provider = SandboxIdentityVerificationProvider(environment="sandbox")
    result = provider.verify(_request())
    assert result.status is not VerificationStatus.VERIFIED
    assert result.status is VerificationStatus.REVIEW_REQUIRED
    assert "SYNTHETIC_PROVIDER_NEVER_ESTABLISHES_LEGAL_IDENTITY" in result.reason_codes


# ---------------------------------------------------------------------------
# 2. Active / VERIFIED state passes the downstream validator
# ---------------------------------------------------------------------------
def test_sandbox_active_evidence_state_passes_validator():
    provider = SandboxIdentityVerificationProvider(
        environment="sandbox", evidence_state=VerificationStatus.VERIFIED,
        subject_reference="dev-local-subject")
    req = _request()
    result = provider.verify(req)
    assert result.status is VerificationStatus.VERIFIED
    accepted, reason = validate_verification_result(
        result,
        provider_id=provider.provider_id,
        organization_id=req.organization_id,
        subject_reference=req.subject_reference,
        kind=req.kind,
        jurisdiction=req.jurisdiction,
        now=_validation_now(),
    )
    assert accepted is True, reason
    assert reason == "IDENTITY_EVIDENCE_VERIFIED"


# ---------------------------------------------------------------------------
# 3-7. Expired / Revoked / Unavailable / Rejected / Review-Required
#     all fail closed through the validator
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("state", [
    VerificationStatus.EXPIRED,
    VerificationStatus.REVOKED,
    VerificationStatus.UNAVAILABLE,
    VerificationStatus.REJECTED,
    VerificationStatus.REVIEW_REQUIRED,
])
def test_sandbox_non_verified_evidence_states_fail_closed(state: VerificationStatus):
    provider = SandboxIdentityVerificationProvider(
        environment="sandbox", evidence_state=state,
        subject_reference="dev-local-subject")
    req = _request()
    result = provider.verify(req)
    assert result.status is state, "sandbox provider must report the requested state"
    accepted, reason = validate_verification_result(
        result,
        provider_id=provider.provider_id,
        organization_id=req.organization_id,
        subject_reference=req.subject_reference,
        kind=req.kind,
        jurisdiction=req.jurisdiction,
        now=_validation_now(),
    )
    assert accepted is False, f"state {state.value} must be rejected by the validator"
    assert reason == f"IDENTITY_STATUS_{state.value}", reason


# ---------------------------------------------------------------------------
# 8. The trusted loader still refuses the sandbox provider even when
#    configured with a VERIFIED evidence state (trust boundary unchanged).
# ---------------------------------------------------------------------------
def test_trusted_loader_refuses_sandbox_provider_regardless_of_state(monkeypatch):
    """Regression pin: a development-only evidence-state override must not
    be treated as production-trust evidence. The runtime loader must refuse
    SandboxIdentityVerificationProvider, even when PAARI_TRUSTED_IDENTITY_
    PROVIDER_IDS lists its provider_id.
    """
    # Use a module path that resolves to the sandbox provider. The factory is
    # a simple callable that returns a configured instance.
    import app.identity_providers.contracts as contracts
    factory = lambda: contracts.SandboxIdentityVerificationProvider(
        environment="sandbox",
        evidence_state=VerificationStatus.VERIFIED,
        subject_reference="subject-should-not-matter",
    )
    # Expose the factory as a module-level name so the loader can import it.
    # We create a minimal module path string the loader's factory lookup expects.
    monkeypatch.setenv("PAARI_IDENTITY_PROVIDER_ADAPTER",
                       "app.identity_providers.contracts:_v33_sandbox_factory")
    monkeypatch.setenv("PAARI_TRUSTED_IDENTITY_PROVIDER_IDS",
                       "paari-synthetic-test-only")
    # Monkeypatch the module attribute so the factory is actually found.
    contracts._v33_sandbox_factory = factory  # type: ignore

    try:
        with pytest.raises(IdentityProviderError) as exc_info:
            load_identity_provider()
        assert "synthetic" in str(exc_info.value).lower() or "sandbox" in str(exc_info.value).lower(), \
            f"error must name the sandbox type: {exc_info.value}"
    finally:
        del contracts._v33_sandbox_factory
