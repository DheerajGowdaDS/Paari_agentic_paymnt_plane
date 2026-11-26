"""KYC/KYB provider contract owned by Paari's control plane.

Provider adapters return evidence and status. Paari remains responsible for
its own policy decision, assurance mapping, revocation and audit. This module
contains no live vendor client and must not be treated as KYC/KYB verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Protocol
import hashlib


class VerificationKind(StrEnum):
    INDIVIDUAL = "INDIVIDUAL"
    ORGANIZATION = "ORGANIZATION"
    AUTHORIZED_REPRESENTATIVE = "AUTHORIZED_REPRESENTATIVE"
    UBO = "UBO"


class VerificationStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    UNAVAILABLE = "UNAVAILABLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


@dataclass(frozen=True)
class VerificationRequest:
    verification_id: str
    organization_id: str
    subject_reference: str
    kind: VerificationKind
    jurisdiction: str = "AE"

    def __post_init__(self) -> None:
        if not self.verification_id.strip() or not self.organization_id.strip() or not self.subject_reference.strip():
            raise ValueError("verification identifiers must be non-empty")
        if len(self.jurisdiction) != 2 or not self.jurisdiction.isalpha() or self.jurisdiction.upper() != self.jurisdiction:
            raise ValueError("jurisdiction must be an uppercase ISO 3166-1 alpha-2 code")


@dataclass(frozen=True)
class VerificationResult:
    provider_id: str
    provider_case_reference: str
    status: VerificationStatus
    jurisdiction: str
    evidence_digest: str | None
    evidence_retrieved_at: datetime | None
    expires_at: datetime | None
    assurance_level: str = "low"
    reason_codes: tuple[str, ...] = ()
    # Bound result to the requested subject and verification purpose. Providers
    # must return the digest calculated by subject_reference_digest(); never
    # return raw identity documents or identifiers in audit payloads.
    subject_reference_digest: str | None = None
    verification_kind: VerificationKind | None = None

    def __post_init__(self) -> None:
        if not self.provider_id.strip() or not self.provider_case_reference.strip():
            raise ValueError("provider identifiers must be non-empty")
        if self.jurisdiction != self.jurisdiction.upper() or len(self.jurisdiction) != 2:
            raise ValueError("jurisdiction must be uppercase ISO 3166-1 alpha-2")
        if self.assurance_level not in {"low", "substantial", "high"}:
            raise ValueError("unsupported assurance level")
        if self.status is VerificationStatus.VERIFIED:
            if not self.evidence_digest or len(self.evidence_digest) != 64:
                raise ValueError("verified results require a SHA-256 evidence digest")
            if self.evidence_retrieved_at is None:
                raise ValueError("verified results require evidence retrieval time")
            if not self.subject_reference_digest or len(self.subject_reference_digest) != 64:
                raise ValueError("verified results require a SHA-256 subject-reference digest")
            if self.verification_kind is None:
                raise ValueError("verified results require a verification kind")
            if self.evidence_retrieved_at.tzinfo is None or self.evidence_retrieved_at.utcoffset() is None:
                raise ValueError("evidence retrieval time must be timezone-aware")
        if self.expires_at is not None and (self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None):
            raise ValueError("expires_at must be timezone-aware")


def subject_reference_digest(organization_id: str, subject_reference: str) -> str:
    """Return a stable, non-reversible digest binding evidence to tenant+subject."""
    material = f"paari-identity-subject-v1\0{organization_id}\0{subject_reference}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


class IdentityVerificationProvider(Protocol):
    """Contract for UAE PASS / KYB vendor / bank-attestation adapters."""

    provider_id: str

    def verify(self, request: VerificationRequest) -> VerificationResult:
        """Create or retrieve verification evidence for a subject and purpose."""
        ...

    def get_status(self, provider_case_reference: str) -> VerificationResult:
        """Refresh authoritative status; cached `VERIFIED` must expire/revoke."""
        ...

    def healthcheck(self) -> bool:
        """Return non-sensitive integration health only."""
        ...


class SandboxIdentityVerificationProvider:
    """Synthetic test double. It refuses construction outside sandbox/test.

    Default behaviour deliberately produces no `VERIFIED` outcome, so the
    mock cannot be used to manufacture legal-identity assurance even inside a
    development flow. The trusted loader (`load_identity_provider`) refuses
    this provider type outright, no matter what `evidence_state` is set.

    `evidence_state` is an explicit, development-only simulation knob for the
    local SAFR acceptance workflow: it lets the Golden Payment Flow exercise
    the active / expired / revoked / unavailable / rejected identity evidence
    states against the real governance engine, so every one of them is proven
    to fail closed (or pass, for active) without a real KYC/KYB vendor. It
    is metadata for a local demonstration, never production identity proof.
    """

    provider_id = "paari-synthetic-test-only"

    def __init__(self, environment: str = "sandbox",
                 evidence_state: VerificationStatus | None = None,
                 subject_reference: str = "local-developer-principal") -> None:
        if environment.strip().lower() not in {"sandbox", "test"}:
            raise RuntimeError("synthetic identity provider is forbidden outside sandbox/test")
        self.environment = environment.strip().lower()
        # None (default) preserves the historical "never VERIFIED" contract.
        # An explicitly set state is a dev-time simulation, never trusted evidence.
        self.evidence_state = evidence_state
        self.subject_reference = subject_reference

    def _state_digest(self, organization_id: str, subject_reference: str, status: VerificationStatus) -> str:
        material = f"paari-sandbox-evidence-v1\0{organization_id}\0{subject_reference}\0{status.value}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _result_for(self, organization_id: str, subject_reference: str,
                    status: VerificationStatus, kind: VerificationKind) -> VerificationResult:
        now = datetime.now(timezone.utc)
        subject_ref_digest = subject_reference_digest(organization_id, subject_reference)
        # Active (VERIFIED) evidence carries a structurally-valid digest + a
        # future expiry + a retrieval time so a downstream validator can reason
        # about liveness; every other state is a structurally-valid refusal.
        if status is VerificationStatus.VERIFIED:
            return VerificationResult(
                provider_id=self.provider_id,
                provider_case_reference=f"SYNTH-VE-{subject_ref_digest[:12]}",
                status=status, jurisdiction="AE",
                evidence_digest=self._state_digest(organization_id, subject_reference, status),
                evidence_retrieved_at=now,
                expires_at=now + timedelta(days=30),
                assurance_level="substantial",
                subject_reference_digest=subject_ref_digest,
                verification_kind=kind,
            )
        return VerificationResult(
            provider_id=self.provider_id,
            provider_case_reference=f"SYNTH-{subject_ref_digest[:12]}",
            status=status, jurisdiction="AE",
            evidence_digest=None, evidence_retrieved_at=now,
            expires_at=None, assurance_level="low",
            reason_codes=(f"SYNTHETIC_{status.value}_NOT_TRUSTED_EVIDENCE",),
            subject_reference_digest=subject_ref_digest,
            verification_kind=kind,
        )

    def with_state(self, status: VerificationStatus | None) -> "SandboxIdentityVerificationProvider":
        """Return a copy pinned to one simulated evidence state (dev-only)."""
        return SandboxIdentityVerificationProvider(
            environment=self.environment, evidence_state=status,
            subject_reference=self.subject_reference)

    def verify(self, request: VerificationRequest) -> VerificationResult:
        if self.evidence_state is not None:
            return self._result_for(request.organization_id, request.subject_reference,
                                    self.evidence_state, request.kind)
        return VerificationResult(
            provider_id=self.provider_id,
            provider_case_reference=f"SYNTHETIC-{request.verification_id}",
            status=VerificationStatus.REVIEW_REQUIRED,
            jurisdiction=request.jurisdiction,
            evidence_digest=None,
            evidence_retrieved_at=None,
            expires_at=None,
            assurance_level="low",
            reason_codes=("SYNTHETIC_PROVIDER_NEVER_ESTABLISHES_LEGAL_IDENTITY",),
            subject_reference_digest=subject_reference_digest(request.organization_id, request.subject_reference),
            verification_kind=request.kind,
        )

    def get_status(self, provider_case_reference: str) -> VerificationResult:
        if self.evidence_state is not None:
            kind = VerificationKind.INDIVIDUAL
            return self._result_for("default", self.subject_reference, self.evidence_state, kind)
        return VerificationResult(
            provider_id=self.provider_id,
            provider_case_reference=provider_case_reference,
            status=VerificationStatus.UNAVAILABLE,
            jurisdiction="AE",
            evidence_digest=None,
            evidence_retrieved_at=None,
            expires_at=None,
            assurance_level="low",
            reason_codes=("SYNTHETIC_PROVIDER_HAS_NO_AUTHORITATIVE_STATUS",),
        )

    def healthcheck(self) -> bool:
        return self.environment in {"sandbox", "test"}
