"""Pure helpers for domain-separated Agent Card / mTLS certificate binding."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from app import crypto_utils


def certificate_validity_utc(cert: x509.Certificate) -> tuple[datetime, datetime]:
    """Return timezone-aware certificate validity timestamps across cryptography versions."""
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return not_before, not_after


def build_agent_card_binding_payload(agent_id: str, org_id: str, cert: x509.Certificate,
                                      agent_card_public_key_pem: str, algorithm_name: str) -> dict[str, Any]:
    """Canonical proof payload signed by the Agent Card key for this exact cert."""
    algorithm = crypto_utils.Algorithm(algorithm_name or "ed25519")
    key_fingerprint = crypto_utils.public_key_fingerprint(agent_card_public_key_pem, algorithm)
    not_before, not_after = certificate_validity_utc(cert)
    return {
        "purpose": "PAARI_AGENT_MTLS_CERTIFICATE_BINDING",
        "version": "1",
        "agent_id": agent_id,
        "org_id": org_id,
        "certificate_fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "certificate_serial_number_hex": format(cert.serial_number, "x"),
        "certificate_not_before": not_before.isoformat(),
        "certificate_not_after": not_after.isoformat(),
        "agent_card_key_fingerprint": key_fingerprint,
    }
