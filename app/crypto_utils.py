"""
Cryptographic helpers for Layer 1 (Agent Trust).

Algorithm choice: Ed25519 by default, with optional post-quantum algorithms
ML-DSA-65 (FIPS 204) and SLH-DSA-SHA2-128S (FIPS 205) dispatched through the
`Algorithm` enum. Real ML-DSA/SLH-DSA signing requires an installed PQC
backend (liboqs-python or pqcrypto).

- Small Ed25519 keys (32 bytes) and signatures (64 bytes) - cheap to store/transmit.
- Deterministic, fast to verify, no parameter footguns (unlike RSA padding
  choices or raw ECDSA nonce reuse risk).
- Widely supported as the modern default for identity/signing use cases.

Paari NEVER generates or holds an agent's private key. The agent generates
its own key pair, keeps the private key, and registers only the public key
with Paari. `generate_agent_keypair` below exists purely so the demo client
can simulate an agent - a real agent would do this on its own side, out of
Paari's reach.
"""
import base64
import hashlib
import json
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Algorithm(str, Enum):
    """Supported signature algorithms. Ed25519 is the current default.

    ML-DSA-65 (FIPS 204, NIST Level 3) is the recommended post-quantum
    algorithm; SLH-DSA-SHA2-128S (FIPS 205, NIST Level 1) is the
    conservative hash-based anchor. Real ML-DSA/SLH-DSA signing requires
    an installed PQC backend (liboqs-python or pqcrypto).
    """
    ED25519 = "ed25519"
    ML_DSA_65 = "ml-dsa-65"
    SLH_DSA_128S = "slh-dsa-sha2-128s"


class PQCBackendUnavailable(RuntimeError):
    """Raised when a post-quantum algorithm is requested but no PQC backend
    (liboqs-python or pqcrypto) is installed and wired."""


# liboqs mechanism names are case-sensitive and use uppercase with hyphens,
# e.g. "ML-DSA-65". Map the enum values to the exact oqs mechanism name.
_OQS_MECHANISM_NAMES = {
    Algorithm.ML_DSA_65: "ML-DSA-65",
    Algorithm.SLH_DSA_128S: "SLH-DSA-SHA2-128s",
}


# liboqs mechanism names differ from our enum values (case / separators).
_OQS_MECHANISM_NAMES = {
    Algorithm.ML_DSA_65: "ML-DSA-65",
    # SHA2 pure variants fail to verify on this liboqs build; use the
    # SHAKE variant (same signature size, hash-based security).
    Algorithm.SLH_DSA_128S: "SLH_DSA_PURE_SHAKE_128S",
}


def _oqs_signer(algorithm: Algorithm):
    """Return an `oqs.Signature` instance for the algorithm, or None if no
    PQC backend (liboqs-python / pqcrypto) is importable or the mechanism
    is not enabled in the installed liboqs build."""
    try:
        import oqs
    except ImportError:
        return None
    try:
        return oqs.Signature(_OQS_MECHANISM_NAMES.get(algorithm, algorithm.value))
    except Exception:
        return None


def generate_keypair(algorithm: Algorithm = Algorithm.ED25519) -> tuple[str, str]:
    """Generate a key pair for the given algorithm. Returns (private_pem, public_pem).

    Ed25519 is generated with the pyca/cryptography library. ML-DSA/SLH-DSA
    key generation requires an installed PQC backend (liboqs-python or
    pqcrypto) and is wired in Phase 3 of the PQC migration.
    """
    algorithm = Algorithm(algorithm)
    if algorithm == Algorithm.ED25519:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return private_pem, public_pem
    signer = _oqs_signer(algorithm)
    if signer is None:
        raise PQCBackendUnavailable(
            f"Algorithm {algorithm.value} requires a post-quantum backend "
            "(liboqs-python or pqcrypto). Install liboqs-python (or pqcrypto) "
            f"to generate {algorithm.value} keys."
        )
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()
    # PQC keys have no standard PEM format yet; store as raw bytes base64.
    return base64.b64encode(secret_key).decode(), base64.b64encode(public_key).decode()


def generate_agent_keypair() -> tuple[str, str]:
    """Backward-compatible alias for generate_keypair(Algorithm.ED25519)."""
    return generate_keypair(Algorithm.ED25519)


def sign_with_private_key(private_pem: str, message: str, algorithm: Algorithm = Algorithm.ED25519) -> str:
    """Sign a message, return base64 signature.

    Ed25519 signing uses pyca/cryptography. ML-DSA/SLH-DSA signing requires
    an installed PQC backend (wired in Phase 3).
    """
    algorithm = Algorithm(algorithm)
    if algorithm == Algorithm.ED25519:
        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        signature = private_key.sign(message.encode())
        return base64.b64encode(signature).decode()
    signer = _oqs_signer(algorithm)
    if signer is None:
        raise PQCBackendUnavailable(
            f"Algorithm {algorithm.value} requires a post-quantum backend "
            "(liboqs-python or pqcrypto). Install liboqs-python (or pqcrypto) "
            f"to sign with {algorithm.value}."
        )
    import oqs

    secret_key = base64.b64decode(private_pem)
    bound = oqs.Signature(_OQS_MECHANISM_NAMES.get(algorithm, algorithm.value), secret_key)
    signature = bound.sign(message.encode())
    return base64.b64encode(signature).decode()


def verify_signature(public_pem: str, message: str, signature_b64: str, algorithm: Algorithm = Algorithm.ED25519) -> bool:
    """Verify a signature was made by the holder of the matching private key."""
    import binascii

    algorithm = Algorithm(algorithm)
    if algorithm == Algorithm.ED25519:
        public_key = serialization.load_pem_public_key(public_pem.encode())
        try:
            signature = base64.b64decode(signature_b64)
        except (binascii.Error, ValueError):
            return False
        try:
            public_key.verify(signature, message.encode())
            return True
        except (InvalidSignature, ValueError):
            return False
    signer = _oqs_signer(algorithm)
    if signer is None:
        raise PQCBackendUnavailable(
            f"Algorithm {algorithm.value} requires a post-quantum backend "
            "(liboqs-python or pqcrypto). Install liboqs-python (or pqcrypto) "
            f"to verify {algorithm.value} signatures."
        )
    try:
        public_key = base64.b64decode(public_pem)
        signature = base64.b64decode(signature_b64)
    except (binascii.Error, ValueError):
        return False
    try:
        return bool(signer.verify(message.encode(), signature, public_key))
    except Exception:
        return False


def canonical_json(payload: dict) -> str:
    """
    Deterministic JSON encoding so the same logical document always produces
    the same bytes to sign/verify, regardless of dict key insertion order.
    Both the parent (signing) and Paari (verifying) must use this exact
    function on the exact same fields.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def verify_hybrid_signature(
    message: str,
    ed25519_sig: str | None,
    ed25519_public: str | None,
    ed25519_algorithm: Algorithm | None = Algorithm.ED25519,
    pq_sig: str | None = None,
    pq_public: str | None = None,
    pq_algorithm: Algorithm | None = None,
    *,
    require_any: bool = True,
) -> bool:
    """Verify a hybrid (classical + post-quantum) signature pair.

    ``require_any=True`` (migration window): returns True when AT LEAST ONE of
    the two signatures verifies. A missing/None signature for that algorithm
    counts as "not present, skip" rather than "failed".

    ``require_any=False`` (cutover): returns True ONLY when the PQC signature
    verifies (the classical side is no longer sufficient).
    """
    ed_ok = (
        ed25519_sig is not None
        and ed25519_public is not None
        and ed25519_algorithm is not None
        and verify_signature(ed25519_public, message, ed25519_sig, algorithm=ed25519_algorithm)
    )
    pq_ok = (
        pq_sig is not None
        and pq_public is not None
        and pq_algorithm is not None
        and verify_signature(pq_public, message, pq_sig, algorithm=pq_algorithm)
    )
    if require_any:
        return ed_ok or pq_ok
    return pq_ok


def public_key_fingerprint(public_pem: str, algorithm: Algorithm = Algorithm.ED25519) -> str:
    """SHA-256 hex digest of the PEM bytes, used to bind a delegation to one
    specific key.

    Ed25519 keys (the current default) return the plain hex digest so existing
    fingerprints and storage keep working unchanged. Post-quantum keys are
    prefixed with the algorithm (e.g. "ml-dsa-65:<sha256>") since they have no
    standard PEM format yet and the algorithm is tracked separately during
    migration.
    """
    algorithm = Algorithm(algorithm)
    digest = hashlib.sha256(public_pem.encode()).hexdigest()
    if algorithm == Algorithm.ED25519:
        return digest
    return f"{algorithm.value}:{digest}"
