"""Provider-neutral Ed25519 signing interface for Paari-issued artifacts.

This module defines the boundary between protocol code and private-key storage.
The sandbox adapter is process-local PEM. A production KMS/HSM integration must
supply a plugin implementing the protocol below; this repository intentionally
ships no cloud-specific client or credentials and therefore keeps production
startup blocked unless an actual managed adapter is installed and healthy.

Plugin contract (configured with PAARI_SIGNING_ADAPTER=module:factory):
  * factory() returns KmsHsmSigningBackend(client, active_key_id), where the
    provider-specific client implements KmsHsmClient.
  * sign() accepts the exact JWS signing input bytes and returns a raw 64-byte
    Ed25519 signature. Public-key lookup must retain old public keys for at
    least the maximum lifetime of tokens signed with each key.
  * healthcheck() must actively verify the configured remote key/service is
    usable without exposing secret material.

A class-shaped interface is used so AWS, GCP, Azure, PKCS#11 HSMs, or a
financial institution's signing service can be integrated without tying the
protocol layer to a vendor SDK. No adapter is presumed to exist just because
an environment variable names one.
"""
from __future__ import annotations

import importlib
import os
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SigningBackendError(RuntimeError):
    """Raised when the configured signing implementation cannot be trusted."""


@runtime_checkable
class SigningBackend(Protocol):
    key_id: str
    managed: bool
    algorithm: str

    def sign(self, message: bytes) -> bytes: ...
    def public_key_pem_for(self, key_id: str) -> str: ...
    def healthcheck(self) -> bool: ...


class LocalPemSigningBackend:
    """Development-only adapter over a local Ed25519 private key."""

    managed = False
    algorithm = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey, key_id: str = "paari-1") -> None:
        self._private_key = private_key
        self.key_id = key_id
        self._public_key = private_key.public_key()
        self._public_pem = self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def private_key(self) -> Ed25519PrivateKey:
        """Compatibility handle for sandbox/test utilities only."""
        return self._private_key

    @property
    def private_pem(self) -> str:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def public_key_pem_for(self, key_id: str) -> str:
        if key_id != self.key_id:
            raise SigningBackendError(f"Unknown signing key id: {key_id!r}")
        return self._public_pem

    def public_key_pem(self) -> str:
        return self._public_pem

    def healthcheck(self) -> bool:
        # Local crypto availability only. This is explicitly not a managed-key
        # or production-health assertion.
        try:
            challenge = b"paari-signing-backend-healthcheck-v1"
            self._public_key.verify(self._private_key.sign(challenge), challenge)
            return True
        except (InvalidSignature, ValueError):
            return False


class KmsHsmClient(Protocol):
    """Minimal contract expected from a provider-specific KMS/HSM adapter."""

    def sign_ed25519(self, key_id: str, message: bytes) -> bytes: ...
    def get_public_key_pem(self, key_id: str) -> str: ...
    def healthcheck(self) -> bool: ...


class KmsHsmSigningBackend:
    """Provider-neutral wrapper around an injected KMS/HSM client.

    The concrete client is intentionally injected; this class validates the
    wire-level cryptographic contract but does not claim provider certification.
    """

    managed = True

    def __init__(self, client: KmsHsmClient, key_id: str) -> None:
        if not key_id or not key_id.strip():
            raise SigningBackendError("A managed signing key id is required")
        self.client = client
        self.key_id = key_id.strip()
        self._active_public_key = self._load_public_key(self.key_id)

    def _load_public_key(self, key_id: str) -> Ed25519PublicKey:
        try:
            pem = self.client.get_public_key_pem(key_id)
            key = serialization.load_pem_public_key(pem.encode("ascii"))
        except Exception as exc:
            raise SigningBackendError(f"Unable to load public key for key id {key_id!r}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise SigningBackendError("Managed signing adapter must expose an Ed25519 public key")
        return key

    def sign(self, message: bytes) -> bytes:
        signature = self.client.sign_ed25519(self.key_id, message)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise SigningBackendError("Managed signing adapter returned a malformed Ed25519 signature")
        try:
            self._active_public_key.verify(signature, message)
        except (InvalidSignature, ValueError) as exc:
            raise SigningBackendError("Managed signing response did not verify against its registered public key") from exc
        return signature

    def public_key_pem_for(self, key_id: str) -> str:
        # The client is required to resolve historical key ids as well as the
        # current active id, so credentials remain verifiable during rotation.
        key = self._load_public_key(key_id)
        return key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def public_key_pem(self) -> str:
        return self._active_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def healthcheck(self) -> bool:
        return bool(self.client.healthcheck())


def _load_factory(spec: str):
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name.strip() or not attribute.strip():
        raise SigningBackendError("PAARI_SIGNING_ADAPTER must be module.path:factory_name")
    try:
        module = importlib.import_module(module_name.strip())
        factory = getattr(module, attribute.strip())
    except Exception as exc:
        raise SigningBackendError("Unable to load configured managed signing adapter") from exc
    if not callable(factory):
        raise SigningBackendError("Configured signing adapter factory is not callable")
    return factory


def load_signing_backend(local_key_factory) -> SigningBackend:
    """Load the selected signer. Local keys are never treated as managed."""
    backend = os.environ.get("PAARI_SIGNING_BACKEND", "local_pem").strip().lower()
    if backend == "local_pem":
        key = local_key_factory()
        key_id = os.environ.get("PAARI_SIGNING_KEY_ID", "paari-1").strip() or "paari-1"
        return LocalPemSigningBackend(key, key_id=key_id)
    if backend in {"kms", "hsm", "kms_hsm"}:
        spec = os.environ.get("PAARI_SIGNING_ADAPTER", "").strip()
        if not spec:
            raise SigningBackendError(
                "PAARI_SIGNING_BACKEND=kms_hsm requires PAARI_SIGNING_ADAPTER=module:factory; refusing local fallback"
            )
        factory = _load_factory(spec)
        try:
            instance = factory()
        except Exception as exc:
            raise SigningBackendError("Managed signing adapter initialization failed") from exc
        if not isinstance(instance, KmsHsmSigningBackend):
            raise SigningBackendError(
                "Managed adapter factory must return KmsHsmSigningBackend(client, active_key_id); "
                "arbitrary plugins cannot self-assert managed status"
            )
        if not str(instance.key_id).strip():
            raise SigningBackendError("Configured managed signing adapter has no active key id")
        expected_key_id = os.environ.get("PAARI_SIGNING_KEY_ID", "").strip()
        if expected_key_id and instance.key_id != expected_key_id:
            raise SigningBackendError(
                "Configured managed signing adapter active key id does not match PAARI_SIGNING_KEY_ID"
            )
        return instance
    raise SigningBackendError("PAARI_SIGNING_BACKEND must be local_pem or kms_hsm")


def encode_ed25519_jwt(payload: dict, backend: SigningBackend) -> str:
    """Encode a compact JWS/JWT using raw Ed25519 bytes supplied by the backend."""
    import base64
    import json

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header = {"alg": "EdDSA", "kid": backend.key_id, "typ": "JWT"}
    header_part = b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_part = b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = backend.sign(signing_input)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise SigningBackendError("Ed25519 signer returned an invalid signature length")
    return f"{header_part}.{payload_part}.{b64url(signature)}"
