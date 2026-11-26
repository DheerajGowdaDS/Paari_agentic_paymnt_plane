"""Provider-neutral signer contract and rotation verification tests."""
import base64
import pytest
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.signing_backends import (
    KmsHsmSigningBackend,
    LocalPemSigningBackend,
    SigningBackendError,
    encode_ed25519_jwt,
    load_signing_backend,
)


def _pub_pem(key):
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


class FakeManagedKms:
    """Contract-test fake only; it is never advertised as real managed KMS."""

    def __init__(self):
        self.keys = {"paari-key-v1": Ed25519PrivateKey.generate(),
                     "paari-key-v2": Ed25519PrivateKey.generate()}
        self.available = True

    def sign_ed25519(self, key_id: str, message: bytes) -> bytes:
        return self.keys[key_id].sign(message)

    def get_public_key_pem(self, key_id: str) -> str:
        return _pub_pem(self.keys[key_id])

    def healthcheck(self) -> bool:
        return self.available


def test_local_backend_sign_verify_and_healthcheck():
    key = Ed25519PrivateKey.generate()
    backend = LocalPemSigningBackend(key)
    message = b"paari-test-message"
    backend.public_key_pem_for("paari-1")
    signature = backend.sign(message)
    public = serialization.load_pem_public_key(backend.public_key_pem_for("paari-1").encode())
    public.verify(signature, message)
    assert backend.managed is False
    assert backend.healthcheck() is True
    with pytest.raises(SigningBackendError, match="Unknown signing key id"):
        backend.public_key_pem_for("retired-key")


def test_managed_adapter_contract_verifies_signatures_and_retains_old_key_ids():
    client = FakeManagedKms()
    backend_v1 = KmsHsmSigningBackend(client, "paari-key-v1")
    old_token = encode_ed25519_jwt({"iss": "paari", "aud": "paari-test", "sub": "agent-1"}, backend_v1)

    # Rotate active signing to v2. A verifier still resolves v1 public material
    # by the JWT kid; production plugins must retain historical keys to support it.
    backend_v2 = KmsHsmSigningBackend(client, "paari-key-v2")
    new_token = encode_ed25519_jwt({"iss": "paari", "aud": "paari-test", "sub": "agent-2"}, backend_v2)
    old_kid = jwt.get_unverified_header(old_token)["kid"]
    new_kid = jwt.get_unverified_header(new_token)["kid"]
    old_claims = jwt.decode(old_token, backend_v2.public_key_pem_for(old_kid), algorithms=["EdDSA"],
                            issuer="paari", audience="paari-test")
    new_claims = jwt.decode(new_token, backend_v2.public_key_pem_for(new_kid), algorithms=["EdDSA"],
                            issuer="paari", audience="paari-test")
    assert old_claims["sub"] == "agent-1"
    assert new_claims["sub"] == "agent-2"
    assert backend_v2.managed is True
    assert backend_v2.healthcheck() is True
    client.available = False
    assert backend_v2.healthcheck() is False


def test_managed_signer_rejects_wrong_signature_key():
    class BadKms(FakeManagedKms):
        def sign_ed25519(self, key_id: str, message: bytes) -> bytes:
            return self.keys["paari-key-v1"].sign(message)

    backend = KmsHsmSigningBackend(BadKms(), "paari-key-v2")
    with pytest.raises(SigningBackendError, match="did not verify"):
        backend.sign(b"key mismatch must fail closed")


def test_kms_mode_refuses_local_fallback_when_adapter_missing(monkeypatch):
    monkeypatch.setenv("PAARI_SIGNING_BACKEND", "kms_hsm")
    monkeypatch.delenv("PAARI_SIGNING_ADAPTER", raising=False)
    with pytest.raises(SigningBackendError, match="refusing local fallback"):
        load_signing_backend(lambda: pytest.fail("local fallback must not be called"))


def test_bad_managed_signature_length_is_refused():
    class MalformedKms(FakeManagedKms):
        def sign_ed25519(self, key_id: str, message: bytes) -> bytes:
            return b"short"

    backend = KmsHsmSigningBackend(MalformedKms(), "paari-key-v2")
    with pytest.raises(SigningBackendError, match="malformed Ed25519 signature"):
        backend.sign(b"length check")
