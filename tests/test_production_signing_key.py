"""Production must never silently create a new protocol signing identity."""
import os

import pytest


def test_production_refuses_to_auto_generate_missing_signing_key(tmp_path, monkeypatch):
    from app import security

    target = tmp_path / "missing-paari-key.pem"
    monkeypatch.setattr(security, "_KEY_PATH", str(target))
    monkeypatch.setenv("PAARI_ENV", "prod")
    monkeypatch.setenv("PAARI_SIGNING_KEY_PATH", str(target))
    monkeypatch.delenv("PAARI_LIVE", raising=False)

    with pytest.raises(RuntimeError, match="refuses to auto-generate"):
        security._load_or_create_signing_key()
    assert not target.exists()


def test_production_rejects_group_or_world_readable_signing_key(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX file permission semantics are not available on Windows")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from app import security

    target = tmp_path / "paari-key.pem"
    target.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(target, 0o644)
    monkeypatch.setattr(security, "_KEY_PATH", str(target))
    monkeypatch.setenv("PAARI_ENV", "prod-live")
    monkeypatch.setenv("PAARI_SIGNING_KEY_PATH", str(target))
    monkeypatch.delenv("PAARI_LIVE", raising=False)

    with pytest.raises(RuntimeError, match="permissions are too broad"):
        security._load_or_create_signing_key()
