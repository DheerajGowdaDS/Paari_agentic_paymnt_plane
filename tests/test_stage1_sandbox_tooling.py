from pathlib import Path
from scripts import paari_sandbox


def _sandbox_env():
    values = {
        "PAARI_ENV": "sandbox",
        "PAARI_KYB_SIMULATION": "1",
        "PAARI_POSTGRES_PASSWORD": "p" * 32,
        "PAARI_ADMIN_API_KEY": "a" * 32,
        "PAARI_BENEFICIARY_HASH_SECRET": "b" * 32,
        "PAARI_V36_KEY_ENCRYPTION_SECRET": "c" * 32,
        "PAARI_V36_PII_HMAC_SECRET": "d" * 32,
        "PAARI_V36_AUTH_SECRET": "e" * 32,
        "PAARI_V37_DATA_ENCRYPTION_SECRET": "f" * 32,
    }
    return "\n".join(f"{k}={v}" for k, v in values.items()) + "\n"


def test_sandbox_preflight_accepts_distinct_sandbox_secrets(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(_sandbox_env(), encoding="utf-8")
    monkeypatch.setattr(paari_sandbox, "ROOT", tmp_path)
    assert paari_sandbox.preflight(mtls=False) == 0


def test_sandbox_preflight_rejects_production_environment(tmp_path, monkeypatch):
    env = _sandbox_env().replace("PAARI_ENV=sandbox", "PAARI_ENV=prod")
    (tmp_path / ".env").write_text(env, encoding="utf-8")
    monkeypatch.setattr(paari_sandbox, "ROOT", tmp_path)
    assert paari_sandbox.preflight(mtls=False) == 2


def test_sandbox_mtls_preflight_requires_local_pki_and_docker(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(_sandbox_env(), encoding="utf-8")
    monkeypatch.setattr(paari_sandbox, "ROOT", tmp_path)
    monkeypatch.setattr(paari_sandbox.shutil, "which", lambda _name: None)
    assert paari_sandbox.preflight(mtls=True) == 2
