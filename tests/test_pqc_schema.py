"""Phase 2b: PQC-sized schema for federation agreements + payment context.

The Phase 2 migration resized agent/mandate/receiver key & signature columns,
but left federation_agreements.signature_b64 and payment_context_envelopes.
signature_b64 at VARCHAR(256) — far too small for an ML-DSA-65 signature
(~4,412 base64 chars) — and signer_fingerprint at VARCHAR(64), which clips the
algorithm-prefixed PQC fingerprint ("ml-dsa-65:<sha256hex>" = 79 chars).

These tests verify the live schema after `alembic upgrade head`.
"""
from __future__ import annotations
import pathlib

import sqlalchemy as sa

PAARI_FIXED = pathlib.Path(__file__).resolve().parents[1]


def _cfg_for(db_path: pathlib.Path):
    from alembic.config import Config
    cfg = Config(str(PAARI_FIXED / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def _cols(db_path: pathlib.Path, table: str) -> dict:
    cfg = _cfg_for(db_path)
    from alembic import command
    command.upgrade(cfg, "head")
    eng = sa.create_engine(f"sqlite:///{db_path}")
    insp = sa.inspect(eng)
    cols = {c["name"]: c for c in insp.get_columns(table)}
    eng.dispose()
    return cols


def test_federation_agreement_signature_and_fingerprint_are_pqc_sized(tmp_path):
    db = tmp_path / "pqc_schema.db"
    cols = _cols(db, "federation_agreements")
    assert "signature_b64" in cols
    assert "signature_algorithm" in cols
    sig_len = int(str(cols["signature_b64"]["type"]).strip().upper().replace("VARCHAR(", "").rstrip(")"))
    assert sig_len >= 8000, f"federation_agreements.signature_b64 is only {sig_len} chars"
    fp_len = int(str(cols["signer_fingerprint"]["type"]).strip().upper().replace("VARCHAR(", "").rstrip(")"))
    assert fp_len >= 128, f"federation_agreements.signer_fingerprint is only {fp_len} chars (needs 128 for PQC fingerprints)"


def test_payment_context_envelope_signature_is_pqc_sized(tmp_path):
    db = tmp_path / "pqc_schema2.db"
    cols = _cols(db, "payment_context_envelopes")
    assert "signature_algorithm" in cols
    sig_len = int(str(cols["signature_b64"]["type"]).strip().upper().replace("VARCHAR(", "").rstrip(")"))
    assert sig_len >= 8000, f"payment_context_envelopes.signature_b64 is only {sig_len} chars"


def test_alembic_check_reports_no_drift_after_phase2b(tmp_path):
    """After the model + migration changes, `alembic check` must be clean on SQLite."""
    from alembic import command
    import os
    os.environ.pop("ALEMBIC_URL", None)
    db = tmp_path / "pqc_check.db"
    cfg = _cfg_for(db)
    command.upgrade(cfg, "head")
    # `check` returns None when no drift is detected; it raises / prints otherwise.
    result = command.check(cfg)
    assert result is None
