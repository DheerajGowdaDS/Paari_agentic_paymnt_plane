"""Independent *local* receiving-institution process (NO MONEY MOVEMENT).

Only issues signed ACCEPTED / REJECTED *acknowledgements* after checking a
separately pinned Paari signing public key, org/receiver/beneficiary, freshness,
and an immutable payment context. Never issues CREDIT_ATTESTED, PAID or proof of
settlement; those need actual receiving-bank or custodial corroboration.

Run independently (separate process / storage / key):
 PAARI_PARTNER_RECEIVER_ID=... PAARI_PARTNER_PRIVATE_KEY_PATH=... \\
 PAARI_PARTNER_PAARI_PUBLIC_KEY_PATH=... PAARI_PARTNER_DATABASE=... \\
 python -m uvicorn scripts.receiver_partner_sandbox:app --host 127.0.0.1 --port 8811

The receiver's allowed beneficiary IDs are configured by its own operator via
PAARI_PARTNER_ALLOWED_BENEFICIARIES (comma-separated), NOT by incoming agent data.
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from app import crypto_utils


def _utc_now():
    return datetime.now(timezone.utc)


class AcceptRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    context: dict
    receiver_id: str = Field(min_length=1, max_length=64)
    provider_reference: str = Field(min_length=1, max_length=128)
    result: str = 'ACCEPTED'


def create_app(*, receiver_id: str, private_key_pem: str,
               paari_public_key_pem: str, database_path: str,
               allowed_beneficiaries: set[str]) -> FastAPI:
    """Create an isolated receiving institution with its own tamper-aware inbox."""
    if not receiver_id or not private_key_pem or not paari_public_key_pem or not database_path:
        raise ValueError('Receiver ID, key material, and independent database are required')
    if not allowed_beneficiaries:
        raise ValueError('Receiver must explicitly configure its allowed beneficiaries')
    # Validate these keys at startup, not on the first payment.
    test = {'purpose': 'receiver_sandbox_startup'}
    if not crypto_utils.verify_signature(
        crypto_utils.serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            .public_key().public_bytes(
                encoding=crypto_utils.serialization.Encoding.PEM,
                format=crypto_utils.serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        crypto_utils.canonical_json(test),
        crypto_utils.sign_with_private_key(private_key_pem, crypto_utils.canonical_json(test))):
        raise ValueError('Receiver private key validation failed')
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS inbox('
                     'intent_id TEXT PRIMARY KEY, context_digest TEXT NOT NULL,'
                     'result_json TEXT NOT NULL, created_at TEXT NOT NULL)')
    api = FastAPI(title='Independent Receiver Sandbox', version='0.1',
                  description='Sandbox acknowledgement only, never settlement')

    @api.get('/v1/health')
    def health():
        return {'service': 'independent_receiving_institution',
                'receiver_id': receiver_id,
                'mode': 'LOCAL_SANDBOX_NO_MONEY',
                'beneficiary_credit_verified': False}

    @api.post('/v1/acknowledge')
    def acknowledge(req: AcceptRequest):
        if req.receiver_id != receiver_id:
            raise HTTPException(403, 'Receiver ID does not match this institution')
        if req.result not in {'ACCEPTED', 'REJECTED'}:
            raise HTTPException(422, 'Only acceptance or rejection is supported; no credit assertions')
        body = req.context
        payload = body.get('payload')
        sig = body.get('signature_b64')
        digest = body.get('payload_digest')
        if not isinstance(payload, dict) or not isinstance(sig, str) or not isinstance(digest, str):
            raise HTTPException(422, 'Signed Paari context required')
        actual = hashlib.sha256(crypto_utils.canonical_json(payload).encode()).hexdigest()
        if not secrets.compare_digest(actual, digest):
            raise HTTPException(403, 'Context digest mismatch')
        if not crypto_utils.verify_signature(paari_public_key_pem, crypto_utils.canonical_json(payload), sig):
            raise HTTPException(403, 'Paari context signature is not valid for pinned issuer')
        if payload.get('type') != 'paari.payment-context.v1' or payload.get('execution_authority') is not False:
            raise HTTPException(403, 'Unsupported or authority-bearing context')
        if payload.get('decision') != 'allow':
            raise HTTPException(403, 'Paari has not permitted this payment instruction')
        if payload.get('beneficiary_id') not in allowed_beneficiaries:
            raise HTTPException(403, 'Beneficiary not permitted by receiving institution')
        if not payload.get('intent_id') or not payload.get('org_id') or not payload.get('agent_id'):
            raise HTTPException(403, 'Context missing immutable origin references')
        if not isinstance(payload.get('amount_minor_units'), int) or payload['amount_minor_units'] <= 0:
            raise HTTPException(403, 'Invalid amount')
        signed_at = payload.get('issued_at')
        try:
            moment = datetime.fromisoformat(signed_at.replace('Z', '+00:00'))
            if moment.tzinfo is None:
                raise ValueError('naive timestamp')
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(403, 'Context creation timestamp invalid')
        if abs((_utc_now() - moment).total_seconds()) > 300:
            raise HTTPException(403, 'Context outside five-minute freshness window')
        if req.result == 'ACCEPTED' and not req.provider_reference:
            raise HTTPException(403, 'Provider reference required')
        context_binding = hashlib.sha256(crypto_utils.canonical_json({
            'payload_digest': digest, 'provider_reference': req.provider_reference,
            'result': req.result, 'receiver_id': receiver_id}).encode()).hexdigest()
        with sqlite3.connect(database_path, timeout=10) as conn:
            # BEGIN IMMEDIATE makes intent-id idempotency durable across receiver process restarts.
            conn.execute('BEGIN IMMEDIATE')
            found = conn.execute('SELECT context_digest,result_json FROM inbox WHERE intent_id=?',
                                 (payload['intent_id'],)).fetchone()
            if found:
                if found[0] != context_binding:
                    raise HTTPException(409, 'Conflicting repeated receiver acknowledgement')
                return json.loads(found[1])
            claim = {'event_id': secrets.token_hex(16),
                     'receiver_id': receiver_id,
                     'beneficiary_id': payload['beneficiary_id'],
                     'intent_id': payload['intent_id'],
                     'result': req.result,
                     'provider_reference': req.provider_reference,
                     'amount_minor_units': payload['amount_minor_units'],
                     'currency': payload['currency'],
                     'signed_at': _utc_now().isoformat()}
            signed = {'claim': claim, 'signature_b64': crypto_utils.sign_with_private_key(
                private_key_pem, crypto_utils.canonical_json(claim)),
                'settlement_confirmed': False,
                'receiving_credit_independently_verified': False,
                'sandbox_only': True}
            conn.execute('INSERT INTO inbox(intent_id,context_digest,result_json,created_at) VALUES(?,?,?,?)',
                         (payload['intent_id'], context_binding, json.dumps(signed), _utc_now().isoformat()))
            return signed

    return api


def _env_app():
    rid = os.getenv('PAARI_PARTNER_RECEIVER_ID', '')
    signer = os.getenv('PAARI_PARTNER_PRIVATE_KEY_PATH', '')
    pinned = os.getenv('PAARI_PARTNER_PAARI_PUBLIC_KEY_PATH', '')
    database = os.getenv('PAARI_PARTNER_DATABASE', '')
    beneficiaries = {x.strip() for x in os.getenv('PAARI_PARTNER_ALLOWED_BENEFICIARIES','').split(',') if x.strip()}
    if not all((rid, signer, pinned, database, beneficiaries)):
        # Module import must not create untrusted demo keys or initialize a server
        # on an operator machine with incomplete configuration.
        return FastAPI(title='Receiver Sandbox (not configured)')
    return create_app(receiver_id=rid, private_key_pem=Path(signer).read_text(),
                      paari_public_key_pem=Path(pinned).read_text(),
                      database_path=database, allowed_beneficiaries=beneficiaries)


app = _env_app()
