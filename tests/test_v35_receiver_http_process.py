"""Validate a distinct receiving process, address, signing key and durable storage."""
import hashlib
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import httpx
import pytest
from app import crypto_utils


def test_separate_http_receiver_process_signs_with_own_key(tmp_path):
    receiver_private, receiver_public = crypto_utils.generate_agent_keypair()
    paari_private, paari_public = crypto_utils.generate_agent_keypair()
    (tmp_path/'receiver.pem').write_text(receiver_private)
    (tmp_path/'paari-public.pem').write_text(paari_public)
    (tmp_path/'receiver.pem').chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    env={**os.environ,
         'PAARI_PARTNER_RECEIVER_ID':'receiver-live-process',
         'PAARI_PARTNER_PRIVATE_KEY_PATH':str(tmp_path/'receiver.pem'),
         'PAARI_PARTNER_PAARI_PUBLIC_KEY_PATH':str(tmp_path/'paari-public.pem'),
         'PAARI_PARTNER_DATABASE':str(tmp_path/'separate-receiver.db'),
         'PAARI_PARTNER_ALLOWED_BENEFICIARIES':'beneficiary-live-01'}
    server=subprocess.Popen([sys.executable,'-m','uvicorn','scripts.receiver_partner_sandbox:app',
                             '--host','127.0.0.1','--port',str(port),'--no-access-log'],
                             cwd=Path(__file__).resolve().parents[1],env=env,
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        base=f'http://127.0.0.1:{port}'
        with httpx.Client(timeout=3,trust_env=False) as client:
            for _ in range(55):
                try:
                    health=client.get(base+'/v1/health')
                    if health.status_code==200: break
                except httpx.HTTPError: pass
                if server.poll() is not None: pytest.fail('Receiver process exited before starting')
                time.sleep(0.15)
            else:pytest.fail('Independent receiver HTTP service did not start')
            assert health.json()['mode']=='LOCAL_SANDBOX_NO_MONEY'
            payload={'type':'paari.payment-context.v1',
                     'intent_id':'process-payment-001','transaction_id':'process-txn-001',
                     'org_id':'bank-sender','agent_id':'agent-001',
                     'beneficiary_id':'beneficiary-live-01','amount_minor_units':9800,
                     'currency':'INR','decision':'allow','execution_authority':False,
                     'issued_at':datetime.now(timezone.utc).isoformat()}
            content=crypto_utils.canonical_json(payload)
            context={'payload':payload,
                'signature_b64':crypto_utils.sign_with_private_key(paari_private,content),
                'payload_digest':hashlib.sha256(content.encode()).hexdigest()}
            signed=client.post(base+'/v1/acknowledge',json={
                'receiver_id':'receiver-live-process','provider_reference':'local-rail-123',
                'context':context}).json()
            assert signed['claim']['result']=='ACCEPTED'
            assert not signed['settlement_confirmed']
            assert crypto_utils.verify_signature(receiver_public,
                crypto_utils.canonical_json(signed['claim']), signed['signature_b64'])
            tampered={**context,'payload':{**payload,'amount_minor_units':1}}
            refused=client.post(base+'/v1/acknowledge',json={
                'receiver_id':'receiver-live-process','provider_reference':'local-rail-123',
                'context':tampered})
            assert refused.status_code==403
        assert (tmp_path/'separate-receiver.db').exists()
    finally:
        server.terminate()
        try:server.wait(timeout=5)
        except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
