"""Sandbox-only managed parent signing; KMS/HSM and KYC/KYB required in production.

No plaintext PAN/GST or parent private key is saved in the database.
"""
import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import jwt


def sandbox_only():
    if os.getenv('PAARI_ENV','sandbox').lower() in {'prod','prod-live'} or os.getenv('PAARI_LIVE') == '1':
        raise HTTPException(503, 'v3.6 sandbox onboarding disabled in production until managed signing/KYC is integrated')


def secret(name):
    val = os.environ.get(name, '')
    if len(val) < 32:
        raise HTTPException(503, f'{name} requires a separately provisioned 32+ character value')
    return val


def signing_fernet():
    raw = hashlib.sha256(secret('PAARI_V36_KEY_ENCRYPTION_SECRET').encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def generate_managed_parent_key():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return public.decode(), signing_fernet().encrypt(private).decode()


def sign_parent(encrypted: str, payload: str) -> str:
    private = serialization.load_pem_private_key(signing_fernet().decrypt(encrypted.encode()), password=None)
    return base64.b64encode(private.sign(payload.encode())).decode()


def digest_identity(value: str) -> str:
    canonical = value.strip().upper().replace(' ','')
    return hmac.new(secret('PAARI_V36_PII_HMAC_SECRET').encode(), canonical.encode(), hashlib.sha256).hexdigest()


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 128:
        raise HTTPException(422, 'Password length must be between 12 and 128 characters')
    salt = secrets.token_bytes(16)
    rounds = 390000
    digest = hashlib.pbkdf2_hmac('sha256',password.encode(),salt,rounds)
    return f'pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}'


def check_password(password: str, encoded: str) -> bool:
    try:
        _, n, salt, digest = encoded.split('$')
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),int(n)),bytes.fromhex(digest))
    except (ValueError,TypeError):
        return False


def issue_parent_token(parent_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({'iss':'paari-v36','sub':parent_id,'iat':now,'exp':now+timedelta(minutes=30),'scope':'parent'},
                      secret('PAARI_V36_AUTH_SECRET'),algorithm='HS256')


def get_parent_from_token(token: str) -> str:
    try:
        payload = jwt.decode(token,secret('PAARI_V36_AUTH_SECRET'),algorithms=['HS256'],issuer='paari-v36',options={'require':['exp','sub','iss']})
        if payload.get('scope')!='parent': raise jwt.InvalidTokenError()
        return payload['sub']
    except jwt.PyJWTError as e:
        raise HTTPException(401,'Invalid or expired parent session') from e
