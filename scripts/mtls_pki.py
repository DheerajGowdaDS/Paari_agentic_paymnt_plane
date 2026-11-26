#!/usr/bin/env python3
"""Create a local Paari ingress CA, gateway certificate and Agent Card mTLS certs.

Local sandbox only. Protect all generated private keys and never ship them in a
source archive. Example:
  python scripts/mtls_pki.py init --out ./local_pki
  python scripts/mtls_pki.py issue-client --out ./local_pki --agent-id <AGENT_ID> \
      --org-id <ORG_ID> --agent-card-private-key ./agent-private.pem \
      --agent-card-public-key ./agent-public.pem
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def save_private(path: Path, key) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_cert(path: Path, cert) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_ca(out: Path):
    ca_key = serialization.load_pem_private_key((out / "ca.key").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((out / "ca.crt").read_bytes())
    return ca_key, ca_cert


def issue_cert(subject, public_key, ca_key, ca_cert, *, client: bool, sans):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(days=180))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False))
    return builder.sign(ca_key, hashes.SHA256())


def init_pki(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    if (out / "ca.key").exists() or (out / "ca.crt").exists():
        raise SystemExit("Refusing to overwrite an existing CA. Use a new directory or rotate deliberately.")
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Paari Local Sandbox Ingress CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2)).not_valid_after(now + timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256()))
    save_private(out / "ca.key", ca_key)
    save_cert(out / "ca.crt", ca_cert)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-gateway.local")])
    server_cert = issue_cert(server_subject, server_key.public_key(), ca_key, ca_cert,
        client=False, sans=[x509.DNSName("agent-gateway.local"), x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))])
    save_private(out / "server.key", server_key)
    save_cert(out / "server.crt", server_cert)
    print(f"Created sandbox CA and gateway certificate under: {out.resolve()}")
    print("Keep ca.key private. Configure Nginx ssl_client_certificate with ca.crt.")


def issue_client(out: Path, agent_id: str, *, org_id: str,
                 agent_card_private_key: Path, agent_card_public_key: Path,
                 agent_card_algorithm: str = "ed25519"):
    # A transport certificate is not enough: the Agent Card's own signing key
    # must explicitly authorize this exact certificate fingerprint and org.
    from app import crypto_utils
    from app.mtls_binding import build_agent_card_binding_payload

    ca_key, ca_cert = load_ca(out)
    safe_id = "".join(ch for ch in agent_id if ch.isalnum() or ch in "-_ ").strip()
    if not safe_id or safe_id != agent_id or len(agent_id) > 64:
        raise SystemExit("Agent ID contains unsupported characters")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)])
    cert = issue_cert(subject, key.public_key(), ca_key, ca_cert, client=True,
                      sans=[x509.UniformResourceIdentifier(f"urn:paari:agent:{agent_id}")])
    key_path = out / "clients" / f"{agent_id}.key"
    cert_path = out / "clients" / f"{agent_id}.crt"
    payload_path = out / "clients" / f"{agent_id}.register.json"
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    card_private = agent_card_private_key.read_text(encoding="utf-8")
    card_public = agent_card_public_key.read_text(encoding="utf-8")
    algorithm = crypto_utils.Algorithm(agent_card_algorithm)
    binding = build_agent_card_binding_payload(agent_id, org_id, cert, card_public, algorithm.value)
    binding_message = crypto_utils.canonical_json(binding)
    signature = crypto_utils.sign_with_private_key(card_private, binding_message, algorithm)
    if not crypto_utils.verify_signature(card_public, binding_message, signature, algorithm):
        raise SystemExit("The supplied Agent Card private/public key pair does not match; no certificate artifacts were written.")
    save_private(key_path, key)
    save_cert(cert_path, cert)
    payload = {
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "agent_card_signature_b64": signature,
    }
    payload_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Client certificate: {cert_path.resolve()}")
    print(f"Client private key: {key_path.resolve()} (keep secret; deliver securely to the agent operator)")
    print(f"Registration payload: {payload_path.resolve()}")
    print(f"SHA-256 fingerprint: {fingerprint}")
    print(f"Agent Card key fingerprint: {binding['agent_card_key_fingerprint']}")
    print("Agent Card proof-of-possession: generated for this exact certificate, agent and organization.")
    print("Only the certificate and signature in the registration payload are sent to Paari; never send either private key.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--out", type=Path, required=True)
    issue = sub.add_parser("issue-client")
    issue.add_argument("--out", type=Path, required=True)
    issue.add_argument("--agent-id", required=True)
    issue.add_argument("--org-id", required=True)
    issue.add_argument("--agent-card-private-key", type=Path, required=True)
    issue.add_argument("--agent-card-public-key", type=Path, required=True)
    issue.add_argument("--agent-card-algorithm", choices=["ed25519", "ml-dsa-65", "slh-dsa-sha2-128s"], default="ed25519")
    args = parser.parse_args()
    if args.command == "init":
        init_pki(args.out)
    elif args.command == "issue-client":
        issue_client(args.out, args.agent_id, org_id=args.org_id,
                     agent_card_private_key=args.agent_card_private_key,
                     agent_card_public_key=args.agent_card_public_key,
                     agent_card_algorithm=args.agent_card_algorithm)


if __name__ == "__main__":
    main()
