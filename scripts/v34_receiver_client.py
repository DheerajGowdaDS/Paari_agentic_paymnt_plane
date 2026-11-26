"""Independent receiver-side Ed25519 signer for local integration tests.

Paari never gets this private key. In real deployments use an HSM/KMS-backed
institution signer; never use this file-based script for live money.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import sys
import httpx
from app import crypto_utils
from app.receivers.router import ReceiverClaim


def main() -> None:
    ap=argparse.ArgumentParser(description="Sign and optionally submit receiver evidence (SANDBOX ONLY)")
    ap.add_argument("--private-key",required=True,help="Private Ed25519 PEM path (offline receiver, not Paari server)")
    ap.add_argument("--claim",required=True,help="JSON file with ReceiverClaim fields")
    ap.add_argument("--submit-url",help="Optional HTTP endpoint, e.g. http://127.0.0.1:8000/control/v1/receivers/attestations")
    ap.add_argument("--output",help="Write signed body to a file instead of stdout")
    args=ap.parse_args()
    key_path=pathlib.Path(args.private_key)
    if not key_path.exists():ap.error("private key does not exist")
    claim=ReceiverClaim.model_validate_json(pathlib.Path(args.claim).read_text(encoding="utf-8"))
    payload=claim.model_dump(mode="json")
    signature=crypto_utils.sign_with_private_key(key_path.read_text(encoding="utf-8"),crypto_utils.canonical_json(payload))
    signed={"claim":payload,"signature_b64":signature}
    if args.output:pathlib.Path(args.output).write_text(json.dumps(signed,indent=2),encoding="utf-8")
    elif not args.submit_url:print(json.dumps(signed,indent=2))
    if args.submit_url:
        if not args.submit_url.startswith("http://127.0.0.1:") and not args.submit_url.startswith("http://localhost:"):
            ap.error("This sandbox helper only supports a loopback receiver API")
        resp=httpx.post(args.submit_url,json=signed,timeout=15)
        print(f"HTTP {resp.status_code}: {resp.text[:1500]}")
        if not resp.is_success:sys.exit(1)

if __name__=="__main__":main()
