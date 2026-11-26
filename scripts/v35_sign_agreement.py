"""External trusted-surface signer for v3.5 agreements (no server-held private keys).

Usage:
  python scripts/v35_sign_agreement.py --claims agreement.json --private-key user.pem --out signed.json

The claims must match /control/v1/federation/requirements policy_digest,
agent and beneficiary IDs, purpose and limits, and use timezone-aware times.
Signing does NOT enroll or certify this actor; a separate administrator must
register the corresponding public key for USER/SENDER_ORG or approve a receiver.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from app import crypto_utils
from app.federation.contracts import AgreementClaims


def main():
    ap = argparse.ArgumentParser(description="Sign externally prepared Paari v3.5 agreement")
    ap.add_argument("--claims", type=Path, required=True, help="JSON claim file, no secrets")
    ap.add_argument("--private-key", type=Path, required=True, help="Private PEM held by the actor, not Paari server")
    ap.add_argument("--out", type=Path, required=True, help="Signed JSON to upload through a secure channel")
    ap.add_argument("--algorithm", default="ed25519",
                    choices=["ed25519", "ml-dsa-65", "slh-dsa-sha2-128s"],
                    help="Signature algorithm (default: ed25519). PQC requires liboqs-python.")
    args = ap.parse_args()
    if args.out.exists():
        ap.error("Refusing to overwrite an existing signed artifact")
    claims = AgreementClaims.model_validate(json.loads(args.claims.read_text(encoding="utf-8")))
    payload = claims.model_dump(mode="json")
    algorithm = crypto_utils.Algorithm(args.algorithm)
    signature = crypto_utils.sign_with_private_key(
        args.private_key.read_text(encoding="utf-8"),
        crypto_utils.canonical_json(payload),
        algorithm=algorithm)
    result = {"claims": payload, "signature_b64": signature, "signature_algorithm": args.algorithm}
    args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Wrote signed governance agreement to", args.out)
    print("Actor:", claims.subject_type, claims.subject_id)
    print("Agreement:", claims.agreement_id)
    print("Algorithm:", args.algorithm)
    print("No private key was copied to the output artifact")


if __name__ == "__main__":
    main()
