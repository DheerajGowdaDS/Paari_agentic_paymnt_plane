#!/usr/bin/env python3
"""Validate a Paari Agent Portability Package against a separately trusted issuer key."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

# Running `python scripts/validate_agent_portability.py` sets sys.path[0] to
# the scripts directory, not the repository root. Add the root explicitly so
# this documented CLI works without requiring package installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.portability import PortabilityValidationError, validate_agent_portability_package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, help="JSON portability package exported by Paari")
    parser.add_argument("--trusted-issuer-key-id", required=True, help="Issuer key ID obtained from an independent trust channel")
    parser.add_argument("--trusted-issuer-public-key", required=True, help="PEM public key pinned independently of the package")
    args = parser.parse_args()
    try:
        package = json.loads(Path(args.package).read_text(encoding="utf-8"))
        trusted_key = Path(args.trusted_issuer_public_key).read_text(encoding="utf-8")
        result = validate_agent_portability_package(package, trusted_issuer_keys={args.trusted_issuer_key_id: trusted_key})
    except (OSError, json.JSONDecodeError, PortabilityValidationError, ValueError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
