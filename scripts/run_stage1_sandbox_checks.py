#!/usr/bin/env python3
"""Run the repeatable Stage 1 local verification suite.

Default: dedicated Stage 1 regression tests + offline local demo verifier.
Use --full to additionally run the verifier's longer provider-stub HTTP E2Es.
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="Include longer simulated-provider HTTP E2Es")
    args = parser.parse_args()
    commands = [
        [sys.executable, "-m", "pytest", "-q", "tests/test_stage1_gateway_kyb.py", "tests/test_stage1_sandbox_tooling.py"],
        [sys.executable, "scripts/verify_local_demo.py"] + (["--full"] if args.full else []),
    ]
    for command in commands:
        print("\n=== " + " ".join(command) + " ===", flush=True)
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode:
            print("FAIL: sandbox verification stopped; see output above.")
            return result.returncode
    print("\nPAARI STAGE 1 SANDBOX CHECKS PASSED. This is local test evidence, not production certification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
