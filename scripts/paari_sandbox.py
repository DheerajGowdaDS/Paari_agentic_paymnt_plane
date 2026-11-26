#!/usr/bin/env python3
"""Safe local Paari sandbox controller.

Examples:
  python scripts/paari_sandbox.py preflight
  python scripts/paari_sandbox.py preflight --mtls
  python scripts/paari_sandbox.py up
  python scripts/paari_sandbox.py up --mtls
  python scripts/paari_sandbox.py status
  python scripts/paari_sandbox.py logs
  python scripts/paari_sandbox.py down

This tool only controls the local Docker Compose sandbox. It never configures
live provider credentials or changes PAARI_ENV to a production mode.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_NAMES = (
    "PAARI_POSTGRES_PASSWORD",
    "PAARI_ADMIN_API_KEY",
    "PAARI_BENEFICIARY_HASH_SECRET",
    "PAARI_V36_KEY_ENCRYPTION_SECRET",
    "PAARI_V36_PII_HMAC_SECRET",
    "PAARI_V36_AUTH_SECRET",
    "PAARI_V37_DATA_ENCRYPTION_SECRET",
)
PLACEHOLDERS = ("replace-with", "changeme", "placeholder", "example", "dummy", "todo")


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def run(command: list[str], *, capture: bool = False) -> int:
    print("$ " + " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=capture)
    if capture:
        if result.stdout:
            print(result.stdout.rstrip())
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
    return result.returncode


def preflight(mtls: bool) -> int:
    env_path = ROOT / ".env"
    if not env_path.is_file():
        print("FAIL: .env is missing. Copy .env.example to .env and set fresh sandbox secrets.")
        return 2
    env = read_env_file(env_path)
    failures = []
    if env.get("PAARI_ENV", "").lower() != "sandbox":
        failures.append("PAARI_ENV must be exactly 'sandbox'. This controller refuses production modes.")
    if env.get("PAARI_KYB_SIMULATION") != "1":
        failures.append("PAARI_KYB_SIMULATION must be 1 for the synthetic KYB sandbox walkthrough.")
    values = []
    for name in SECRET_NAMES:
        value = env.get(name, "")
        if len(value) < 32 or any(token in value.lower() for token in PLACEHOLDERS):
            failures.append(f"{name} must be a unique random value of at least 32 characters.")
        values.append(value)
    if len(set(values)) != len(values):
        failures.append("All required secret values must be independently generated and different.")
    pg = env.get("PAARI_POSTGRES_PASSWORD", "")
    if pg and not re.fullmatch(r"[A-Za-z0-9_-]{32,}", pg):
        failures.append("PAARI_POSTGRES_PASSWORD must be URL-safe: letters, digits, underscore or hyphen only.")
    if mtls:
        for name in ("ca.crt", "server.crt", "server.key"):
            if not (ROOT / "local_pki" / name).is_file():
                failures.append(f"Missing local_pki/{name}. Run scripts/mtls_pki.py init --out ./local_pki first.")
        if not shutil.which("docker"):
            failures.append("Docker CLI is not installed or not on PATH.")
        else:
            code = run(["docker", "compose", "version"], capture=True)
            if code:
                failures.append("Docker Compose v2 is unavailable. Install/enable it in Docker Desktop.")
            else:
                config_command = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.mtls.yml", "config", "--quiet"]
                if run(config_command, capture=True):
                    failures.append("Docker Compose rejected the mTLS sandbox configuration. Check .env interpolation and Compose YAML.")
    if failures:
        for item in failures:
            print("FAIL: " + item)
        return 2
    print("PASS: sandbox environment checks are satisfied; secret values were not displayed.")
    return 0


def compose(mtls: bool) -> list[str]:
    command = ["docker", "compose", "-f", "docker-compose.yml"]
    if mtls:
        command += ["-f", "docker-compose.mtls.yml"]
    return command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    pf = sub.add_parser("preflight", help="Validate local sandbox settings")
    pf.add_argument("--mtls", action="store_true", help="Also check Docker Compose and local PKI files")
    up = sub.add_parser("up", help="Start local Postgres + Paari; optionally include mTLS gateway")
    up.add_argument("--mtls", action="store_true")
    status = sub.add_parser("status", help="Show local Compose service status")
    status.add_argument("--mtls", action="store_true", help="Include the Nginx mTLS gateway profile")
    logs = sub.add_parser("logs", help="Follow local Compose service logs")
    logs.add_argument("--tail", type=int, default=150)
    logs.add_argument("--mtls", action="store_true", help="Include the Nginx mTLS gateway profile")
    down = sub.add_parser("down", help="Stop local services (preserve volumes)")
    down.add_argument("--mtls", action="store_true", help="Stop the Nginx mTLS gateway profile too")
    down.add_argument("--volumes", action="store_true", help="Also delete volumes; destructive sandbox reset")
    args = parser.parse_args(argv)

    if args.action == "preflight":
        return preflight(args.mtls)
    mtls = bool(getattr(args, "mtls", False))
    if args.action == "up":
        code = preflight(mtls)
        if code:
            return code
        if not mtls:
            if not shutil.which("docker"):
                print("FAIL: Docker CLI is not installed or not on PATH.")
                return 2
            if run(compose(False) + ["config", "--quiet"], capture=True):
                print("FAIL: Docker Compose rejected the local sandbox configuration.")
                return 2
        command = compose(mtls) + ["up", "-d", "--build"]
    elif args.action == "status":
        command = compose(args.mtls) + ["ps"]
    elif args.action == "logs":
        command = compose(args.mtls) + ["logs", "-f", "--tail", str(max(1, args.tail))]
    elif args.action == "down":
        command = compose(args.mtls) + ["down"] + (["-v"] if args.volumes else [])
    else:
        return 2
    return run(command)


if __name__ == "__main__":
    raise SystemExit(main())
