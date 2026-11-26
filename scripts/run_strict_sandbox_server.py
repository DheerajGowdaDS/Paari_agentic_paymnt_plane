"""Start a persistent, strict Paari sandbox service.

This process intentionally remains alive after a client-side E2E driver exits so
provider webhooks and reconciliation workers can finish. It is NOT a production
launcher; the application itself still blocks prod/prod-live until managed
KMS/HSM and trusted KYC/KYB adapters are implemented and validated.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from llm_agent.env import load_env  # noqa: E402


def prepare_environment(env: dict[str, str]) -> dict[str, str]:
    """Return a strict sandbox environment, refusing production-like profiles."""
    result = dict(env)
    current = result.get("PAARI_ENV", "sandbox").strip().lower()
    if current not in {"sandbox", "test"} or result.get("PAARI_LIVE") == "1":
        raise ValueError(
            "run_strict_sandbox_server.py only starts PAARI_ENV=sandbox/test; "
            "use an approved production deployment pipeline for any production profile"
        )
    result["PAARI_ENV"] = current
    result["PAARI_CONTROL_PLANE_ENFORCEMENT"] = "1"
    result["PAARI_REQUIRE_SIGNED_MANDATE"] = "1"
    result["PAARI_REQUIRE_USER_MANDATE"] = "1"
    result["PAARI_MODE"] = "autonomous"
    return result


def main() -> int:
    load_env()
    try:
        os.environ.update(prepare_environment(dict(os.environ)))
    except ValueError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    # Report posture only; never print secrets or complete provider key IDs.
    key_id = os.environ.get("RAZORPAY_KEY_ID", "")
    provider_environment = "test" if key_id.startswith("rzp_test_") else (
        "live" if key_id.startswith("rzp_live_") else "unknown"
    )
    print(
        "Paari strict sandbox server starting: "
        f"env={os.environ['PAARI_ENV']} mode={os.environ['PAARI_MODE']} "
        "control_plane_enforcement=true signed_mandates_required=true "
        f"provider_environment={provider_environment}; process remains running for webhooks",
        flush=True,
    )
    import uvicorn
    uvicorn.run("app.main:app", host=os.environ.get("PAARI_HOST", "127.0.0.1"),
                port=int(os.environ.get("PAARI_PORT", "8000")), reload=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
