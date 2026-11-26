"""Minimal .env loader and provider-neutral OpenAI-compatible LLM configuration."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

KILO_DEFAULT_BASE = "https://ai-gateway.kilo.ai/api/v1"
KILO_DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"


def load_env(path: str | os.PathLike[str] = ".env") -> list[str]:
    """Populate os.environ from a local env file; returns key NAMES only."""
    file = Path(path)
    if not file.is_file():
        return []
    names: list[str] = []
    for line in file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")
        names.append(key)
    return names


def require_env(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"{key} is not set — add it to .env or your shell")
    return value


def resolve_llm_config(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Resolve provider settings without exposing or logging secrets.

    Provider precedence:
      1. PAARI_LLM_PROVIDER=kilo, or KILO_API_KEY is set
      2. PAARI_LLM_PROVIDER=openai-compatible, or OPENAI_COMPATIBLE_API_KEY is set
      3. legacy BYNARA_* variables for backward compatibility

    Kilo defaults only its documented OpenAI-compatible base and the free-model
    example; a caller should still validate model availability and tool-calling.
    Explicit provider selection never silently falls back to another provider.
    """
    env = os.environ if environ is None else environ
    provider = str(env.get("PAARI_LLM_PROVIDER", "")).strip().casefold()
    if not provider:
        if env.get("KILO_API_KEY", "").strip():
            provider = "kilo"
        elif env.get("OPENAI_COMPATIBLE_API_KEY", "").strip():
            provider = "openai-compatible"
        else:
            provider = "bynara"

    if provider == "kilo":
        api_key = str(env.get("KILO_API_KEY", "")).strip()
        if not api_key:
            raise RuntimeError("KILO_API_KEY is not set — add it to .env or your shell")
        base_url = str(env.get("KILO_API_BASE", KILO_DEFAULT_BASE)).strip()
        model = str(env.get("KILO_MODEL", KILO_DEFAULT_MODEL)).strip()
    elif provider in {"openai-compatible", "openai_compatible", "generic"}:
        api_key = str(env.get("OPENAI_COMPATIBLE_API_KEY", "")).strip()
        if not api_key:
            raise RuntimeError("OPENAI_COMPATIBLE_API_KEY is not set — add it to .env or your shell")
        base_url = str(env.get("OPENAI_COMPATIBLE_API_BASE", "")).strip()
        model = str(env.get("OPENAI_COMPATIBLE_MODEL", "")).strip()
    elif provider == "bynara":
        api_key = str(env.get("BYNARA_API_KEY", "")).strip()
        base_url = str(env.get("BYNARA_API_BASE", "")).strip()
        model = str(env.get("BYNARA_MODEL", "")).strip()
    else:
        raise RuntimeError(
            "PAARI_LLM_PROVIDER must be one of: kilo, openai-compatible, bynara"
        )

    missing = [name for name, value in (("base URL", base_url), ("model", model)) if not value]
    if missing:
        prefix = {"kilo": "KILO", "bynara": "BYNARA"}.get(provider, "OPENAI_COMPATIBLE")
        vars_by_name = {"base URL": f"{prefix}_API_BASE", "model": f"{prefix}_MODEL"}
        names = ", ".join(vars_by_name[name] for name in missing)
        raise RuntimeError(f"Missing LLM configuration: {names}")

    # A base URL must identify the API root, not an endpoint, to avoid accidental
    # double appends like /v1/chat/completions/chat/completions.
    base_url = base_url.rstrip("/")
    if not base_url.startswith(("https://", "http://")):
        raise RuntimeError("LLM API base URL must be an absolute HTTP(S) URL")
    if base_url.endswith("/chat/completions") or base_url.endswith("/models"):
        raise RuntimeError("LLM API base URL must be the API root, not /models or /chat/completions")
    return {"provider": provider, "base_url": base_url, "api_key": api_key, "model": model}
