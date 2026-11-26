from llm_agent.env import KILO_DEFAULT_BASE, KILO_DEFAULT_MODEL, resolve_llm_config
import pytest


def test_kilo_config_defaults_base_and_free_model_without_exposing_secret():
    result = resolve_llm_config({"KILO_API_KEY": "kilo-test-secret"})
    assert result == {"provider": "kilo", "base_url": KILO_DEFAULT_BASE,
                      "api_key": "kilo-test-secret", "model": KILO_DEFAULT_MODEL}
    assert "kilo-test-secret" not in result["base_url"]


def test_explicit_kilo_selection_does_not_fallback_to_legacy_provider():
    with pytest.raises(RuntimeError, match="KILO_API_KEY"):
        resolve_llm_config({"PAARI_LLM_PROVIDER": "kilo", "BYNARA_API_KEY": "legacy",
                            "BYNARA_API_BASE": "https://legacy.example/v1",
                            "BYNARA_MODEL": "legacy-model"})


def test_generic_openai_compatible_provider():
    result = resolve_llm_config({"PAARI_LLM_PROVIDER": "openai-compatible",
        "OPENAI_COMPATIBLE_API_BASE": "https://gateway.example/v1/",
        "OPENAI_COMPATIBLE_API_KEY": "example-secret",
        "OPENAI_COMPATIBLE_MODEL": "model-a"})
    assert result["provider"] == "openai-compatible"
    assert result["base_url"] == "https://gateway.example/v1"
    assert result["model"] == "model-a"


def test_api_endpoint_url_is_not_accepted_as_base():
    with pytest.raises(RuntimeError, match="API root"):
        resolve_llm_config({"PAARI_LLM_PROVIDER": "openai-compatible",
            "OPENAI_COMPATIBLE_API_BASE": "https://gateway.example/v1/chat/completions",
            "OPENAI_COMPATIBLE_API_KEY": "key", "OPENAI_COMPATIBLE_MODEL": "model-a"})


def test_legacy_bynara_still_works():
    result = resolve_llm_config({"BYNARA_API_BASE": "https://router.bynara.id/v1",
                                 "BYNARA_API_KEY": "legacy-key", "BYNARA_MODEL": "legacy-model"})
    assert result["provider"] == "bynara"
