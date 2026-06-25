"""Tests for the air-gapped egress guard (day 6 / STANDOFF II W1)."""

from __future__ import annotations

import pytest

from cyberai.core.config import LLMConfig
from cyberai.core.egress_guard import (
    EgressViolation,
    assert_air_gapped,
    is_local_endpoint,
)


def test_ollama_default_is_local():
    assert is_local_endpoint(LLMConfig(provider="ollama")) is True


def test_ollama_private_host_is_local():
    cfg = LLMConfig(provider="ollama", base_url="http://192.168.1.10:11434")
    assert is_local_endpoint(cfg) is True


def test_ollama_public_host_is_not_local():
    cfg = LLMConfig(provider="ollama", base_url="http://ollama.example.com:11434")
    assert is_local_endpoint(cfg) is False


def test_openai_without_base_url_is_not_local():
    # Bare openai => public cloud API.
    assert is_local_endpoint(LLMConfig(provider="openai")) is False


def test_openai_with_loopback_base_url_is_local():
    # vLLM / local OpenAI-compatible server.
    cfg = LLMConfig(provider="openai", base_url="http://127.0.0.1:8000/v1")
    assert is_local_endpoint(cfg) is True


def test_anthropic_with_private_base_url_is_local():
    cfg = LLMConfig(provider="anthropic", base_url="http://10.0.0.5:8080")
    assert is_local_endpoint(cfg) is True


def test_assert_air_gapped_passes_for_local():
    assert_air_gapped(LLMConfig(provider="ollama"))  # no raise


def test_assert_air_gapped_raises_for_cloud():
    with pytest.raises(EgressViolation):
        assert_air_gapped(LLMConfig(provider="openai", api_key="k"))


def test_localhost_hostname_is_local():
    cfg = LLMConfig(provider="openai", base_url="http://localhost:8000")
    assert is_local_endpoint(cfg) is True
