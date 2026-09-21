"""An unknown provider name must not reach the config as if it were one.

Before this, CYBERAI_LLM_PROVIDER=gemini produced a config whose provider was
the literal string "gemini". Nothing rejected it: from_env passed str into a
field declared Literal, and the two files holding that path were outside
[tool.mypy] files, so the checker never saw the assignment either. The name
was answered at call time, with a credential resolved for a provider that
does not exist.

The reader narrows instead of raising, per the rule stated on _env_bool: a
value outside the declared set is nobody having chosen, and garbage in a
variable must not abort a scan at startup.
"""

from typing import get_args, get_type_hints

from cyberai.core.config import _PROVIDERS, CyberAIConfig, LLMConfig, _env_provider


def test_a_declared_provider_survives_the_environment(monkeypatch):
    """The narrowing must not collapse every answer onto the default."""
    monkeypatch.setenv("CYBERAI_LLM_PROVIDER", "anthropic")
    assert CyberAIConfig.from_env().llm.provider == "anthropic"


def test_an_unknown_provider_does_not_reach_the_config(monkeypatch):
    monkeypatch.setenv("CYBERAI_LLM_PROVIDER", "gemini")
    provider = CyberAIConfig.from_env().llm.provider
    assert provider in _PROVIDERS
    assert provider == "openai"


def test_an_unknown_provider_does_not_abort_the_run(monkeypatch):
    """No raise here: nine call sites reach from_env, one inside an MCP tool."""
    monkeypatch.setenv("CYBERAI_LLM_PROVIDER", "not-a-provider")
    CyberAIConfig.from_env()


def test_case_and_whitespace_do_not_invent_a_provider(monkeypatch):
    monkeypatch.setenv("CYBERAI_LLM_PROVIDER", "  Anthropic ")
    assert CyberAIConfig.from_env().llm.provider == "anthropic"


def test_the_reader_reads_the_declared_literal_and_not_a_copy():
    """Control: a second hand-written list would pass every test above."""
    assert _PROVIDERS == frozenset(get_args(get_type_hints(LLMConfig)["provider"]))
    assert _PROVIDERS == {"openai", "anthropic", "ollama"}


def test_the_fallback_returns_the_default_it_was_given(monkeypatch):
    """Asserted where the branch and the default differ.

    from_env passes "openai", which is also the field default, so every
    assertion above is satisfied by a reader that ignores its argument and
    hardcodes "openai". Reading with a different default is the only place
    the two answers come apart.
    """
    monkeypatch.setenv("CYBERAI_PROBE_PROVIDER", "gemini")
    assert _env_provider("CYBERAI_PROBE_PROVIDER", "ollama") == "ollama"


def test_the_unset_fallback_returns_the_default_it_was_given(monkeypatch):
    """Same distinction for the unset path, which is a separate branch."""
    monkeypatch.delenv("CYBERAI_PROBE_PROVIDER", raising=False)
    assert _env_provider("CYBERAI_PROBE_PROVIDER", "anthropic") == "anthropic"
