"""A new provider cannot be added without deciding how it authenticates.

The defect this replaces was silent for as long as it existed: api_key came
from a default_factory reading OPENAI_API_KEY, so every provider added after
OpenAI inherited OpenAI's credential and nothing compared them. The rule is
stated over the provider Literal rather than over a hand-written list, so a
fourth provider fails here on the day its name is added.

Providers that take no credential are named, not omitted -- an empty entry
and a deliberate absence read the same in a mapping, and only one of them is
a decision.
"""

from typing import get_args, get_type_hints

from cyberai.core.config import _PROVIDER_KEY_ENV, LLMConfig, api_key_for

KEYLESS_PROVIDERS = {"ollama"}


def _declared_providers() -> set[str]:
    return set(get_args(get_type_hints(LLMConfig)["provider"]))


def test_every_declared_provider_is_either_keyed_or_named_keyless():
    undecided = _declared_providers() - set(_PROVIDER_KEY_ENV) - KEYLESS_PROVIDERS
    assert not undecided, f"providers with no credential decision: {undecided}"


def test_no_credential_rule_names_a_provider_that_does_not_exist():
    """The mapping is not allowed to outlive the Literal either."""
    stale = (set(_PROVIDER_KEY_ENV) | KEYLESS_PROVIDERS) - _declared_providers()
    assert not stale, f"credential rules for unknown providers: {stale}"


def test_the_rule_is_not_vacuous():
    assert _declared_providers() == {"openai", "anthropic", "ollama"}


def test_each_keyed_provider_reads_its_own_variable(monkeypatch):
    for provider, variable in _PROVIDER_KEY_ENV.items():
        for other in _PROVIDER_KEY_ENV.values():
            monkeypatch.setenv(other, f"sk-{other}")
        assert api_key_for(provider) == f"sk-{variable}"
