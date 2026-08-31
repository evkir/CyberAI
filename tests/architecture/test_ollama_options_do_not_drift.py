"""Two builders produce an ollama options dict; they must not drift apart.

LLMClient._ollama_request serves every product call. LLMClassifier._payload
serves the L2 detector, which deliberately bypasses the client so that a
message suspected of being an attack is never billed to a third party.

That bypass makes the classifier a second producer of the same shape. Until
now the two disagreed -- the client sent neither temperature nor seed -- and
the disagreement was invisible because nothing compared them. This states
the invariant instead: whatever sampling keys one builder sends, the other
sends too. A new key added to one and forgotten in the other fails here on
the day it is added, not on the day a measurement stops reproducing.

The values are deliberately not compared. The classifier pins its own seed
because it must answer the same way for every caller; the product path
takes whatever the session configured. Only the key set is shared.
"""

import pytest

from cyberai.core.config import LLMConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.security.llm_classifier import LLMClassifier


def _client_options() -> dict:
    config = LLMConfig(provider="ollama", model="qwen2.5:7b", seed=0)
    _url, payload = LLMClient(config)._ollama_request([{"role": "user", "content": "x"}], None)
    return payload["options"]


def _classifier_options() -> dict:
    return LLMClassifier(model="qwen2.5:7b")._payload("x")["options"]


@pytest.mark.architecture
def test_both_ollama_builders_send_the_same_option_keys():
    assert set(_client_options()) == set(_classifier_options())


@pytest.mark.architecture
def test_the_shared_keys_are_the_ones_that_decide_reproducibility():
    """A rule over an empty or accidental key set passes forever."""
    assert set(_client_options()) == {"num_ctx", "temperature", "seed"}
