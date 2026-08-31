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

import pathlib
import re

import pytest

from cyberai.core.config import LLMConfig
from cyberai.core.llm_client import LLMClient
from cyberai.core.security.llm_classifier import LLMClassifier

_ROOT = pathlib.Path(__file__).resolve().parents[2]


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


@pytest.mark.architecture
def test_the_research_document_names_the_option_keys_the_client_sends():
    """The published sentence about the request must match the request.

    docs/research/detector-v2.md told readers for three days that this path
    forwarded neither temperature nor seed, which was true when written and
    false the moment it was fixed. A document that describes a request is a
    consumer of that request's shape, and an unwatched consumer goes stale
    silently. The live determinism figure it carries cannot be reproduced in
    CI; the shape it rests on can, and that is what is pinned.
    """
    doc = (_ROOT / "docs" / "research" / "detector-v2.md").read_text(encoding="utf-8")
    sentence = re.search(r"The ollama request carries ([^.]+)\.", doc)
    assert sentence, "detector-v2.md no longer states which option keys the request carries"
    named = set(re.findall(r"`([^`]+)`", sentence.group(1)))
    assert named == set(_client_options())
