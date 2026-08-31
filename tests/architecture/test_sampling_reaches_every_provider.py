"""A provider branch that ignores the sampling config cannot be added quietly.

The behavioural tests cover the four Anthropic paths that exist today by
driving them. What they cannot cover is the ninth branch nobody has written
yet, and that is exactly how this defect arrived: the OpenAI paths carried
temperature from the start, the Anthropic ones were added later without it,
and nothing compared them.

Scope, stated because a reader will assume more than this file checks: it
covers the branches that talk to an SDK client. The ollama path builds its
options dict in _ollama_request and is held by
tests/architecture/test_ollama_options_do_not_drift.py instead.
"""

import ast
import pathlib

import pytest

CLIENT_SOURCE = pathlib.Path(__file__).resolve().parents[2] / "cyberai" / "core" / "llm_client.py"

_SDK_CLIENTS = (
    "anthropic.Anthropic",
    "anthropic.AsyncAnthropic",
    "openai.OpenAI",
    "openai.AsyncOpenAI",
)


def _sdk_methods():
    source = CLIENT_SOURCE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    cls = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "LLMClient"
    )
    for member in cls.body:
        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        segment = ast.get_source_segment(source, member) or ""
        if any(client in segment for client in _SDK_CLIENTS):
            yield member


def _reads(node, field: str) -> bool:
    return any(isinstance(child, ast.Attribute) and child.attr == field for child in ast.walk(node))


@pytest.mark.architecture
def test_every_sdk_branch_reads_the_configured_temperature():
    deaf = [m.name for m in _sdk_methods() if not _reads(m, "temperature")]
    assert not deaf, f"provider branches that never read config.temperature: {deaf}"


@pytest.mark.architecture
def test_the_rule_is_not_vacuous():
    """A rule matching nothing passes forever. Eight branches exist today."""
    found = sorted(m.name for m in _sdk_methods())
    assert found == [
        "_acall_anthropic",
        "_acall_openai",
        "_call_anthropic",
        "_call_openai",
        "_call_tools_anthropic",
        "_call_tools_openai",
        "_structured_anthropic",
        "_structured_openai",
    ]
