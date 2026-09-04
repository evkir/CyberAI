"""The headline is a claim about the repository, checked against the modules.

A product headline is the one line most readers take away, and it is the
line least likely to be revisited when the code moves. The previous one led
with a pentest platform while the sentence thirty lines below it already led
with MCP servers and LLM endpoints, so the two disagreed about what this is
and nothing noticed.

The headline names three things, and each is required to exist as code. That
is a weaker claim than "this works", which no architecture test can make,
and a stronger one than the document currently supported: a headline naming
a capability with no module behind it is marketing, and it fails here.

The map is read in both directions. A phrase in the map has to appear in the
headline block, so a claim that is quietly dropped from the prose takes its
entry with it rather than leaving a check on text nobody reads.
"""

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"

_OPENS = "# 🤖 CyberAI"
_CLOSES = "![CyberAI benchmark demo]"

# What the headline promises, and the module that has to be there for it.
_CLAIM_TO_MODULE = {
    "MCP servers": "cyberai/agents/mcp_scan/agent.py",
    "LLM agents": "cyberai/agents/redteam/fuzzer.py",
    "out-of-band": "cyberai/agents/exploit/oob_workflow.py",
}


def _headline() -> str:
    body = _README.read_text(encoding="utf-8")
    start = body.index(_OPENS)
    return body[start : body.index(_CLOSES, start)]


def test_every_claim_in_the_headline_has_a_module_behind_it() -> None:
    missing = sorted(
        f"{claim} -> {rel}" for claim, rel in _CLAIM_TO_MODULE.items() if not (_ROOT / rel).exists()
    )
    assert not missing, f"headline claims a capability with no module: {missing}"


def test_every_mapped_claim_is_still_in_the_headline() -> None:
    """A check on a sentence nobody kept is a check on nothing."""
    headline = _headline()
    dropped = sorted(claim for claim in _CLAIM_TO_MODULE if claim not in headline)
    assert not dropped, f"mapped claim the headline no longer makes: {dropped}; drop the entry"
