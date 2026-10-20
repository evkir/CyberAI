"""The first section names what is attacked before it names what it is made of.

A reader deciding whether this is a wrapper over a port scanner decides in the
first screen, and so does a model retrieving the file. The section once opened
with an orchestration layer, a count of agents and a typed pipeline -- true,
and true of every wrapper ever written -- while the sentences that said what
the project attacks sat below the fold. Reordering fixed the page once. Nothing
stopped the next edit from putting the machinery back on top, because no test
reads the order of a paragraph.

The order is what is checked here, not the wording. A guard quoting a sentence
holds until someone rewrites the sentence and then holds nothing, so what is
measured is where two sets of words sit relative to each other: the surfaces
this attacks have to be named before the parts it is built from. Rewriting the
prose freely is allowed; demoting the subject is not.

Both lists are required to appear. A guard that passes when its subject terms
are missing is a guard that rewards deleting them, and an opening that names
no target at all is the failure this exists to catch, not a page with nothing
to order.
"""

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_README = _ROOT / "README.md"

_OPENS = "## What is CyberAI?"
_CLOSES = "Real orchestrator output"

# What is attacked. One of these has to come first.
_TARGETS = ("MCP server", "LLM endpoint", "RAG pipeline", "smart contract")

# What it is built from. These are the means, and they follow.
_MACHINERY = ("specialized agents", "typed, auditable", "**Planner**")


def _section() -> str:
    body = _README.read_text(encoding="utf-8")
    start = body.index(_OPENS)
    return body[start : body.index(_CLOSES, start)]


def _first_index(section: str, terms: tuple[str, ...]) -> int:
    present = [section.index(term) for term in terms if term in section]
    assert present, f"none of {terms} appear in the opening section"
    return min(present)


def test_the_opening_names_a_target_before_it_names_the_machinery() -> None:
    section = _section()
    assert _first_index(section, _TARGETS) < _first_index(section, _MACHINERY), (
        "the opening section describes how CyberAI is built before it says what "
        "it attacks; move the surfaces above the agent roster"
    )


def test_the_opening_does_not_argue_against_a_label() -> None:
    """Repeating a dismissal to deny it prints it in our own voice.

    The section used to quote "LLM wrapper over nmap" and then rebut it, which
    reads as a rebuttal only to someone who already arrived with the objection
    and plants it in everyone else.
    """
    assert "wrapper over nmap" not in _section()


def test_every_machinery_term_is_still_in_the_section() -> None:
    """A term dropped from the prose takes its entry here with it.

    Otherwise the ordering above is enforced against words that left the page,
    and the check passes by measuring nothing.
    """
    section = _section()
    for term in _MACHINERY:
        assert term in section, f"{term} left the opening; drop it here too"
