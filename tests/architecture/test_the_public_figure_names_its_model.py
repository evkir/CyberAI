"""A figure from a local model is meaningless without the model and the seed.

The benchmark section states a recall for two layers. The second of them is a
language model answering over Ollama, and that answer is a function of which
model the tag resolved to, which seed was pinned, and which prompt was asked.
Publishing the number alone invites a reader to compare it with somebody
else's, which is the comparison this whole exercise exists to make honest.

So the prose is checked against the recording that produced it rather than
against itself: the model name and the seed in the document must be the ones
in the committed verdicts. A tag is not a digest -- `ollama pull` can move
`fast-coder:latest` under the same name without a word -- so this cannot
prove the weights were the same, and does not claim to. What it stops is the
cheaper failure: the recording being regenerated under a different model
while the sentence beside it keeps the old name.

Not asserted here: that the percentages are right. Those travel from the
committed reports and test_docs_quote_the_artifact holds that chain.
"""

import json
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_RESEARCH = _ROOT / "docs" / "research" / "detector-v2.md"
_RECORDING = _ROOT / "examples" / "detector-eval" / "agentdojo-verdicts.json"
_REPORT = _ROOT / "examples" / "detector-eval" / "agentdojo.md"

_SECTION = "## A public benchmark"


def _header() -> dict[str, object]:
    payload = json.loads(_RECORDING.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), f"{_RECORDING.name} is not an object"
    return payload


def _document() -> str:
    return _RESEARCH.read_text(encoding="utf-8")


def test_the_document_names_the_model_the_verdicts_came_from() -> None:
    model = _header()["model"]
    assert isinstance(model, str) and model
    assert f"`{model}`" in _document(), model


def test_the_document_names_the_seed_the_verdicts_came_from() -> None:
    seed = _header()["seed"]
    assert isinstance(seed, int)
    assert f"seed {seed}" in _document(), seed


def test_the_benchmark_section_carries_them_itself() -> None:
    """Next to the figure, not merely somewhere in the file.

    A reader quoting the table will not scroll to find out what produced it,
    and a section that holds a number without its conditions is the shape
    this repository has published stale figures in before.
    """
    body = _document()
    start = body.index(_SECTION)
    end = body.index("\n## ", start + len(_SECTION))
    section = body[start:end]
    model = _header()["model"]
    assert isinstance(model, str)
    assert f"`{model}`" in section, "the model is named elsewhere but not beside the figure"
    assert f"seed {_header()['seed']}" in section


def test_the_report_beside_the_recording_names_the_same_model() -> None:
    """The artifact and the recording describe one run or neither is evidence."""
    model = _header()["model"]
    assert isinstance(model, str)
    assert model in _REPORT.read_text(encoding="utf-8"), model
