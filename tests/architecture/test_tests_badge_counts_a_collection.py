"""The test-count badge must come from a collection, not from a memory.

The badge said 2252 while the suite held 2440. Nothing produced that number:
it was typed once and edited by hand afterwards, which is the same failure
the artifact gates exist to stop, moved to the README.

It counts collected tests rather than passing ones, and the distinction is
deliberate. Collection is cheap and reproducible; "passing" is a claim about
a run, and this test is itself part of the run that would have to make it.
The suite being green is what makes every collected test a passing one, so
the badge says what is measured here and the CI status badge says the rest.

Counting used to live here, which left the badge readable and unwritable: the
gate could say the number was wrong and nothing could set it right. The
counter now lives in scripts/tests_badge.py and this file reads it, so the
number written by hand and the number checked here cannot be two numbers.

The launch post states the same figure and is written by the same script.
It said 2252 while the suite collected 2650, and it is the document an
outside reader meets first. Rather than run a second collection here, the
post is compared against the badge: the badge is already pinned to a
collection above, so one measurement reaches both readers.

The script is loaded from its path rather than imported by name. scripts/ is
importable today only because the editable install drops the repository root
into sys.path; an assertion resting on the install mode is an assertion about
the machine it last ran on.
"""

import importlib.util
import pathlib
import shutil
import subprocess
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "tests_badge.py"


def _badge_tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("tests_badge", _SCRIPT)
    assert spec and spec.loader, f"no module at {_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_badge_counts_the_tests_that_exist() -> None:
    tool = _badge_tool()
    claimed, collected = tool.claimed(), tool.collected()
    assert claimed == collected, (
        f"the README badge says {claimed} tests and the suite collects {collected}. "
        "Run scripts/tests_badge.py rather than editing this number."
    )


def test_the_writer_writes_the_number_the_reader_reads(tmp_path) -> None:
    """A writer that puts down a different figure is a second producer."""
    tool = _badge_tool()
    copy = tmp_path / "README.md"
    shutil.copy(tool.README, copy)
    assert tool.rewrite(1, copy) is True
    assert tool.claimed(copy) == 1


def test_rewriting_a_current_badge_leaves_the_file_alone(tmp_path) -> None:
    """Otherwise every run dirties the tree and the diff stops meaning anything."""
    tool = _badge_tool()
    copy = tmp_path / "README.md"
    shutil.copy(tool.README, copy)
    before = copy.read_bytes()
    assert tool.rewrite(tool.claimed(copy), copy) is False
    assert copy.read_bytes() == before


def test_the_post_states_the_number_the_badge_states() -> None:
    tool = _badge_tool()
    post, badge = tool.claimed_in_post(), tool.claimed()
    assert post == badge, (
        f"the launch post says {post} tests and the README badge says {badge}. "
        "Run scripts/tests_badge.py rather than editing either number."
    )


def test_the_post_writer_writes_the_number_the_post_reader_reads(tmp_path) -> None:
    tool = _badge_tool()
    copy = tmp_path / "launch-post-draft.md"
    shutil.copy(tool.POST, copy)
    assert tool.rewrite_post(1, copy) is True
    assert tool.claimed_in_post(copy) == 1


def test_rewriting_a_current_post_leaves_the_file_alone(tmp_path) -> None:
    tool = _badge_tool()
    copy = tmp_path / "launch-post-draft.md"
    shutil.copy(tool.POST, copy)
    before = copy.read_bytes()
    assert tool.rewrite_post(tool.claimed_in_post(copy), copy) is False
    assert copy.read_bytes() == before


def test_the_sentence_is_found_across_a_line_break(tmp_path) -> None:
    """A reflowed paragraph must not silently stop being written to.

    Markdown wraps, and the phrase this script edits is long enough to be
    split by an editor or by a later rewording. Matched on one line only,
    the writer would report no change and the reader would go on quoting
    whatever number was there before.
    """
    tool = _badge_tool()
    copy = tmp_path / "launch-post-draft.md"
    copy.write_text("7 tests collected under the gated\nselection.\n", encoding="utf-8")
    assert tool.claimed_in_post(copy) == 7
    assert tool.rewrite_post(9, copy) is True
    assert tool.claimed_in_post(copy) == 9


@pytest.mark.parametrize("status", [1, 2, 5])
def test_an_unfinished_collection_is_not_a_count(monkeypatch, status: int) -> None:
    """The number pytest prints after a collection error is the part it reached.

    Measured on this tree: one unimportable test module and the run ends with
    "2954/2975 tests collected (21 deselected), 1 error", exit status 2. The
    first number is smaller than the truth and shaped exactly like it, so a
    reader that takes the number and drops the status writes a short count
    into the README and the post, and the badge gate then compares that count
    against itself and passes. The status is the only thing that separates a
    partial collection from a whole one.

    Three statuses, because "not the one I saw" is not the property: 2 is the
    collection error measured here, 1 is a run that collected and then failed,
    5 is a run that collected nothing. A guard written against 2 alone admits
    the other two and survives a test that only ever sends 2.
    """
    tool = _badge_tool()
    partial = "========= 2954/2975 tests collected (21 deselected), 1 error in 2.80s =========="
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0] if a else [], status, partial, ""),
    )
    with pytest.raises(AssertionError) as caught:
        tool.collected()
    assert "2954" not in str(caught.value).split("\n")[0], (
        "the failure quotes the partial count as if it were the answer"
    )
    assert f"exited {status}" in str(caught.value)


def test_a_finished_collection_of_the_same_shape_is_read(monkeypatch) -> None:
    """The guard above must reject the status, not the sentence.

    Same wording, same two numbers, exit status 0: this is what a clean run
    that deselects looks like, and it has to come back as a number.
    """
    tool = _badge_tool()
    whole = "========= 2954/2975 tests collected (21 deselected) in 2.80s =========="
    monkeypatch.setattr(
        tool.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0] if a else [], 0, whole, ""),
    )
    assert tool.collected() == 2954
