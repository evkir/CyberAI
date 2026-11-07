"""The coverage upload has to be a measurement, not a hopeful POST.

Every pull request carried a banner asking for the Codecov app to be
installed, which is what an unauthenticated upload looks like from the other
end. The upload was also configured not to fail the job, so an upload that
never arrived produced no status, no comment and no red -- the exact shape of
a check that decides nothing, which codecov.yml already argues against in
prose.

Two things fix it and only one of them lives here. Authenticating the upload
does, and there are two means of doing it: an OIDC token minted from the
workflow's own identity, the way release.yml publishes to PyPI, or an upload
token kept as a repository secret. Installing the Codecov GitHub App does not
-- it is an account-level setting, it cannot be asserted from a checkout, and
the note is here because this is where the next person looks.

Which of the two means is in use is settled, and how it was settled is worth
keeping. OIDC was chosen in day 29 and nothing was ever found wrong with it;
what was wrong sat downstream, where the head commit of every pull request
was recorded on branch main although --branch was sent and codecov/project
arrived on none of them. Authentication was the one difference from a working
repository that had not been varied, so the token path ran once in day 34 and
moved nothing: on head 36d6f0a the upload was accepted and patch arrived, the
branch was still main, and project was absent there and on merge commit
4157df8. The means neither loses the branch nor withholds the status, so the
cause is outside this repository and the facts are complete enough to file.
OIDC is back because it rotates no secret. Both means stay allowed below,
because what the assertion there pins is the shape that carried the swap in
both directions -- the job asks for exactly what its means needs -- and not
which means won.

fail_ci_if_error is on deliberately. It means a Codecov outage reds this job
and, with the required checks on main, blocks merges until it clears. That is
the cost of the upload being load-bearing; the alternative is the state this
repository was already in, where the report was optional and therefore
ignored.

An authenticated upload can still be filed against the wrong commit. The
uploads were arriving and being accepted for a month while codecov/project
never appeared. The checkout depth was offered as the reason and was not it:
depth zero landed in day 32 and the next commit still had patch and no
project. The depth is still asserted below, because a full fetch is what
Codecov documents and that is true regardless of which guess was right.

What is measured about the missing status, and what was withdrawn: this
paragraph used to report pullid, head and compared_to as null. The Codecov
API has no such fields, so those were .get() calls on absent keys rather than
readings, and the conclusion drawn from them -- that project had no base and
so had nothing to send -- goes with them. What survives being asked with keys
that exist: codecov knows every branch by name, the uploader sends --pr and
--branch, the commit is still recorded on branch main, and the pull request
carries both base and head totals, so a base is there. patch is computed from
the diff with the parent and arrives as a check-run. Across the heads of pull
requests 258 to 267 patch appears from 261 onwards and project appears on
none of the ten, so nothing regressed here; the status has never arrived at
all. The uploader is told which pull request and which branch it is on
because that is the right thing to send, not because it produced the status.

What that costs, and what of it is measured: neither means of authenticating
survives a fork. A workflow triggered by a pull request from a fork is
granted neither id-token: write nor the repository secrets, so under either
means the upload has nothing to present and the job reds on a contribution
the contributor cannot fix. That much follows from the permissions model.

What was measured, on the day this paragraph stopped guessing: all 267 pull
requests this repository has ever had were opened from branches inside it,
and the two existing forks have opened none. So the failure has never
happened, and saying it has not is now a count rather than an impression.

The fork-aware condition this paragraph used to promise is not free: an `if`
on the upload step is exactly what the sibling test above reds on, because it
would end the one-upload-per-matrix-entry arrangement described there. Until
a fork actually opens one, the cheaper half is done instead -- CONTRIBUTING
tells the contributor what a red upload on their pull request means and that
it is not their contribution being refused, which is asserted below so the
warning cannot quietly go missing while the upload stays credentialed.
"""

import pathlib
import re

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_CONTRIBUTING = _ROOT / "CONTRIBUTING.md"
_ACTION = "codecov/codecov-action"

# v4 is the version whose tokenless uploads produce the banner. The floor is
# a version, not the pin: bumping the pin must not have to touch this file.
_MINIMUM_MAJOR = 5


def _uploads() -> list[tuple[str, dict, dict]]:
    found = []
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for job_name, job in (document.get("jobs") or {}).items():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith(_ACTION):
                    found.append((f"{workflow.name}:{job_name}", job, step))
    return found


def test_exactly_one_step_uploads_coverage() -> None:
    """A second upload step would be a second report from the same commit."""
    assert len(_uploads()) == 1, [name for name, _, _ in _uploads()]


def test_the_upload_is_repeated_by_the_matrix_and_narrowed_by_nothing() -> None:
    """One step is not one upload, and the docstring above used to imply it was.

    The uploading job runs a version matrix, and the step carries no condition,
    so the report is posted once per entry, each an anonymous session of the
    same measurement, each declaring the same pull request through override_pr.
    The paragraph that stood here said the count had never been visible from
    the outside. That was an assumption, and it was wrong: the uploads for a
    commit are their own resource, separate from its report, and reading it
    needs no credential. Measured on 2026-09-08 for head 36d6f0a and for merge
    commit 4157df8 alike -- four uploads each, every one named `CyberAI CI -
    test`, provider github-actions, state merged, flags empty. The matrix has
    four entries, so the number sent and the number stored agree, and nothing
    is being dropped on the way in.

    That agreement is what the count below pins. Widening or narrowing the
    matrix reds it, and the paragraph then has to be rewritten against a fresh
    reading rather than left stating a figure that was true once. An `if`
    narrowing the step to one entry, or a `flags` or `name` telling the
    sessions apart, are both reasonable answers to four identical uploads, and
    both change what is written here; they red it too.
    """
    for name, job, step in _uploads():
        combinations = (job.get("strategy") or {}).get("matrix") or {}
        assert combinations, f"{name} uploads outside any matrix; the count above is stale"
        assert not {"include", "exclude"} & set(combinations), (
            f"{name} shapes its matrix with include/exclude; the entry count is no "
            "longer the product of the axes and the reading above cannot be checked"
        )
        entries = 1
        for axis in combinations.values():
            entries *= len(axis)
        assert entries == 4, (
            f"{name} runs {entries} matrix entries and the paragraph above reports "
            "four uploads measured on the commit; re-read the uploads endpoint and "
            "rewrite it rather than editing this number"
        )
        assert "if" not in step, (
            f"{name} narrows the upload with a condition; it no longer runs once per "
            "matrix entry and the reasoning above needs rewriting"
        )
        for label in ("flags", "name"):
            assert label not in step["with"], (
                f"{name} distinguishes its uploads with {label}; the sessions are no "
                "longer anonymous and merging is no longer what happens"
            )


def test_the_upload_is_a_version_that_can_authenticate() -> None:
    for name, _, step in _uploads():
        ref = str(step["uses"]).split("@")[1]
        major = int(ref.lstrip("v").split(".")[0])
        assert major >= _MINIMUM_MAJOR, f"{name} pins {ref}"


def test_the_upload_identifies_itself_by_one_means_and_asks_for_that_one() -> None:
    """Without this the report is accepted on trust or not at all.

    Two means are allowed because the repository has swapped between them
    twice, and the shape that has to hold across a swap is that the job asks
    for exactly what its means needs. OIDC needs id-token: write and
    a stored token does not, so leaving the permission behind after a swap
    would be a job declaring an identity nothing reads -- which is how the
    comment in ci.yml came to describe an upload that no longer worked that
    way. Both means at once is not belt and braces either: the action would
    pick one and the file would stop saying which.
    """
    for name, job, step in _uploads():
        supplied = step["with"]
        means = [key for key in ("use_oidc", "token") if key in supplied]
        assert len(means) == 1, f"{name} authenticates by {means or 'nothing'}"
        granted = (job.get("permissions") or {}).get("id-token")
        if means == ["use_oidc"]:
            assert supplied["use_oidc"] is True, name
            assert granted == "write", f"{name} mints no token it can use"
        else:
            assert "secrets.CODECOV_TOKEN" in str(supplied["token"]), (
                f"{name} carries a token that is not the repository secret"
            )
            assert granted is None, (
                f"{name} still asks for id-token: {granted!r} with nothing reading it"
            )


def test_a_fork_pull_request_is_warned_about_where_a_contributor_reads() -> None:
    """The permissions model is not where a contributor finds this out.

    A credentialed upload that is allowed to red the job will red it on every
    fork pull request, and until this assertion existed the only place that
    said so was the docstring of this file. CONTRIBUTING is where somebody
    opening their first pull request looks, so the warning has to be there
    and has to survive an edit that quietly drops it.

    The guard is deliberate rather than decorative: an upload that cannot red
    the job, or one that presents no credential at all, does not do this to
    forks, and on the day the step becomes either of those the warning is
    stale text and this stops demanding it.
    """
    sections = _sections(_CONTRIBUTING.read_text(encoding="utf-8"))
    for name, _, step in _uploads():
        supplied = step["with"]
        credentialed = {"use_oidc", "token"} & set(supplied)
        if not credentialed or supplied.get("fail_ci_if_error") is not True:
            continue
        warned = [
            block for block in sections if "fork" in block.lower() and "coverage" in block.lower()
        ]
        assert len(warned) == 1, (
            f"{name} presents {sorted(credentialed)} and reds the job, so every fork "
            f"pull request fails on it; CONTRIBUTING carries {len(warned)} sections "
            "naming a fork and the coverage upload together, and it needs exactly one"
        )


# The warning used to be looked for in a paragraph, split on a blank line. The
# passage names the upload in its first line and the fork in its third, so a
# blank line between them left no paragraph holding both and the guard
# reported that CONTRIBUTING carries none -- about text nobody had touched.
# Measured: that edit killed this test before the section split existed. A
# section is the unit that actually carries the warning, and reflowing its
# prose does not move it.
_SECTION = re.compile(r"(?m)^(?=## )")


def _sections(text: str) -> list[str]:
    """The page cut at its own headings, so reflowing a paragraph moves nothing."""
    return [block for block in _SECTION.split(text) if block.strip()]


def test_a_reflowed_paragraph_does_not_move_the_warning() -> None:
    """A control with a known answer: the split is held off the page as well as on it."""
    page = "intro\n\n## One\nalpha\n\nbeta\n\n## Two\ngamma\n"
    assert _sections(page) == ["intro\n\n", "## One\nalpha\n\nbeta\n\n", "## Two\ngamma\n"]

    headfirst = _sections("## Only\nalpha\n")
    assert headfirst == ["## Only\nalpha\n"], headfirst


def test_a_failed_upload_is_visible() -> None:
    """An upload allowed to fail quietly is the check that decides nothing."""
    for name, _, step in _uploads():
        assert step["with"]["fail_ci_if_error"] is True, name


def test_the_uploading_job_checks_out_enough_history() -> None:
    """Depth one hides the parent, and a report with no base decides nothing.

    Zero rather than two: the documented remedy is a full fetch, and a
    shallow-but-deeper checkout would work until the day a pull request sat
    further from its base than the number written here.
    """
    for name, job, _ in _uploads():
        checkouts = [
            step
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout")
        ]
        assert checkouts, f"{name} uploads coverage without checking anything out"
        for step in checkouts:
            depth = (step.get("with") or {}).get("fetch-depth")
            assert depth == 0, f"{name} checks out at fetch-depth {depth!r}"


def test_the_upload_names_the_pull_request_and_the_branch() -> None:
    """Detected values put every report on main with no pull attached.

    The two overrides read the same facts out of the event payload: the pull
    request number, empty on a push, and the head branch falling back to the
    pushed ref. This asserts they are supplied, and that is all it ever
    asserted: the measurement it existed to take has since been taken on
    a86dc32 and the status did not appear. They stay because sending the
    pull request you are on is right on its own.
    """
    for name, _, step in _uploads():
        supplied = step["with"]
        assert "github.event.pull_request.number" in str(supplied.get("override_pr", "")), (
            f"{name} lets the uploader guess the pull request"
        )
        assert "github.head_ref" in str(supplied.get("override_branch", "")), (
            f"{name} lets the uploader guess the branch"
        )
