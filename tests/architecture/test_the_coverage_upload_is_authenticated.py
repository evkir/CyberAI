"""The coverage upload has to be a measurement, not a hopeful POST.

Every pull request carried a banner asking for the Codecov app to be
installed, which is what an unauthenticated upload looks like from the other
end. The upload was also configured not to fail the job, so an upload that
never arrived produced no status, no comment and no red -- the exact shape of
a check that decides nothing, which codecov.yml already argues against in
prose.

Two things fix it and only one of them lives here. Authenticating the upload
does: the action requests an OIDC token from the workflow's own identity, the
way release.yml already publishes to PyPI, so there is no secret to rotate
and no tokenless guess. Installing the Codecov GitHub App does not -- it is
an account-level setting, it cannot be asserted from a checkout, and the note
is here because this is where the next person looks.

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

What is measured about the missing status: on bcc4282 the commit is recorded
on branch main with pullid null, pull 266 carries head null and compared_to
null, and codecov knows every branch by name. patch is computed from the diff
with the parent and arrives; project compares against a base the pull request
never got, so there is nothing to send. The uploader is therefore told which
pull request and which branch it is on rather than left to detect them, and
whether that produces the status is the open measurement, not a claim.

What that costs and what is not measured here: a pull request opened from a
fork cannot be granted id-token: write, so the upload has nothing to
authenticate with and the job fails on a contribution the contributor cannot
fix. No fork has opened one yet, so this is reasoning from the permissions
model rather than an observation. The first outside pull request is the
measurement; if it lands red for this reason, the answer is a fork-aware
condition here, not a quiet return to an upload nobody reads.
"""

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_WORKFLOWS = _ROOT / ".github" / "workflows"
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
    so the report is posted once per entry -- four times per commit today, each
    an anonymous session of the same measurement, each now declaring the same
    pull request through override_pr. Codecov merges sessions on a commit, so
    the count has never been visible from the outside and nothing here claims
    which one is decisive.

    What this pins is that the multiplicity is deliberate. An `if` narrowing
    the step to one entry, or a `flags` or `name` telling the sessions apart,
    are both reasonable answers to four identical uploads, and both change what
    the paragraph above says. This reds on the day either arrives so the
    sentence gets rewritten with the change rather than a year later.
    """
    for name, job, step in _uploads():
        combinations = (job.get("strategy") or {}).get("matrix") or {}
        assert combinations, f"{name} uploads outside any matrix; the count above is stale"
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


def test_the_upload_identifies_itself() -> None:
    """Without this the report is accepted on trust or not at all."""
    for name, job, step in _uploads():
        assert step["with"]["use_oidc"] is True, name
        assert job["permissions"]["id-token"] == "write", name


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
    pushed ref. This asserts they are supplied, not that supplying them fixes
    the status -- that is the measurement the change exists to take.
    """
    for name, _, step in _uploads():
        supplied = step["with"]
        assert "github.event.pull_request.number" in str(supplied.get("override_pr", "")), (
            f"{name} lets the uploader guess the pull request"
        )
        assert "github.head_ref" in str(supplied.get("override_branch", "")), (
            f"{name} lets the uploader guess the branch"
        )
