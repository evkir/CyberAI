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
never appeared, and the reason was the checkout: at depth one Codecov cannot
resolve the merge commit a pull request is built from, so it recorded every
report on branch main and left pull 265 with compared_to null. A project
status compares against a base commit; with none resolved there was nothing
to compare and nothing to send. The depth is asserted below rather than
trusted to a comment in the workflow.

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


def test_exactly_one_job_uploads_coverage() -> None:
    """Two uploads would be two reports, and the second one would win."""
    assert len(_uploads()) == 1, [name for name, _, _ in _uploads()]


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
