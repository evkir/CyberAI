"""Refuse to publish a commit the checks never passed.

main is protected by nine required checks. The tag that publishes to PyPI is
not protected by anything: `release.yml` fires on a tag matching v*, builds,
and uploads. A tag placed on a commit whose run went red, or whose run is
still going, reaches PyPI with nothing consulted. The strong gate guards the
way code enters and there was none on the way it leaves.

This is the missing half, and it is a script rather than a shell step because
a step in a workflow cannot be tested and this one has to be. It reads the
check runs GitHub recorded for a commit and refuses unless every job the CI
workflow defines is present and finished successfully.

The list of jobs is not written here. It is read out of the workflow, so a job
added to CI is required by the release the same day, and a job renamed cannot
silently stop being required -- the failure would be a job with no check run,
which is exactly what this reports. Matrix jobs arrive as "Run Tests (3.12)"
for a job named "Run Tests", so a check run counts for a job when it carries
the job's name followed by the matrix suffix GitHub appends.

A run that is queued or in progress is refused like a failed one. "Not
finished" is not "passed", and the tag can be pushed again once it is.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

import yaml


def job_names(workflow: pathlib.Path) -> list[str]:
    """Display names of every job the workflow defines, in file order."""
    document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
    names = []
    for key, job in (document.get("jobs") or {}).items():
        names.append(str((job or {}).get("name") or key))
    return names


def _runs_for(job: str, runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Check runs belonging to a job, matrix legs included."""
    return [run for run in runs if run["name"] == job or run["name"].startswith(f"{job} (")]


def failures(workflow: pathlib.Path, runs: list[dict[str, Any]]) -> list[str]:
    """Every reason this commit must not be published, in reporting order."""
    problems = []
    for job in job_names(workflow):
        matched = _runs_for(job, runs)
        if not matched:
            problems.append(f"{job}: no check run on this commit")
            continue
        for run in matched:
            if run.get("status") != "completed":
                problems.append(f"{run['name']}: {run.get('status')}, not finished")
            elif run.get("conclusion") != "success":
                problems.append(f"{run['name']}: {run.get('conclusion')}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=pathlib.Path, required=True)
    parser.add_argument(
        "--check-runs",
        type=pathlib.Path,
        required=True,
        help="JSON as returned by the commit check-runs endpoint",
    )
    args = parser.parse_args(argv)

    payload = json.loads(args.check_runs.read_text(encoding="utf-8"))
    runs = payload["check_runs"] if isinstance(payload, dict) else payload

    problems = failures(args.workflow, runs)
    if problems:
        print("this commit was not published because:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"every job in {args.workflow} passed on this commit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
