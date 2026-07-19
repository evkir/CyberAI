"""
/api/bench/regression — compare a suite's current run against its baseline.

Both manifests are read from config.output_dir: manifest_<suite>.json is the
current run, baseline_<suite>.json is the stored baseline. The gate logic is
reused from cyberai.bench.regression_gate; this router only loads the two files
and returns the verdict. A missing current manifest is a not-found error; a
missing baseline is a pass (the current run would establish one).
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Request

from cyberai.bench.regression_gate import check_regression, load_baseline

router = APIRouter()


def _out_dir(request: Request) -> Path:
    return Path(request.app.state.config.output_dir)


@router.get("/bench/regression/{suite}")
def get_regression(suite: str, request: Request) -> dict:
    """Return the regression verdict for a suite as a GateResult dict."""
    out = _out_dir(request)
    safe = Path(suite).name
    current = load_baseline(out / f"manifest_{safe}.json")
    if current is None:
        return {"error": "current manifest not found", "suite": suite}
    baseline = load_baseline(out / f"baseline_{safe}.json")
    result = check_regression(current, baseline)
    verdict = asdict(result)
    verdict["suite"] = safe
    verdict["has_baseline"] = baseline is not None
    return verdict
