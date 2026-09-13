"""What the SWC table leaves out of the registry, named instead of counted.

The tables here were guarded in one direction only: every name we map had to
exist in `aderyn registry`. Nothing said how much of that registry we map, so
the answer -- nineteen detectors of sixty-three -- was a number nobody held.
Grouping is by SWC id, and a detector without one is kept per-detector and can
never be cross-validated by slither, whatever its severity. On the audit of
tests/fixtures/access_control.sol the highest finding of the run,
`unprotected-initializer`, is Critical and carries no SWC: it is one of the
twelve below that hold an Immunefi tier and still group alone.

These sets are the record. A new mapping, a dropped one, or a registry that
grows under a release bump is red here and has to be re-measured, rather than
shifting the reach of cross-validation without a sound.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberai.agents.web3.immunefi_severity import ADERYN_CHECK_TO_IMMUNEFI
from cyberai.agents.web3.merge import ADERYN_DETECTOR_SWC, SLITHER_DETECTOR_SWC

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "aderyn_registry_0.1.9.json"

# Registry detectors with no SWC id, after the day-44 mapping pass.
UNMAPPED_BY_THE_SWC_TABLE = frozenset(
    {
        "avoid-abi-encode-packed",
        "boolean-equality",
        "centralization-risk",
        "constant-functions-assembly",
        "constants-instead-of-literals",
        "contract-locks-ether",
        "contract-with-todos",
        "delete-nested-mapping",
        "deprecated-oz-functions",
        "division-before-multiplication",
        "dynamic-array-length-assignment",
        "empty-block",
        "enumerable-loop-removal",
        "experimental-encoder",
        "inconsistent-type-names",
        "incorrect-caret-operator",
        "incorrect-shift-order",
        "large-numeric-literal",
        "misused-boolean",
        "msg-value-in-loop",
        "multiple-constructors",
        "nested-struct-in-mapping",
        "pre-declared-local-variable-usage",
        "public-variable-read-in-external-context",
        "push-zero-opcode",
        "redundant-statements",
        "require-with-string",
        "reused-contract-name",
        "reverts-and-requires-in-loops",
        "signed-storage-array",
        "solmate-safe-transfer-lib",
        "storage-array-edit-with-memory",
        "tautological-compare",
        "tautology-or-contradiction",
        "unindexed-events",
        "unprotected-initializer",
        "unsafe-casting-detector",
        "unsafe-oz-erc721-mint",
        "useless-error",
        "useless-internal-function",
        "useless-modifier",
        "useless-public-function",
        "yul-return",
        "zero-address-check",
    }
)

# Carry an Immunefi tier and still group per-detector, cross-validation out of
# reach for all twelve.
TIERED_WITHOUT_AN_SWC = frozenset(
    {
        "centralization-risk",
        "contract-locks-ether",
        "contract-with-todos",
        "empty-block",
        "msg-value-in-loop",
        "push-zero-opcode",
        "unindexed-events",
        "unprotected-initializer",
        "unsafe-casting-detector",
        "useless-modifier",
        "useless-public-function",
        "zero-address-check",
    }
)

# SWC ids both analyzers can reach. Only these can ever be cross-validated.
REACHED_BY_BOTH = [
    "SWC-103",
    "SWC-104",
    "SWC-105",
    "SWC-106",
    "SWC-107",
    "SWC-109",
    "SWC-112",
    "SWC-115",
    "SWC-116",
    "SWC-119",
    "SWC-120",
    "SWC-132",
]

# Reachable from aderyn alone: single-tool findings by construction.
REACHED_BY_ADERYN_ALONE = ["SWC-117", "SWC-129", "SWC-130"]


@pytest.fixture(scope="module")
def registry() -> dict[str, str]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["detectors"]


def test_the_swc_table_names_the_registry_it_leaves_out(registry):
    assert frozenset(registry) - frozenset(ADERYN_DETECTOR_SWC) == UNMAPPED_BY_THE_SWC_TABLE


def test_a_tier_does_not_buy_a_detector_an_swc(registry):
    """Severity travels; the grouping key does not. These fourteen group alone."""
    assert frozenset(ADERYN_CHECK_TO_IMMUNEFI) - frozenset(ADERYN_DETECTOR_SWC) == (
        TIERED_WITHOUT_AN_SWC
    )


def test_cross_validation_reaches_only_the_taxonomy_both_tools_share():
    aderyn = set(ADERYN_DETECTOR_SWC.values())
    slither = set(SLITHER_DETECTOR_SWC.values())
    assert sorted(aderyn & slither) == REACHED_BY_BOTH
    assert sorted(aderyn - slither) == REACHED_BY_ADERYN_ALONE
