"""Every field a Finding holds is a decision at the export, not an omission.

Two paths serialize a Finding. ScanSession.to_json goes through asdict() and
carries whatever the dataclass holds; export_json lists its keys by hand. A
field added to the dataclass therefore appears in one output and not the
other, and nothing goes red -- data was lost that way for the whole of the
project's life, and confidence after it.

This guard does not say the two must agree. The export is a declared contract
read by a program outside this repository: widening it is a decision, and
building it from asdict() would make every internal field a public promise
nobody agreed to. What the guard says is that the decision must be written
down. A field in the dataclass is either in the export or named below with
the reason it is not.

Both files are read as syntax trees. The names here are attributes, keys and
locals all over this tree, and a grep answers about the word.
"""

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_MODEL = _ROOT / "cyberai" / "core" / "scan_session.py"
_EXPORTER = _ROOT / "cyberai" / "agents" / "report" / "json_exporter.py"

# A field left out of the contract, and why. The reason is the point: an
# unexplained exclusion is the silent gap this guard exists to close.
_NOT_IN_THE_CONTRACT = frozenset(
    {
        # A duplicate of cve_ids[0]. __post_init__ keeps the two in sync at
        # construction and no writer in the tree appends to cve_ids afterwards
        # (measured), so the export carries the list and the consumer reads
        # the first element. Should a writer ever grow the list in place, the
        # field stops being derivable and belongs in the contract.
        "cve",
    }
)


def _finding_fields() -> set[str]:
    """The annotated fields of the Finding dataclass, from the tree."""
    tree = ast.parse(_MODEL.read_text(encoding="utf-8"))
    cls = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Finding")
    fields = {
        st.target.id
        for st in cls.body
        if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name)
    }
    assert fields, "Finding lost its fields, or stopped being a dataclass"
    return fields


def _exported_keys() -> set[str]:
    """The keys of the finding dict export_json writes, from the tree."""
    tree = ast.parse(_EXPORTER.read_text(encoding="utf-8"))
    fn = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "export_json"
    )
    for node in ast.walk(fn):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if not (isinstance(key, ast.Constant) and key.value == "findings"):
                continue
            if isinstance(value, ast.ListComp) and isinstance(value.elt, ast.Dict):
                return {
                    k.value
                    for k in value.elt.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
    raise AssertionError("no findings list comprehension found in export_json")


def test_every_field_is_either_exported_or_named_as_left_out() -> None:
    """A new field on the finding reaches the export or says why it does not."""
    unaccounted = _finding_fields() - _exported_keys() - _NOT_IN_THE_CONTRACT
    assert not unaccounted, (
        "fields on Finding that the export neither carries nor excludes "
        f"on purpose: {sorted(unaccounted)}. Add the key to export_json, or "
        "add the field to _NOT_IN_THE_CONTRACT with the reason it is derivable."
    )


def test_an_exclusion_names_a_field_that_exists() -> None:
    """An exclusion outliving its field would hide the next real omission."""
    stale = _NOT_IN_THE_CONTRACT - _finding_fields()
    assert not stale, f"excluded from the contract but gone from Finding: {sorted(stale)}"


def test_the_two_readers_are_not_reading_an_empty_tree() -> None:
    """Were either parser to return nothing, the check above would pass."""
    assert "confidence" in _finding_fields()
    assert "confidence" in _exported_keys()
