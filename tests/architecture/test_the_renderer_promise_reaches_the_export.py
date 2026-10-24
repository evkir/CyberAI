"""The renderer's promise about the export is checked against the export.

The module docstring of markdown_renderer tells the reader where the rest of
a cut value is: the JSON export, which carries evidence and data alike. That
sentence is about a different module, and nothing made the two agree. The
export listed its finding fields by hand and data was not among them for the
whole of the project's life -- the prose was written when it was true of
evidence alone, and then stayed.

A sentence naming a field in another module is a claim, not a comment. It is
read here out of the docstring rather than hard-coded, so rewording the
promise to name a third field puts that field under the same check.

The export is read as a syntax tree, not grepped: `data` is a parameter name,
a local and a key all over this tree, and a grep answers about the word.
"""

import ast
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_RENDERER = _ROOT / "cyberai" / "agents" / "report" / "markdown_renderer.py"
_EXPORTER = _ROOT / "cyberai" / "agents" / "report" / "json_exporter.py"

_KNOWN_FIELDS = ("evidence", "data", "cve_ids", "description", "target")


def _promised_fields() -> set[str]:
    """The finding fields the renderer's docstring sends the reader to."""
    tree = ast.parse(_RENDERER.read_text(encoding="utf-8"))
    doc = ast.get_docstring(tree)
    assert doc, "the renderer lost its module docstring"
    sentence = next(
        (s for s in doc.replace("\n", " ").split(".") if "JSON export" in s),
        None,
    )
    assert sentence, "the renderer no longer says where the full copy is"
    named = {f for f in _KNOWN_FIELDS if f in sentence}
    assert named, "the promise names no field at all"
    return named


def _exported_finding_keys() -> set[str]:
    """The keys of the finding dict that export_json writes, from the tree."""
    tree = ast.parse(_EXPORTER.read_text(encoding="utf-8"))
    fn = next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "export_json"
    )
    keys: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Dict):
            continue
        values = [v for v in node.values if isinstance(v, ast.Attribute)]
        if not any(v.attr in _KNOWN_FIELDS for v in values):
            continue
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
    assert keys, "no finding dict found in export_json"
    return keys


def test_every_field_the_renderer_promises_is_in_the_export() -> None:
    """A reader sent to the export for the rest of a value must find it there."""
    missing = _promised_fields() - _exported_finding_keys()
    assert not missing, f"promised in the renderer, absent from the export: {sorted(missing)}"


def test_the_promise_is_read_from_the_prose_not_assumed() -> None:
    """Were the sentence gone, the check above would pass over an empty set."""
    assert "data" in _promised_fields()
