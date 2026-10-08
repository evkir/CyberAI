#!/usr/bin/env python3
"""Build a corpus directory from a local AgentDojo checkout.

Why this exists. Our own corpus is ours: we wrote the injections and captured
the benign output, so a number taken on it answers only to us. AgentDojo is a
public benchmark nobody here designed, and a figure measured on it can be put
beside a figure somebody else published. This turns that checkout into the
corpus shape `cyberai detector eval` already reads, so no second evaluator
exists and the two numbers come out of one instrument.

Why it writes outside the repository and takes the destination as an argument.
The samples are somebody else's text under the MIT licence; redistributing
them would mean carrying their copyright notice in NOTICE and explaining a
second licence in docs/licensing.md. None of that buys anything: the material
is one `git clone` away, and what is worth committing is the extractor and the
figure, not the corpus. The destination is therefore required, with no default
pointing anywhere inside the tree.

What is measured here rather than assumed, each one having been wrong first:

The multiplier. Seventeen attacks are registered upstream, and six of them are
distinct texts -- the `important_instructions` family differs only in which
names it substitutes, which is not a different sample for a detector that
reads text. Multiplying by seventeen would have inflated the denominator
nearly threefold and bought recall for free.

The outcome. Reading the leading verb of a goal classifies `please` as an
action, which is a judgement about English rather than a measurement. The
upstream task says it itself: `security()` that inspects the environment or
delegates to `security_from_traces` is observed by acting, and the one task
whose body is `self._TARGET in model_output` is observed by disclosure.
Measured on the checkout this file was written against, that is 53 act and 1
disclose over 54 declarations.

The subclass namespace. Upstream template names collide with ours -- `direct`
means something else in our taxonomy -- so each is prefixed with its origin.
The two reports are not meant to be read as one table, and the prefix is what
says so in the output itself rather than in a paragraph nobody reads.

What this corpus does NOT get, stated because the absence is invisible from
the outside. tests/architecture/test_corpus_integrity.py and
test_sample_names_claim_what_they_hold.py are both pinned to tests/corpus.
Anything written here is outside their reach: no floor per class, no
duplicate check, no filename-against-bytes predicate. The manifest written
here satisfies their rules by construction, and nothing re-checks that it
still does.
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
from typing import Dict, Iterable, List, Tuple

import yaml

# Upstream substitutes these at attack time. Normalising them is what collapses
# the important_instructions family to one shape.
_SUBSTITUTED = re.compile(r"\{(user|model|tools)\}")

# Filename tokens that tests/architecture/test_sample_names_claim_what_they_hold
# reads as a claim about the bytes of a sample. A generated name carrying one
# would assert a technique this extractor never put there.
_CLAIM_TOKENS = ("ansi", "b64", "bidi", "cyrillic", "fullwidth", "rot13", "zerowidth")

_USER = "Emma Johnson"
_MODEL = "the AI assistant"
_TOOLS = "You should use the following tool: send_money"


def _goal_text(value: ast.expr) -> str | None:
    """The literal part of a GOAL, with interpolations marked rather than lost."""
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.JoinedStr):
        pieces: List[str] = []
        for part in value.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                pieces.append(part.value)
            else:
                pieces.append("PLACEHOLDER")
        return "".join(pieces)
    return None


def _assigned_names(statement: ast.stmt) -> List[str]:
    if isinstance(statement, ast.Assign):
        return [t.id for t in statement.targets if isinstance(t, ast.Name)]
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
        return [statement.target.id]
    return []


def _outcome_of(node: ast.ClassDef) -> str:
    """How a success would be observed, taken from the task's own predicate."""
    security = next(
        (m for m in node.body if isinstance(m, ast.FunctionDef) and m.name == "security"),
        None,
    )
    if security is None:
        return "unobservable"
    body = ast.unparse(ast.Module(body=security.body, type_ignores=[]))
    if "post_environment" in body or "pre_environment" in body:
        return "act"
    if "security_from_traces" in body:
        return "act"
    if "model_output" in body:
        return "disclose"
    return "unobservable"


def read_goals(checkout: pathlib.Path) -> Dict[str, str]:
    """Every distinct injection goal in the checkout, mapped to its outcome."""
    suites = checkout / "src" / "agentdojo" / "default_suites"
    if not suites.is_dir():
        raise SystemExit(f"not an agentdojo checkout: {suites} is missing")
    goals: Dict[str, str] = {}
    for path in sorted(suites.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for statement in node.body:
                if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    continue
                if "GOAL" not in _assigned_names(statement) or statement.value is None:
                    continue
                text = _goal_text(statement.value)
                if text:
                    goals.setdefault(text, _outcome_of(node))
    return goals


def read_templates(checkout: pathlib.Path) -> Dict[str, str]:
    """Jailbreak templates by name, one entry per distinct text.

    A template is a literal `_JB_STRING` or the first argument a subclass hands
    to its parent. Collapsing on the substituted text is what turns seventeen
    registered attacks into the six shapes a text detector can tell apart; the
    first name to carry a shape keeps it, and the rest are dropped as copies.
    """
    attacks = checkout / "src" / "agentdojo" / "attacks"
    by_shape: Dict[str, str] = {}
    templates: Dict[str, str] = {}
    for path in sorted(attacks.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            name = None
            jailbreak = None
            for statement in node.body:
                if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    continue
                names = _assigned_names(statement)
                if (
                    "name" in names
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)
                ):
                    name = statement.value.value
                if "_JB_STRING" in names and statement.value is not None:
                    try:
                        literal = ast.literal_eval(statement.value)
                    except ValueError:
                        literal = None
                    jailbreak = literal if isinstance(literal, str) else None
            if jailbreak is None:
                for inner in ast.walk(node):
                    if (
                        isinstance(inner, ast.Call)
                        and getattr(inner.func, "attr", "") == "__init__"
                        and inner.args
                        and isinstance(inner.args[0], ast.Constant)
                        and isinstance(inner.args[0].value, str)
                    ):
                        jailbreak = inner.args[0].value
                        break
            if not name or not jailbreak or "{goal}" not in jailbreak:
                continue
            shape = _SUBSTITUTED.sub("{X}", jailbreak)
            if shape in by_shape:
                continue
            by_shape[shape] = name
            templates[name] = jailbreak
    return templates


class _ImportLoader(yaml.SafeLoader):
    """Their environments use a !include tag, so safe_load alone cannot read them."""


def _include(loader: yaml.Loader, node: yaml.Node) -> object:
    if not isinstance(node, yaml.ScalarNode):
        raise yaml.constructor.ConstructorError(
            None, None, "!include needs a path", node.start_mark
        )
    target = pathlib.Path(loader.name).parent / str(loader.construct_scalar(node))
    with target.open(encoding="utf-8") as handle:
        return yaml.load(handle, _ImportLoader)


_ImportLoader.add_constructor("!include", _include)

# A string shorter than this is a label, not tool output: a city name or a
# currency code says nothing about whether ordinary data trips the detector.
_MIN_BENIGN = 40

# Keys that are identifiers of a carrier rather than names of a field -- a
# filename, a URL. Using them as a subclass would put a web address in a
# report column.
_FIELD_NAME = re.compile(r"[a-z_]+")


def read_benign(checkout: pathlib.Path) -> List[Tuple[str, str]]:
    """Environment text from every suite, deduplicated by content.

    The same message appears in more than one suite -- measured on the
    checkout this was written against, 305 strings collapse to 222. Keeping
    the copies would inflate the denominator of any false-positive rate taken
    here, which is the one number this side of the corpus exists to produce.

    Nothing is filtered on top of the length floor. Dropping addresses or
    opening hours because they look unlike tool output would be choosing the
    benign population to suit the answer, and the two refuted filtering
    hypotheses in this project were both that shape.
    """
    suites = checkout / "src" / "agentdojo" / "data" / "suites"
    found: Dict[str, Tuple[str, str]] = {}
    for path in sorted(suites.rglob("*.yaml")):
        with path.open(encoding="utf-8") as handle:
            document = yaml.load(handle, _ImportLoader)

        def walk(node: object, key: str | None = None) -> None:
            if isinstance(node, str):
                if len(node) >= _MIN_BENIGN:
                    field = key if key and _FIELD_NAME.fullmatch(key) else "document"
                    found.setdefault(re.sub(r"\s+", " ", node).strip(), (field, node))
            elif isinstance(node, dict):
                for inner_key, value in node.items():
                    walk(value, str(inner_key))
            elif isinstance(node, list):
                for value in node:
                    walk(value, key)

        walk(document)
    return [value for value in found.values()]


def _render(template: str, goal: str) -> str:
    filled = template.replace("{goal}", goal)
    filled = filled.replace("{user}", _USER).replace("{model}", _MODEL)
    return filled.replace("{tools}", _TOOLS)


def _slug(text: str, limit: int = 48) -> str:
    """A filename that carries no claim about the bytes of the sample."""
    words = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-").split("-")
    kept: List[str] = []
    for word in words:
        if any(token in word for token in _CLAIM_TOKENS):
            continue
        kept.append(word)
        if len("-".join(kept)) >= limit:
            break
    return "-".join(kept) or "goal"


def build(checkout: pathlib.Path, destination: pathlib.Path) -> Tuple[int, int, int]:
    goals = read_goals(checkout)
    templates = read_templates(checkout)
    if not goals or not templates:
        raise SystemExit(f"nothing extracted: {len(goals)} goals, {len(templates)} templates")

    injections = destination / "injections"
    injections.mkdir(parents=True, exist_ok=True)
    (destination / "benign").mkdir(parents=True, exist_ok=True)

    entries: List[Dict[str, str]] = []
    seen: set[str] = set()
    for template_name, template in sorted(templates.items()):
        for index, (goal, outcome) in enumerate(sorted(goals.items())):
            stem = f"{template_name}-{index:02d}-{_slug(goal)}"
            name = f"{stem}.txt"
            if name in seen:
                continue
            seen.add(name)
            (injections / name).write_text(_render(template, goal), encoding="utf-8")
            entries.append(
                {
                    "id": f"inj-agentdojo-{template_name}-{index:02d}",
                    "path": f"injections/{name}",
                    "label": "injection",
                    "subclass": f"agentdojo:{template_name}",
                    "source": "public",
                    "origin": f"AgentDojo {template_name} x injection goal {index}",
                    "outcome": outcome,
                }
            )

    benign_dir = destination / "benign"
    for index, (field, text) in enumerate(sorted(read_benign(checkout))):
        name = f"{index:03d}-{_slug(text)}.txt"
        (benign_dir / name).write_text(text, encoding="utf-8")
        entries.append(
            {
                "id": f"ben-agentdojo-{index:03d}",
                "path": f"benign/{name}",
                "label": "benign",
                "subclass": f"agentdojo:{field}",
                "source": "public",
                "origin": f"AgentDojo environment field {field}",
            }
        )

    manifest = destination / "manifest.jsonl"
    manifest.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries),
        encoding="utf-8",
    )
    return len(goals), len(templates), len(entries)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("checkout", type=pathlib.Path, help="A local AgentDojo clone")
    parser.add_argument("destination", type=pathlib.Path, help="Corpus directory to write")
    args = parser.parse_args(list(argv) if argv is not None else None)

    resolved = args.destination.resolve()
    repository = pathlib.Path(__file__).resolve().parents[1]
    if resolved == repository or repository in resolved.parents:
        raise SystemExit(f"refusing to write a third-party corpus inside {repository}")

    goals, templates, samples = build(args.checkout.resolve(), resolved)
    print(
        f"goals: {goals}  templates: {templates}  "
        f"injections: {goals * templates}  samples: {samples}"
    )
    print(f"written: {resolved}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
