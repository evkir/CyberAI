"""A test may not feed a function an argument shape production never sends.

The class this guards was found three times in four days. A test passes a
literal — a bare host where production passes a URL, `"Vault.sol"` where
production passes a path that exists — the wrapper takes a branch that no
production call can reach, and the assertion checks the declaration rather
than the path. Every instance was green. The aderyn wrapper reported a clean
contract in every release because of it.

The body of the called function is the ground truth of the shape it needs. A
parameter that reaches `Path()`, `.exists()` or a subprocess argv needs a path
that resolves; a parameter that reaches `urlparse()` or an HTTP client needs a
scheme. The check resolves the callee through imports and receiver classes
rather than by bare name, so `get` in a test does not match `get` anywhere in
the package.

What this does not cover, measured rather than assumed: the day-36 instance
(a bare host against a URL) is invisible here, because that function compared
its parameter against strings and never touched a boundary — nothing in the
body says which shape is right. The day-38 instance (no test ever took the
HTTP branch) is a coverage property, not an argument shape. The day-36 form
is covered since day 43 by the sibling detector that reads the parameter
name instead of the body.

The blind zone is measured rather than assumed. Of the 204 arguments that
reach a parameter whose body declares a shape, 64 are string literals and
140 are not -- names, calls, one binary operation. Folding names bound to a
single string assignment in the same file recovers 7 of the 140 and finds
no new violation, which is why it is not done. Both numbers are asserted
below, so the zone cannot grow in silence.
"""

from __future__ import annotations

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]

# Attribute access that only a real path survives.
_PATH_ATTRS = frozenset(
    {
        "exists",
        "is_file",
        "is_dir",
        "read_text",
        "read_bytes",
        "iterdir",
        "glob",
        "rglob",
        "stat",
    }
)
# Receivers whose .get/.post carry a URL rather than a key.
_HTTP_RECV = ("client", "session", "httpx", "requests", "http", "transport")
_EXTS = (
    ".sol",
    ".json",
    ".txt",
    ".py",
    ".yaml",
    ".yml",
    ".md",
    ".log",
    ".xml",
    ".csv",
    ".toml",
)

# Literals a production call site cannot produce, kept with the reason they
# are allowed anyway. An entry that stops firing fails the staleness check
# below: an allowlist nobody re-earns is an allowlist nobody reads.
# Measured on this tree: 2079 calls resolved, the largest single suite
# contributing 101 of them; 64 literals and 140 blind arguments on shaped
# parameters, the largest suite contributing 32 of the blind. Each bound sits
# one suite of that size away from the measurement, so losing or doubling a
# suite does not fire it and a resolver going quiet does.
_RESOLVED_FLOOR = 1900
_LITERAL_FLOOR = 45
_BLIND_CEILING = 0.75

ALLOWED = {
    (
        "cyberai/agents/mcp_scan/mst_bridge.py::MSTBridge._parse_report",
        "out_path",
        "/no/such/file.json",
    ): "the absent file is the subject of the test, not an accident of it",
}


class _Fn:
    """A function definition plus how each parameter is consumed."""

    def __init__(self, module: str, cls: str, node: ast.AST) -> None:
        self.key = f"{module}::{cls + '.' if cls else ''}{node.name}"
        self.name = node.name
        args = node.args
        self.params = [
            p.arg for p in (args.posonlyargs + args.args) if p.arg not in ("self", "cls")
        ]
        self.ann = {
            p.arg: (ast.unparse(p.annotation) if p.annotation else "")
            for p in args.posonlyargs + args.args + args.kwonlyargs
        }
        self.use: dict[str, set[str]] = {p: set() for p in self.ann}
        self._scan(node)

    def _mark(self, name: str, kind: str) -> None:
        if name in self.use:
            self.use[name].add(kind)

    def _scan(self, node: ast.AST) -> None:
        after_call = {}
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Call):
                after_call[id(n.value)] = n.attr
        for n in ast.walk(node):
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
                if n.attr in _PATH_ATTRS:
                    self._mark(n.value.id, "PATH")
            if isinstance(n, ast.List):
                for element in n.elts:
                    if isinstance(element, ast.Name):
                        self._mark(element.id, "ARGV")
            if isinstance(n, ast.JoinedStr):
                previous = ""
                for value in n.values:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        previous = value.value
                        continue
                    if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                        # "http://{host}" carries a host, not a URL.
                        if previous.endswith(("://", "//", "/", "@", ":")):
                            self._mark(value.value.id, "HOST")
                    previous = ""
            if not isinstance(n, ast.Call):
                continue
            func = n.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "startswith"
                and isinstance(func.value, ast.Name)
                and n.args
                and "http" in ast.unparse(n.args[0])
            ):
                self._mark(func.value.id, "URL")
            called = (
                func.id
                if isinstance(func, ast.Name)
                else (func.attr if isinstance(func, ast.Attribute) else "")
            )
            receiver = ast.unparse(func.value).lower() if isinstance(func, ast.Attribute) else ""
            for arg in list(n.args) + [k.value for k in n.keywords]:
                if not isinstance(arg, ast.Name):
                    continue
                if called in {"Path", "open"}:
                    self._mark(arg.id, "PATH")
                if called == "Path" and after_call.get(id(n)) in {
                    "name",
                    "stem",
                    "suffix",
                    "parts",
                }:
                    self._mark(arg.id, "NAMEONLY")
                if called in {"urlparse", "urlsplit", "urljoin"}:
                    self._mark(arg.id, "URL")
                if called in {"exists", "isfile", "isdir", "dirname", "abspath"}:
                    self._mark(arg.id, "PATH")
                if called in {"get", "post", "put", "delete", "head", "request", "stream"} and any(
                    h in receiver for h in _HTTP_RECV
                ):
                    self._mark(arg.id, "URL")
                if called.lower() in ("argv", "cmd", "command") or called.lower().endswith(
                    ("_argv", "_cmd", "_command")
                ):
                    self._mark(arg.id, "ARGV")


def _index(root: pathlib.Path) -> tuple[dict, dict]:
    """Module-level functions and class methods of the package under `root`."""
    funcs: dict[tuple[str, str], _Fn] = {}
    classes: dict[tuple[str, str], dict[str, _Fn]] = {}
    for path in sorted((root / "cyberai").rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        module = rel[:-3].replace("/", ".").removesuffix(".__init__")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[(module, node.name)] = _Fn(rel, "", node)
            elif isinstance(node, ast.ClassDef):
                classes[(module, node.name)] = {
                    b.name: _Fn(rel, node.name, b)
                    for b in node.body
                    if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
    return funcs, classes


def _resolve(path: pathlib.Path, funcs: dict, classes: dict) -> list[tuple[_Fn, ast.Call]]:
    """Calls in one test module that reach a definition in the package.

    Resolution is by import and receiver, never by bare name: an imported
    function, a variable holding an imported class, or a variable holding what
    a local factory helper returns. The factory case is not a nicety — it hid
    four call sites of this very class until it was added.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported_fn: dict[str, _Fn] = {}
    imported_cls: dict[str, tuple[str, str]] = {}
    imported_mod: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("cyberai"):
            for alias in node.names:
                name = alias.asname or alias.name
                if (node.module, alias.name) in funcs:
                    imported_fn[name] = funcs[(node.module, alias.name)]
                if (node.module, alias.name) in classes:
                    imported_cls[name] = (node.module, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("cyberai"):
                    imported_mod[alias.asname or alias.name] = alias.name

    factory: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Return) and isinstance(inner.value, ast.Call):
                    called = inner.value.func
                    if isinstance(called, ast.Name) and called.id in imported_cls:
                        factory[node.name] = imported_cls[called.id]

    holds: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            called = node.value.func
            name = called.id if isinstance(called, ast.Name) else None
            source = imported_cls.get(name) or factory.get(name)
            if source:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        holds[target.id] = source

    out: list[tuple[_Fn, ast.Call]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in imported_fn:
            out.append((imported_fn[func.id], node))
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            receiver = func.value.id
            where = holds.get(receiver) or imported_cls.get(receiver)
            if where:
                found = classes.get(where, {}).get(func.attr)
                if found:
                    out.append((found, node))
            elif receiver in imported_mod:
                found = funcs.get((imported_mod[receiver], func.attr))
                if found:
                    out.append((found, node))
    return out


def _literals(fn: _Fn, call: ast.Call) -> list[tuple[str, str]]:
    out = []
    for i, arg in enumerate(call.args):
        if i < len(fn.params) and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            out.append((fn.params[i], arg.value))
    for keyword in call.keywords:
        if (
            keyword.arg
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            out.append((keyword.arg, keyword.value.value))
    return out


def scan(root: pathlib.Path) -> tuple[set[tuple[str, str, str]], int]:
    """Violations under `root`, and how many calls resolved on the way."""
    funcs, classes = _index(root)
    violations: set[tuple[str, str, str]] = set()
    resolved = 0
    for path in sorted((root / "tests").rglob("*.py")):
        pairs = _resolve(path, funcs, classes)
        resolved += len(pairs)
        for fn, call in pairs:
            for param, literal in _literals(fn, call):
                kinds = fn.use.get(param, set())
                if "HOST" in kinds or kinds <= {"PATH", "NAMEONLY"} and "NAMEONLY" in kinds:
                    continue
                if kinds & {"PATH", "ARGV"} or "Path" in fn.ann.get(param, ""):
                    on_disk = pathlib.Path(literal).exists() or (root / literal).exists()
                    looks_like_path = "://" not in literal and (
                        "/" in literal or literal.endswith(_EXTS)
                    )
                    if looks_like_path and not on_disk:
                        violations.add((fn.key, param, literal))
                elif "URL" in kinds and "://" not in literal and literal not in ("", "/"):
                    violations.add((fn.key, param, literal))
    return violations, resolved


def shaped_arguments(root: pathlib.Path) -> tuple[int, int]:
    """String literals and everything else reaching a shape-carrying parameter."""
    funcs, classes = _index(root)
    literals = blind = 0
    for path in sorted((root / "tests").rglob("*.py")):
        for fn, call in _resolve(path, funcs, classes):
            args = [(fn.params[i], arg) for i, arg in enumerate(call.args) if i < len(fn.params)]
            args += [(kw.arg, kw.value) for kw in call.keywords if kw.arg]
            for param, arg in args:
                if not fn.use.get(param or "", set()) & {"URL", "PATH", "ARGV", "HOST"}:
                    continue
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    literals += 1
                else:
                    blind += 1
    return literals, blind


def _plant(root: pathlib.Path) -> None:
    """A package and a suite holding one known-bad call of each shape."""
    package = root / "cyberai" / "agents"
    package.mkdir(parents=True)
    (root / "cyberai" / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    (package / "tool.py").write_text(
        "from pathlib import Path\n"
        "from urllib.parse import urlparse\n"
        "\n"
        "\n"
        "class Tool:\n"
        "    def analyze(self, target: str) -> list:\n"
        "        argv = ['tool', target]\n"
        "        return argv if Path(target).exists() else []\n"
        "\n"
        "\n"
        "def fetch(url: str) -> str:\n"
        "    return urlparse(url).netloc\n",
        encoding="utf-8",
    )
    suite = root / "tests"
    suite.mkdir()
    (suite / "test_planted.py").write_text(
        "from cyberai.agents.tool import Tool, fetch\n"
        "\n"
        "\n"
        "def _make():\n"
        "    return Tool()\n"
        "\n"
        "\n"
        "def test_path_shape():\n"
        "    tool = _make()\n"
        "    assert tool.analyze('Vault.sol') == []\n"
        "\n"
        "\n"
        "def test_url_shape():\n"
        "    assert fetch('api.acme.com') == ''\n"
        "\n"
        "\n"
        "def test_url_shape_by_keyword():\n"
        "    assert fetch(url='api.beta.com') == ''\n",
        encoding="utf-8",
    )


def test_no_test_feeds_a_shape_production_never_sends() -> None:
    violations, _ = scan(REPO)
    unexplained = {v for v in violations if v not in ALLOWED}
    assert unexplained == set(), (
        "these tests pass a literal production cannot produce; give the call "
        "the real shape, or add it to ALLOWED with the reason: " + repr(sorted(unexplained))
    )


def test_every_allowed_entry_is_still_earned() -> None:
    """An allowlist entry that no longer fires is a claim nobody re-checks."""
    violations, _ = scan(REPO)
    assert ALLOWED, "an empty allowlist makes the check above vacuous"
    stale = {key for key in ALLOWED if key not in violations}
    assert stale == set(), "remove these from ALLOWED, they no longer fire: " + repr(sorted(stale))


def test_the_walk_reaches_the_suite() -> None:
    """A resolver that resolves nothing reports nothing and looks clean."""
    _, resolved = scan(REPO)
    assert resolved >= _RESOLVED_FLOOR, (
        f"only {resolved} calls resolved — the resolver is broken, not the suite"
    )


def test_the_blind_zone_is_a_measured_share_of_the_shaped_arguments() -> None:
    """A rule reading literals only is worth what the share of literals is."""
    literals, blind = shaped_arguments(REPO)
    assert literals >= _LITERAL_FLOOR, f"only {literals} literals reach a shaped parameter"
    share = blind / (literals + blind)
    assert share <= _BLIND_CEILING, (
        f"{blind} of {literals + blind} arguments on shaped parameters are not "
        f"literals ({share:.1%}) — the rule now sees less than it is credited with"
    )


def test_a_planted_shape_of_each_kind_is_caught(tmp_path: pathlib.Path) -> None:
    """The guard is measured against known-bad input, not trusted on silence."""
    _plant(tmp_path)
    violations, resolved = scan(tmp_path)
    # analyze(...) and two fetch(...); Tool() is a constructor. The keyword call
    # is here so a walk that reads positional arguments only is a red guard.
    assert resolved == 3, resolved
    assert shaped_arguments(tmp_path) == (3, 0), shaped_arguments(tmp_path)
    assert violations == {
        ("cyberai/agents/tool.py::Tool.analyze", "target", "Vault.sol"),
        ("cyberai/agents/tool.py::fetch", "url", "api.acme.com"),
        ("cyberai/agents/tool.py::fetch", "url", "api.beta.com"),
    }
