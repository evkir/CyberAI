# Typing scope

`mypy --strict` reads 91 of 170 modules in the package. The other 79 hold 300
errors and are not checked. Both numbers are measured, not chosen.

## How the set was drawn

A single run over the whole package under `--strict --python-version 3.11
--ignore-missing-imports` partitions the package into modules that report at
least one error and modules that report none. The clean side is what
`[tool.mypy] files` lists. No source was changed to enlarge it: every module
in the scope already passed before it was added.

The scope mixes two forms. Five directories are clean throughout and are
listed as directories, so a module added to one of them is checked from the
moment it lands. The remaining entries are individual modules inside
directories that are not clean, and a sibling added next to them is not
checked and nothing says so. That gap is real and is not closed here.

## Reproducing it

```
rm -rf .mypy_cache
mypy --strict --python-version 3.11 --ignore-missing-imports cyberai
```

The cache purge is not decoration. A scoped run that reuses a cache left by a
wider run re-emits errors for modules outside the scope, and reports them as
if the declared set were dirty. Measured: cold cache gives `Success` on 91
modules, the same command after a full-package run gives 232 errors in 49
files, and every one of those files lies outside the scope.

## What the numbers depend on

The partition moves with the checker. Measured on mypy 1.19.1 the clean side
holds 91 modules; a later release moved it by one module in the other
direction. The dev extra therefore bounds the checker rather than naming a
floor and admitting every future release.

It also moves with the stubs that happen to be installed. Two modules import
yaml, and without `types-PyYAML` both report import-untyped and leave the
clean side. `ignore_missing_imports` does not cover that case: the package is
installed and it is the stubs that are absent. A workstation that acquired the
stubs years ago measures a wider clean set than a fresh runner, so the dev
extra names them.

## The unchecked side

Six modules carry roughly a third of the 300 errors:

| Module | Errors |
|---|---|
| `cyberai/core/llm_client.py` | 39 |
| `cyberai/core/orchestrator.py` | 20 |
| `cyberai/agents/recon/async_agent.py` | 17 |
| `cyberai/core/session.py` | 10 |
| `cyberai/core/kb_graph.py` | 10 |
| `cyberai/agents/report/html_renderer.py` | 9 |

Widening the scope past this point costs source changes, and each of those
modules is a separate decision rather than a batch.
