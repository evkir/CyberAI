# Typing scope

`mypy --strict` reads 91 of 170 modules in the package. The other 79 hold 299
errors and are not checked. Both numbers are measured, not chosen, and they
are measured on the runner: the typecheck job prints them on every run. A
workstation can report one more, and one here does, because a single call in
`cyberai/cli/bench.py` infers differently there. The runner is what the
numbers describe.

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
checked. Nothing said so until the typecheck job grew a step that runs
`scripts/typing_scope_drift.py`: it repeats the wide run, subtracts this
scope from the modules that report nothing, and exits non-zero on what is
left. The gap is still a gap, but it can no longer widen unnoticed.

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

`scripts/typing_scope_drift.py` runs the same partition without the hazard.
It reads the flags from `[tool.mypy]` instead of repeating them, so this page
and the step cannot drift apart in what they mean by strict, and it hands the
wide run a cache directory of its own instead of purging the shared one.

## What the numbers depend on

The partition moves with the checker. Measured on mypy 1.19.1 the clean side
holds 91 modules; a later release moved it by one module in the other
direction. The dev extra therefore bounds the checker rather than naming a
floor and admitting every future release.

It also moves with the stubs that happen to be installed, and it does not
always move loudly. Two modules import yaml, and without `types-PyYAML` both
report import-untyped. `ignore_missing_imports` does not cover that case: the
package is installed and it is the stubs that are absent, so the run turns red
and the missing stubs get named.

`networkx` behaves the other way round, and that is why it was missed for a
day. It ships no `py.typed`, so without `types-networkx` it resolves to `Any`
and nothing is reported at all; with the stubs installed,
`cyberai/core/kb_graph.py` reports ten `type-arg` errors. One module, one
checker, a cold cache on both sides, and opposite verdicts depending on a
package nobody had declared. A stub whose absence is announced gets declared
on the first red run; a stub whose absence only widens a silence has to be
looked for. Both are in the dev extra now, and the gate that keeps them there
reads the declaration rather than the environment, because the job that runs
the tests installs no stubs at all.

## The unchecked side

Six modules carry roughly a third of the 299 errors:

| Module | Errors |
|---|---|
| `cyberai/core/llm_client.py` | 39 |
| `cyberai/core/orchestrator.py` | 20 |
| `cyberai/agents/recon/async_agent.py` | 12 |
| `cyberai/core/session.py` | 10 |
| `cyberai/core/kb_graph.py` | 10 |
| `cyberai/agents/report/html_renderer.py` | 9 |

Widening the scope past this point costs source changes, and each of those
modules is a separate decision rather than a batch.
