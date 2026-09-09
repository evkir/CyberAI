# Typing scope

`mypy --strict` reads 98 of 171 modules in the package. The other 73 hold 285
errors and are not checked.

Not checked is stronger than it sounds, and the boundary is the reason. Of
the 98 modules in the scope, 21 import a module outside it at module level,
and between them they reach 28 such modules. mypy follows those imports to
resolve names and does not report what it finds there: measured by appending
an unannotated function to `cyberai/core/config.py`, which is outside the
scope and imported from inside it, running with a cold cache, and getting
`Success: no issues found in 97 source files` all the same. So a name
crossing the boundary is typed by a module nothing checks, and adding a
module to the scope costs its import closure rather than its own error count
-- `mypy` on three single-error modules alone reports 90 errors across 26
files. The crossing is measured on every run by the test named below, which
reds when either count moves, so the paragraph cannot drift away from it. Both numbers are measured, not chosen, and they
are measured on the runner: the typecheck job prints them on every run.

Four modules were carried into the scope rather than found there. The call at
`cyberai/cli/bench.py` that reported `Cannot call function of unknown type`
was read for a day as a divergence between machines, and it was not one: the
two factories in `_LIVE_ENGINES` take different optional arguments, the
inferred value type of the dict is their join, and the join is `object`.
Annotating the factories' return type does not move it -- measured, the error
survives that -- and annotating the dict does. The three factory modules came
in behind it, named by the drift step once the call site stopped hiding them.

Two more arrived without being chosen. `cyberai/cli/mcp_scan.py` and
`cyberai/cli/web3_audit.py` pass `config.output_dir`, a `Path`, to a parameter
that was declared `str`; widening that declaration to what its callers pass
made both modules clean, and the drift step named them the same day. They cost
nothing to take: a cold run reports `Success` on 97 rather than 95, the error
total outside the scope is unchanged at 285, and the drift is none. The
crossing counts moved with them, from 19 modules reaching 26 to 21 reaching
28, which is the price rule the paragraph above states, paid and measured
rather than assumed.

## How the set was drawn

A single run over the whole package under `--strict --python-version 3.11
--ignore-missing-imports` partitions the package into modules that report at
least one error and modules that report none. The clean side is what
`[tool.mypy] files` lists. The scope was drawn without changing source: every
module in it passed before it was added, except the four described above,
where the source was annotated first and the partition was re-measured after.

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
if the declared set were dirty. Measured: cold cache gives `Success` on 97
modules, the same command after a full-package run gives 239 errors in 54
files, and every one of those files lies outside the scope.

`scripts/typing_scope_drift.py` runs the same partition without the hazard.
It reads the flags from `[tool.mypy]` instead of repeating them, so this page
and the step cannot drift apart in what they mean by strict, and it hands the
wide run a cache directory of its own instead of purging the shared one.

## What the numbers depend on

The partition moves with the checker. Measured on mypy 1.19.1 the clean side
holds 98 modules; a later release moved it by one module in the other
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

Six modules carry roughly a third of the 285 errors:

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
