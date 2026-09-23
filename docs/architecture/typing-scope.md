# Typing scope

`mypy --strict` reads 104 of 172 modules in the package. The other 68 hold 275
errors and are not checked.

The scope is a list of named modules, so a module that passes strictly stays
outside it until someone says otherwise, and nothing about the module itself
announces that. cyberai/bench/environment.py spent four commits in exactly
that state: clean from its first line, never checked, invisible to the badge.
scripts/typing_scope_drift.py is what found it -- it runs the checker over the
whole package and subtracts the declared scope from what reports nothing, so a
module that could be declared and is not becomes a failing CI step rather than
a quiet omission.

Not checked is stronger than it sounds, and the boundary is the reason. Of
the 104 modules in the scope, 22 import a module outside it at module level,
and between them they reach 30 such modules. mypy follows those imports to
resolve names and does not report what it finds there: measured on 2026-09-17
by appending an unannotated function to `cyberai/core/config.py`, which was
outside the scope then and imported from inside it, running with a cold cache,
and getting `Success: no issues found in 97 source files` all the same. That
module is in the scope as of 2026-09-20, so the demonstration is dated rather
than repeatable as written; the mechanism it showed is unchanged. So a name
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

The boundary can also move inward. On 2026-09-20 `cyberai/core/config.py`
was declared, to put the provider name under the checker at the point the
environment is read. Nothing was imported or deleted, yet both crossing
counts fell -- 22 modules reaching 29 became 20 reaching 28 -- because the
modules whose only crossing was that import stopped crossing, and the file
left the reached set itself. A count that falls on an unchanged import graph
is the edge moving, not the graph; the distinction is worth stating because
the numbers alone read like imports went away.

It moves the other way just as easily. Later the same day `cyberai/__main__.py`
and `cyberai/core/model_router.py` were declared, for the two remaining places
a provider name reached the config untyped, and the counts rose to 22 reaching
31. An entry point brings its own imports to the edge with it: `__main__.py`
reaches `cli/audit_verify.py`, `cli/detector_eval.py` and `cli/scope.py`, which
nothing else in the scope touches. So the price of a module is not its error
count and not a fixed direction on these counters; it is measured per module,
before the fact, which is what the numbers here are for.

A third module went in the same day, `agents/exploit/safety_validator.py`,
whose public signature declared two implicit Optionals. Only one counter
moved: it imports nothing outside the scope, so it never was a crosser, and
reached fell from 31 to 30.

Those three moves were once summarised here as a rule -- a leaf pays one
counter, an entry point pays both. `scripts/scope_price.py` projected all 68
undeclared modules on 2026-09-23 and the summary does not survive it. The
moves fall into eleven classes, not two, and `core/cache.py` is the plainest
refutation: it imports nothing outside the scope, so by that rule it was a
leaf paying one counter, and it moves both. `agents/intel/epss_client.py` is
the only module in the scope that reaches it and reaches nothing else, so
declaring cache.py retires a crosser and a reached module at once.

What the projection shows instead is two independent sums. A candidate
enters the crosser set if it imports past the edge itself, and it removes
every module whose only crossing was to reach it; `integrations/phantom_grid.py`
removes two, which no rule about leaves permits. It adds its own targets to
the reached set and removes itself if anything already reached it;
`core/orchestrator.py` adds two while joining no crossing of its own. Because
the two sums are independent, the observed pairs run from -2 and -1 up to +1
and +5, and the largest class is neither: twenty modules move nothing at all,
costing only the errors they carry. The price of a module is therefore read
per module and before the fact, which is what the tool is for and what this
paragraph no longer claims to predict.

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

The checker is not the only version these counts depend on, and on 2026-09-18
it turned out not to be the one that mattered. A workstation carrying mcp
1.28.1 reports 284 errors where one carrying 2.0.0 reports 285: the signature
of `Server` differs between the SDK branches, and `cyberai/mcp/server.py` has
one more call-arg error against the older one. `mcp>=1.0,<3` admits both on
purpose -- the `mcp-1x` job exists to keep the 1.x surface working -- so the
manifest cannot narrow its way out of this. Both checker and SDK are therefore
declared in `[tool.cyberai.measurement]`, named here, and compared against the
installed set by the drift report, so a reader who gets a different total can
tell which of the two moved. The counts on this page were produced by mypy
1.19.1 and mcp 2.0.0. Measured the same day: mypy 1.19.1 and 1.20.2 produce
identical counts once the stubs and the SDK are held fixed, so of the three
versions the numbers ride on, the checker is the one that did not move them.

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

Six modules carry roughly a third of the 280 errors, measured 2026-09-20
with mypy 1.19.1 over the whole package. The per-module numbers move with
the checker and with the tree, so they are dated here rather than gated by
a test: a test pinning them would red on every release and teach the next
reader to delete it. `cyberai/agents/recon/async_agent.py` read 17 until
this remeasurement and reads 12 now; the drift went unnoticed because
nothing compares the table with a run.

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
