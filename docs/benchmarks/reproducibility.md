# Reproducibility

A benchmark number that cannot be reproduced is a press release. This page
describes what `cyberai bench run` pins, what it records, and what it does
not yet measure.

## Pinning a run

```bash
cyberai bench run --suite local --seed 1337
```

`--seed` (default 1337) seeds `random` and sets `PYTHONHASHSEED` before the
adapter loads any task. The ordering matters: `PYTHONHASHSEED` only reaches
children spawned after the call, and the engines spawn containers.

Seeding does not make a run deterministic on its own. Container start order,
network timing, and any model sampling remain sources of variance. What it
does is remove one source and record the value, so a re-run starts from the
same place.

## The run manifest

```bash
cyberai bench run --suite local --manifest runs/local.json
```

The manifest is the provenance record for one run:

| field | meaning |
| --- | --- |
| `suite` | which suite was run |
| `engine_version` | CyberAI version that produced the result |
| `config` | seed, model, provider, temperature, engine |
| `suite_hash` | SHA-256 over the identifying fields of the tasks that ran |
| `solved` / `total` | the raw score behind the rate |
| `timestamp` | when the run happened |
| `manifest_hash` | fingerprint of everything above except the timestamp |
| `environment` | every external binary the run could reach, and its version |

Three properties are deliberate.

**The manifest hash excludes the timestamp.** Two identical runs at different
times produce the same fingerprint. The time is recorded but is not part of
the run's identity.

**The suite hash covers what actually ran, not the suite as declared.** A run
narrowed with `--task` hashes differently from the full suite. Without this, a
one-task run could be compared against a three-task baseline and pass.

**The toolchain is fingerprinted by version, not by path.** Two runs that
differ only in a nuclei upgrade no longer share a fingerprint. The path each
binary was found at is recorded but left out of the hash: a path says where a
machine keeps a binary, not what the binary is, so hashing it would make a run
on a laptop incomparable with the same run on a CI runner. A binary that is
absent, and one that is present but whose version flag we have not measured,
both record a null version next to the reason -- they are different
environments and hash differently.

## The regression gate

```bash
cyberai bench run --suite local --baseline runs/local.json
```

Exit code 1 when the solve-rate dropped against the baseline, 0 otherwise.
Three cases are worth stating explicitly:

- **No baseline file** — passes. A first run has nothing to regress against
  and establishes one.
- **Suite content changed** — fails, rather than comparing anyway. A changed
  `suite_hash` means the two runs measured different things; silently
  comparing them would produce a number that looks like a regression check
  and is not one.
- **Rate held or improved** — passes. The default tolerance is zero: no drop
  is allowed.

`--baseline` stands alone. The manifest is built whenever either flag needs
it, so a CI job can gate without publishing a new manifest. The gate runs
after the manifest and scorecard are written — a regression is exactly when
those artefacts are wanted.

In CI:

```yaml
- name: Benchmark regression gate
  run: |
    cyberai bench run --suite local --engine agent \
      --manifest runs/local.json \
      --baseline runs/baseline.json
```

## What this does not measure

**Cost and token usage per run are not recorded.** The rollup type exists
(`cyberai/bench/run_budget.py`) but the engines are not instrumented to
report usage, so there is no tracker to summarise. The scorecard omits the
line rather than printing a zero: an unmeasured cost reported as `$0.00` is
worse than an absent field, because it reads as a measurement.

**Variance across repeated runs is not reported.** A single run yields a
single rate. Until repeated-run variance is published, treat a solve-rate
difference smaller than one task as noise.

**The targets themselves are not versioned.** The manifest pins the tools
that attacked, not the thing attacked. For the local suite there is no single
version to pin: the containers run a stock `python:3.12-slim` with our app
code mounted in from `cyberai/bench/apps`, so the image digest is unchanged by
an edit to the app that decides whether a task is solvable. Recording the
digest alone would be a version-shaped field that moves for the wrong reasons.
External suites pin their own images upstream.

These are open items, listed here rather than left for a reader to discover.
