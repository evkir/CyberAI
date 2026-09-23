# Contributing to CyberAI

## Setup
git clone https://github.com/evkir/CyberAI
cd CyberAI && pip install -e ".[test,dev]"

## Tests
pytest tests/unit/ -v
pytest tests/integration/ -v

The README states how many tests the suite collects, and a gate compares
that number with a fresh collection. After adding or removing tests, let
the tool restate it instead of editing the badge by hand:

python3 scripts/tests_badge.py

The typing badge states a ratio of checked modules to package modules, and
both halves move when modules are added. It has its own tool:

python3 scripts/mypy_badge.py

Adding a module to `[tool.mypy] files` costs its own errors and moves the two
boundary counters the scope page states, sometimes in directions the module's
shape does not predict. Read the price before paying it, with the declared
flags and without editing the manifest:

python3 scripts/scope_price.py cyberai/core/cache.py

## Lint
ruff check cyberai/ --fix

## Commits
feat(scope): new feature
fix(scope): bug fix
docs: documentation
test(scope): tests

## Pull requests from a fork

The Run Tests job uploads a coverage report, and it authenticates with a
credential GitHub withholds from a workflow triggered by a pull request from
a fork. That step can go red on your pull request through nothing you did and
nothing you can change from your side. It is the upload failing, not the
contribution being rejected: say so in the pull request and the maintainer
re-runs it from a branch that carries the credential.

## Contributor License Agreement

This project requires a signed CLA before a pull request can be merged.
Read [CLA.md](CLA.md) and add this line to your pull request description:

> I have read the CLA document and I hereby sign the CLA.

One signature covers all your future pull requests. The agreement grants
the maintainer the right to relicense contributions, which keeps the door
open for commercial components without collecting consent again later.
See [docs/licensing.md](docs/licensing.md).

## Licence

Contributions are accepted under the Apache License, Version 2.0.
