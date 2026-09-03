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

## Lint
ruff check cyberai/ --fix

## Commits
feat(scope): new feature
fix(scope): bug fix
docs: documentation
test(scope): tests

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
