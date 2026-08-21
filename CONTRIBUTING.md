# Contributing to CyberAI

## Setup
git clone https://github.com/evkir/CyberAI
cd CyberAI && pip install -e ".[test,dev]"

## Tests
pytest tests/unit/ -v
pytest tests/integration/ -v

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
