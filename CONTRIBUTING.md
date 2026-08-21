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
