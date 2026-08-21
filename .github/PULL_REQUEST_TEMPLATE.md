## What this changes

<!-- One paragraph. What question does this pull request close? -->

## How it was measured

<!-- Commands run and their output. A claim about behaviour needs a measurement,
     not a description. -->

## Checklist

- [ ] `ruff format --check cyberai/ tests/` and `ruff check cyberai/ tests/` pass
- [ ] `pytest -W ignore::DeprecationWarning -m "not slow and not smoke"` passes
- [ ] New behaviour is covered by a test that fails without the change
- [ ] I have read [CLA.md](../CLA.md) and I hereby sign the CLA
