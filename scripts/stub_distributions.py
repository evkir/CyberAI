"""Check that the stub distributions named for the typed scope exist and ship.

The scope depends on which stub packages are installed, so the mapping from an
untyped import to the distribution that stubs it is declared rather than
sensed. Declaring it does not make it true: `types-PyYAML` was written down
next to `yaml` by hand, and nothing in the repository asked the distribution
whether it carries `yaml-stubs` at all. A typo, a distribution that stopped
shipping a module, or a rename would leave the test suite green, the checker
quietly reporting `Any`, and the scope drawn from a lie.

This runs where the dev extra is installed, which is the typecheck job. The
test suite cannot do it: the test extra carries no stubs, so every assertion
here would be red where the tests run and green where the checker runs.

The mapping lives here rather than in the test that reads it, so that a module
gains a stub distribution in one place.
"""

import sys
from importlib.metadata import PackageNotFoundError, files

# Imported modules that ship no `py.typed`, mapped to the distribution that
# supplies their stubs.
STUB_DISTRIBUTION_FOR = {
    "yaml": "types-PyYAML",
    "networkx": "types-networkx",
}


def stub_roots(distribution: str) -> set[str]:
    """Top-level `<module>-stubs` directories a distribution installs."""
    installed = files(distribution) or []
    return {
        str(path).split("/")[0] for path in installed if str(path).split("/")[0].endswith("-stubs")
    }


def main() -> int:
    problems = []
    for module, distribution in sorted(STUB_DISTRIBUTION_FOR.items()):
        try:
            roots = stub_roots(distribution)
        except PackageNotFoundError:
            problems.append(f"{distribution} is not installed, so {module} resolves to Any")
            continue
        if f"{module}-stubs" not in roots:
            problems.append(
                f"{distribution} ships {sorted(roots) or 'nothing'} and not {module}-stubs"
            )
        print(f"{module:12} <- {distribution:16} {sorted(roots)}")
    for problem in problems:
        print(f"problem: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
