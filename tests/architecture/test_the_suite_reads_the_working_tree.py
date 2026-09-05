"""The package the suite imports is the package in this tree.

For most of this project's life the two were the same thing and nothing had
to say so. They stopped being the same on the day the released wheel was
installed from PyPI for acceptance: pytest does not put the working directory
on sys.path -- the directory it inserts is the one holding the topmost
conftest, which is tests/ -- so `import cyberai` resolved to site-packages and
every assertion in the suite described the installed copy. The tree could
have been edited freely and the gate would have stayed green about code that
was not going to be committed.

Nothing detected that for a day. One test noticed, and only by accident: it
derived the repository root from the imported package and went looking for a
README beside it. A FileNotFoundError naming site-packages is a poor way to
learn that the suite has been measuring somebody else's code.

So the claim is made directly, here, where it reads as what it is. The
comparison is a function rather than a line inside the test, because an
assertion about the machine cannot be mutated on the machine: the function
can be checked on paths that are not this one, and the single live call is
the measurement.

Acceptance of a released wheel is still worth doing. It belongs in an
environment of its own -- a venv or pipx -- rather than in the interpreter
that runs the gate, which is the arrangement this test makes visible.
"""

import pathlib

import cyberai

_ROOT = pathlib.Path(__file__).resolve().parents[2]


def imported_from_tree(package_file: str | pathlib.Path, root: pathlib.Path) -> bool:
    """Whether the imported package's directory is the one inside root."""
    return pathlib.Path(package_file).resolve().parent == (root / "cyberai").resolve()


def test_the_suite_imports_the_package_from_this_tree() -> None:
    assert imported_from_tree(cyberai.__file__, _ROOT), (
        f"the suite imported cyberai from {pathlib.Path(cyberai.__file__).parent}, "
        f"not from {_ROOT / 'cyberai'}. Every result below describes that copy. "
        "Reinstall this checkout with pip install -e . and keep the released "
        "wheel in an environment of its own."
    )


def test_a_package_installed_elsewhere_is_rejected() -> None:
    """The comparison has to be able to say no, or it says nothing."""
    elsewhere = "/usr/lib/python3/site-packages/cyberai/__init__.py"
    assert not imported_from_tree(elsewhere, _ROOT)


def test_the_copy_in_this_tree_is_accepted() -> None:
    assert imported_from_tree(_ROOT / "cyberai" / "__init__.py", _ROOT)
