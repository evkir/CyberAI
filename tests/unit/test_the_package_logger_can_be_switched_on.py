"""The package had calls at info and no way to hear them.

Forty-odd modules log through logging.getLogger. Nothing in the package
configured the loggers that came back, so warnings left through logging's
last resort and everything at info went nowhere: twenty-three calls, of
which fourteen report that a check was skipped rather than passed. Whether
a target was clean or never reached had no way out of the process.

These assertions pin both sides of the lever. Switching it on has to reach
a module that never had a handler of its own, and leaving it unset has to
change nothing -- a default that starts printing would be a different
defect, not a fix for this one.
"""

import logging

import pytest
from rich.logging import RichHandler

from cyberai.core.logger import configure_package_logging, console, get_logger

_SILENT = "cyberai.bench.docker"


@pytest.fixture(autouse=True)
def _restore_package_logger():
    """Undo whatever the lever did, so one test cannot configure the next."""
    package = logging.getLogger("cyberai")
    had = list(package.handlers)
    level = package.level
    yield
    package.handlers[:] = had
    package.setLevel(level)


def test_switching_it_on_reaches_a_module_that_has_no_handler_of_its_own():
    """Asserted on what came out, not on what was permitted.

    The first version of this ended at isEnabledFor, which answers for the
    level alone: a mutant that raised the level and attached no handler kept
    the whole suite green. Permission to log is not delivery, so the record
    is emitted and the handler it installed is the one read back.
    """
    assert configure_package_logging("INFO") == logging.INFO

    silent = logging.getLogger(_SILENT)
    assert not silent.handlers, "this module is supposed to own nothing"

    package = logging.getLogger("cyberai")
    attached = [h for h in package.handlers if isinstance(h, RichHandler)]
    assert attached, "the lever raised the level and attached nothing to carry the record"

    # Read the handler the lever installed, not one of our own. A sink added
    # here answers for the parent passing the record along; it says nothing
    # about whether the installed handler would have emitted it, and a mutant
    # leaving that handler at WARNING survived exactly that assertion.
    with console.capture() as captured:
        silent.info("no evaluator for class demo; treating as unsolved")

    assert "treating as unsolved" in captured.get(), (
        "the handler the lever installed did not emit the record"
    )


def test_leaving_it_unset_changes_nothing(monkeypatch):
    monkeypatch.delenv("CYBERAI_LOG_LEVEL", raising=False)
    package = logging.getLogger("cyberai")
    package.handlers[:] = []
    package.setLevel(logging.NOTSET)

    assert configure_package_logging() is None
    assert package.handlers == [], "an unset lever attached a handler"
    assert not logging.getLogger(_SILENT).isEnabledFor(logging.INFO)


def test_a_value_that_is_not_a_level_is_refused_rather_than_raised(monkeypatch):
    """A typo in a variable must not abort a scan before it starts."""
    monkeypatch.setenv("CYBERAI_LOG_LEVEL", "LOUD")
    package = logging.getLogger("cyberai")
    package.handlers[:] = []
    package.setLevel(logging.NOTSET)

    assert configure_package_logging() is None
    assert package.handlers == []


def test_a_logger_that_carries_its_own_handler_does_not_print_twice():
    """The audit logger and the orchestrator get handlers from get_logger.

    A handler on the parent would emit their records a second time, which is
    the same doubling the trail suffered from two builds of one session --
    reached here from the other direction.
    """
    own = get_logger("cyberai.audit.propagation")
    assert own.handlers, "get_logger is supposed to attach one"

    configure_package_logging("INFO")

    assert own.propagate is False, "its records would reach the parent handler too"


def test_calling_it_again_moves_the_handler_that_is_already_there():
    """The second call has to re-level, not attach a second handler.

    get_logger used to stack handlers on a repeat call and that is fixed one
    layer down, so this one attaches nothing new -- which leaves the branch
    that lowers the existing handler as the only thing standing between a
    second call and a lever that silently does nothing. A mutant emptying
    that loop survived until this input existed: no test called the lever
    twice.
    """
    configure_package_logging("WARNING")
    package = logging.getLogger("cyberai")
    before = [h for h in package.handlers if isinstance(h, RichHandler)]
    assert len(before) == 1

    configure_package_logging("DEBUG")

    after = [h for h in package.handlers if isinstance(h, RichHandler)]
    assert len(after) == 1, "a second call attached a second handler"
    assert after[0].level == logging.DEBUG, "the handler kept the level of the first call"

    with console.capture() as captured:
        logging.getLogger(_SILENT).debug("surface walk starting")

    assert "surface walk starting" in captured.get(), (
        "the second call raised nothing it could be heard through"
    )
