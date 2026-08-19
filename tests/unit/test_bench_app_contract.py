"""Pin the contract between the bench apps and the evaluator.

Each vulnerable app bakes in a success signal; the evaluator's probes look for
that exact signal. The two live in different modules with nothing linking them,
so a rename on one side would not fail any existing test — the probe would just
stop matching, the task would silently drop to unsolved, and pass@1 would fall
for a reason no error explains. That is the same class of drift the reflected-
input probe bugs came from.

These tests fail loudly the moment the app side and the evaluator side disagree,
at pytest time rather than during a puzzling bench run. Importing the app
modules here also exercises their module bodies (the apps otherwise run only
inside a container, invisible to coverage).
"""

from __future__ import annotations

from cyberai.bench import evaluator
from cyberai.bench.apps import cmdi_ping, path_traversal, sqli_login, ssrf_fetch
from cyberai.bench.targets import LOCAL_SUITE, VulnClass


def _target(vc: VulnClass):
    return next(t for t in LOCAL_SUITE if t.vuln_class is vc)


def test_traversal_flag_matches_evaluator():
    # The probe searches file contents for this flag; the app must serve it.
    assert evaluator._TRAVERSAL_FLAG in path_traversal.SECRET_BODY


def test_traversal_secret_lives_outside_web_root():
    # If the secret sat inside the web root it would be a normal read, not a
    # traversal — the ../ escape is the whole point.
    assert not path_traversal.SECRET_PATH.startswith(path_traversal.WEB_ROOT)


def test_sqli_flag_matches_evaluator():
    # The app hard-codes the flag in its /login handler; keep it in sync.
    import inspect

    source = inspect.getsource(sqli_login)
    assert evaluator._SQLI_FLAG in source


def test_cmdi_expected_is_the_product_of_the_expression():
    # The probe injects _CMDI_EXPR and looks for _CMDI_EXPECTED; the expected
    # value must actually be what a shell would compute (6857 * 3 = 20571).
    assert evaluator._CMDI_EXPECTED == str(6857 * 3)
    assert "6857*3" in evaluator._CMDI_EXPR.replace(" ", "")


def test_app_ports_match_the_suite():
    ports = {
        VulnClass.SQLI: sqli_login.PORT,
        VulnClass.COMMAND_INJECTION: cmdi_ping.PORT,
        VulnClass.PATH_TRAVERSAL: path_traversal.PORT,
        VulnClass.SSRF: ssrf_fetch.PORT,
    }
    # Every class in the suite must appear above. A table listing a subset
    # would let a new target drift its port undetected -- the check would pass
    # by not looking, which is how this file's own SSRF gap survived a mutant.
    assert {t.vuln_class for t in LOCAL_SUITE} == set(ports)
    for vc, app_port in ports.items():
        assert _target(vc).port == app_port, f"port drift for {vc.value}"


def test_the_ssrf_target_answers_identically_whatever_the_fetch_does():
    """The app's blindness is its contract with the evaluator.

    Every other target leaks its success into the reply. This one must not:
    the moment it reports an outcome, the response-reading walk confirms it and
    the target stops covering the out-of-band path it exists to cover.
    """
    import inspect

    source = inspect.getsource(ssrf_fetch._fetch)
    assert source.count("h.respond") == 1, "one reply, no outcome-dependent branch"
    assert "_CONSTANT_REPLY" in source


def test_the_ssrf_fetch_carries_a_timeout():
    # The bench server is single-threaded: a hanging fetch stops the target
    # answering anything else, and the run reads as a dead target.
    assert ssrf_fetch.FETCH_TIMEOUT > 0
    assert "timeout=FETCH_TIMEOUT" in __import__("inspect").getsource(ssrf_fetch._fetch)


def test_the_ssrf_app_runs_the_way_the_container_runs_it(monkeypatch):
    """The container path, not the package path.

    Inside the bench container there is no `cyberai` package -- only the apps
    directory, mounted and used as the working directory -- so the module falls
    back to a flat `_server` import and is executed as __main__. Neither line
    is reached by importing the module normally, and if either broke the target
    would simply never come up: a dead target, not an import error, which reads
    as an unexploitable one.
    """
    import runpy
    import sys
    from pathlib import Path

    apps_dir = Path(ssrf_fetch.__file__).parent
    monkeypatch.syspath_prepend(str(apps_dir))
    monkeypatch.setitem(sys.modules, "cyberai.bench.apps._server", None)

    served: list[tuple[object, int]] = []
    monkeypatch.setattr(
        "_server.serve", lambda handler, port: served.append((handler, port)), raising=False
    )

    runpy.run_path(str(apps_dir / "ssrf_fetch.py"), run_name="__main__")

    assert len(served) == 1, "the container entrypoint must start the server exactly once"
    handler, port = served[0]
    assert port == ssrf_fetch.PORT, "the standalone run must bind the suite's port"
    assert ("GET", "/fetch") in handler.routes, "the vulnerable route must be registered"
