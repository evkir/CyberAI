"""The callback address a container can actually reach.

Read from Docker rather than named. A resolvable name is not a reachable one:
`host.docker.internal` answers on hosts where it was never mapped, and the
callback then leaves for whatever answered instead of arriving here -- which
looks exactly like a target that is not vulnerable.
"""

from unittest.mock import MagicMock, patch

from cyberai.core.sandbox import bridge_gateway_host


def test_the_gateway_is_asked_of_docker_not_assumed():
    proc = MagicMock(stdout="172.17.0.1\n")
    with patch("cyberai.core.sandbox.proc.run_sealed", return_value=proc) as sealed:
        assert bridge_gateway_host() == "172.17.0.1"
    argv = sealed.call_args.args[0]
    assert argv[:3] == ["docker", "network", "inspect"]
    assert "bridge" in argv


def test_both_failure_shapes_fall_back():
    """The CLI raising, and the CLI answering nothing.

    A fallback nobody exercises is how a callback address silently becomes
    unreachable.
    """
    with patch("cyberai.core.sandbox.proc.run_sealed", side_effect=OSError("no docker")):
        assert bridge_gateway_host() == "127.0.0.1"

    with patch("cyberai.core.sandbox.proc.run_sealed", return_value=MagicMock(stdout="  \n")):
        assert bridge_gateway_host() == "127.0.0.1"


def test_the_caller_chooses_what_happens_without_docker():
    with patch("cyberai.core.sandbox.proc.run_sealed", side_effect=OSError("no docker")):
        assert bridge_gateway_host(fallback="localhost") == "localhost"
