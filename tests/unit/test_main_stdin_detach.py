"""Terminal-safety: the scan CLI must detach stdin so subprocess children
(nmap runtime interaction, whois, ...) never leave the tty in raw/no-echo."""

from unittest.mock import patch

import cyberai.__main__ as m


def test_detach_stdin_points_fd0_at_devnull():
    with (
        patch.object(m.os, "open", return_value=7) as m_open,
        patch.object(m.os, "dup2") as m_dup2,
        patch.object(m.os, "close") as m_close,
    ):
        m._detach_stdin_from_tty()

    m_open.assert_called_once_with(m.os.devnull, m.os.O_RDONLY)
    m_dup2.assert_called_once_with(7, 0)
    m_close.assert_called_once_with(7)


def test_detach_stdin_swallows_oserror():
    """A closed/edge-case stdin must never crash the scan."""
    with patch.object(m.os, "open", side_effect=OSError("no fd")):
        m._detach_stdin_from_tty()  # must not raise
