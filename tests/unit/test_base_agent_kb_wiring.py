from cyberai.core.base_agent import BaseAgent
from cyberai.core.config import CyberAIConfig
from cyberai.core.scan_session import ScanSession


class _DummyAgent(BaseAgent):
    """Concrete BaseAgent so we can exercise the real __init__ / KB wiring."""

    AGENT_NAME = "dummy"

    def _register_tools(self) -> None:  # abstract
        pass

    def run(self, target, context=None):  # abstract
        return {}


def test_first_agent_shares_empty_session_kb():
    """Empty KB is falsy (len 0); the first agent must still bind to session.kb,
    not a throwaway created by a truthiness-based fallback."""
    session = ScanSession(target="scanme.nmap.org")
    assert not session.kb and len(session.kb) == 0  # falsy precondition
    agent = _DummyAgent(CyberAIConfig(), session)
    assert agent.kb is session.kb


def test_write_by_first_agent_visible_to_second():
    """A recon-style write into an initially-empty session KB must be visible
    to a later agent reading the same session."""
    session = ScanSession(target="scanme.nmap.org")
    a1 = _DummyAgent(CyberAIConfig(), session)
    a1.kb.set("recon.nmap", {"ports": [{"port": 80}]})
    a2 = _DummyAgent(CyberAIConfig(), session)
    assert a2.kb.get("recon.nmap", {}).get("ports") == [{"port": 80}]
