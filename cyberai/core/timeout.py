"""Default per-agent time limits.

The decorator and the SIGALRM handler that lived here were removed: nothing
imported them and nothing called them, and a signal-based timeout that no
path installs is a promise the pipeline does not keep. The table below is
read by core/async_base_agent.py, which is the whole of this module now.
"""


class AgentTimeoutManager:
    """
    Context manager for agent operation timeouts.
    Cleaner alternative to decorator for async contexts.
    """

    DEFAULT_TIMEOUTS = {
        "recon": 120,  # nmap can be slow
        "intel": 30,  # NVD API call
        "exploit": 60,  # payload generation
        "report": 90,  # PDF generation
    }

    @classmethod
    def get_timeout(cls, agent_name: str) -> int:
        return cls.DEFAULT_TIMEOUTS.get(agent_name, 60)
