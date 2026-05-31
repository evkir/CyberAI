"""
Agent timeout enforcement with graceful fallback.
Prevents runaway agents from hanging the pipeline.
"""

import signal
import functools
from typing import Callable, Any, Optional


class AgentTimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise AgentTimeoutError("Agent exceeded time limit")


def with_timeout(seconds: int, fallback: Optional[Any] = None):
    """
    Decorator: kill agent tool call if it exceeds `seconds`.
    On timeout, returns `fallback` instead of crashing the pipeline.

    Usage:
        @with_timeout(30, fallback={"error": "timeout"})
        def run_nmap(target): ...
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Cancel alarm
                return result
            except AgentTimeoutError:
                signal.alarm(0)
                if fallback is not None:
                    return fallback
                raise

        return wrapper

    return decorator


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
