"""
Tool-level decorators.

Applied to the TLS tool only. Two further decorators once lived here,
require_scope and enforce_trust_boundary; neither was ever applied, and both
were removed with the classes they called.
"""

import functools
import logging
from typing import Callable

from cyberai.core.safety import InputSanitizer, ToolInputBlocked

logger = logging.getLogger("cyberai.safety")


def sanitize_input(func: Callable):
    """Refuse a tool call whose string arguments carry an injection payload.

    Refuse, not rewrite. The decorator used to replace a flagged argument with
    a placeholder string and call the tool anyway, which turned an attack into
    a scan of a hostname nobody asked for and reported the result as if it
    described the target.

    Raising is safe for the caller that has one: AsyncBaseAgent.run_tool turns
    any exception from a tool into an error dict, so a blocked argument shows
    up as a failed tool call rather than an aborted phase.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        for value in list(args) + list(kwargs.values()):
            if not isinstance(value, str):
                continue
            verdict = InputSanitizer.inspect(value)
            if verdict["is_injection"]:
                categories = sorted({m["type"] for m in verdict["matches"]})
                logger.warning(
                    f"[{func.__qualname__}] input blocked: "
                    f"risk={verdict['risk_score']} categories={','.join(categories)}"
                )
                raise ToolInputBlocked(categories, verdict["risk_score"])
        return func(*args, **kwargs)

    return wrapper


def log_agent_action(func: Callable):
    """Decorator: automatically log every agent tool call"""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        logger.info(f"[{self.__class__.__name__}] {func.__name__} args={args[:2]}")
        result = func(self, *args, **kwargs)
        logger.info(f"[{self.__class__.__name__}] {func.__name__} → done")
        return result

    return wrapper
