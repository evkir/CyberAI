"""
Tool-level decorators.

Applied to the TLS tool only. Two further decorators once lived here,
require_scope and enforce_trust_boundary; neither was ever applied, and both
were removed with the classes they called.
"""

import functools
import logging
from typing import Callable

from cyberai.core.safety import InputSanitizer

logger = logging.getLogger("cyberai.safety")


def sanitize_input(func: Callable):
    """
    Decorator: sanitize all string arguments before passing to agent tool.
    Blocks prompt injection attempts automatically.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        clean_args = [InputSanitizer.sanitize(a) if isinstance(a, str) else a for a in args]
        clean_kwargs = {
            k: InputSanitizer.sanitize(v) if isinstance(v, str) else v for k, v in kwargs.items()
        }
        return func(*clean_args, **clean_kwargs)

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
