"""
Safety check decorators — DRY pattern for agent protection.
Extracts repeated safety logic from every agent into clean decorators.
"""

import functools
import logging
from typing import Callable

from cyberai.core.safety import AgentTrustBoundary, InputSanitizer

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


def require_scope(scope_validator):
    """
    Decorator factory: validates target is in scope before execution.

    Usage:
        @require_scope(validator)
        def scan(target: str): ...
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # First positional arg assumed to be target
            target = args[0] if args else kwargs.get("target", "")
            if not scope_validator.is_in_scope(target):
                logger.warning(f"OUT_OF_SCOPE: {target} blocked")
                return {"error": f"Target {target} is not in authorized scope"}
            return func(*args, **kwargs)

        return wrapper

    return decorator


def enforce_trust_boundary(agent_name: str):
    """
    Decorator: validate KB write permissions before agent stores results.
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(self, key: str, value, *args, **kwargs):
            AgentTrustBoundary.validate_write(agent_name, key)
            return func(self, key, value, *args, **kwargs)

        return wrapper

    return decorator


def log_agent_action(func: Callable):
    """Decorator: automatically log every agent tool call"""

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        logger.info(f"[{self.__class__.__name__}] {func.__name__} args={args[:2]}")
        result = func(self, *args, **kwargs)
        logger.info(f"[{self.__class__.__name__}] {func.__name__} → done")
        return result

    return wrapper
