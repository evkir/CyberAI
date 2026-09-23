"""
Exponential backoff with jitter for external API calls.
Handles NVD API rate limiting (429) and transient errors.
"""

import logging
import random
import time
from typing import Any, Callable, Optional, Type

logger = logging.getLogger("cyberai.utils.backoff")


def exponential_backoff(
    fn: Callable,
    *args,
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exceptions: tuple[Type[Exception], ...] = (Exception,),
    **kwargs,
) -> Any:
    """
    Retry fn(*args, **kwargs) with exponential backoff + jitter.

    Delay formula: min(base * 2^attempt + jitter, max_delay)
    Jitter: random float [0, 1) to avoid thundering herd.

    Args:
        fn:          callable to retry
        max_retries: maximum number of attempts
        base_delay:  initial delay in seconds
        max_delay:   cap on delay
        exceptions:  exception types that trigger retry

    Raises:
        ValueError:  max_retries below one. Asked for zero attempts, this
                     helper used to reach its own final raise with nothing
                     caught and fail with "exceptions must derive from
                     BaseException" -- a TypeError from the retry helper,
                     naming neither the call that failed nor the reason.
                     Zero attempts is a caller's mistake and is answered at
                     once, before any request goes out. Reading it as one
                     attempt would invent a choice nobody made.

    Usage:
        result = exponential_backoff(
            nvd_client.fetch_cve,
            "CVE-2024-1234",
            max_retries=5,
            exceptions=(httpx.HTTPStatusError,),
        )
    """
    if max_retries < 1:
        raise ValueError(f"max_retries must be at least 1, got {max_retries}")

    last_exc: Optional[Exception] = None

    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except exceptions as e:
            last_exc = e
            if attempt == max_retries - 1:
                break

            delay = min(base_delay * (2**attempt) + random.random(), max_delay)
            logger.warning(
                f"[backoff] {fn.__name__} failed (attempt {attempt + 1}/{max_retries}): "
                f"{e} — retrying in {delay:.1f}s"
            )
            time.sleep(delay)

    logger.error(f"[backoff] {fn.__name__} failed after {max_retries} attempts")
    if last_exc is None:  # pragma: no cover - unreachable while the guard stands
        # Unreachable while max_retries >= 1: the loop runs and either
        # returns or binds last_exc. The checker cannot see that, and the
        # honest way to say so is a branch that reports a broken invariant
        # rather than a type: ignore that hides one. Before the guard above
        # this line raised None and the caller read "exceptions must derive
        # from BaseException" instead of the failure that actually happened.
        raise RuntimeError(
            f"[backoff] {fn.__name__} ended with no attempt and no failure "
            f"(max_retries={max_retries})"
        )
    raise last_exc
