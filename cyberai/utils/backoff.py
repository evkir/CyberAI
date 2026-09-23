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

    Usage:
        result = exponential_backoff(
            nvd_client.fetch_cve,
            "CVE-2024-1234",
            max_retries=5,
            exceptions=(httpx.HTTPStatusError,),
        )
    """
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
    raise last_exc
