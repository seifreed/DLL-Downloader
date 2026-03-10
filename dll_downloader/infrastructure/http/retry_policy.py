"""
Retry policy for infrastructure HTTP requests.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from random import Random, SystemRandom
from time import sleep

import requests


@dataclass
class RetryPolicy:
    """Decide when HTTP transport failures should be retried."""

    max_attempts: int = 5
    retryable_status_codes: frozenset[int] = frozenset(
        {408, 425, 429, 500, 502, 503, 504}
    )
    backoff_seconds: float = 0.0
    jitter_seconds: float = 0.0
    sleep_fn: Callable[[float], None] = sleep
    rng: Random = field(default_factory=SystemRandom)

    def __post_init__(self) -> None:
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.backoff_seconds < 0:
            raise ValueError("backoff_seconds cannot be negative")
        if self.jitter_seconds < 0:
            raise ValueError("jitter_seconds cannot be negative")
    def should_retry_status(self, status_code: int, attempt: int) -> bool:
        """Return whether a response status should be retried."""
        return (
            status_code in self.retryable_status_codes
            and attempt < self.max_attempts
        )

    def should_retry_exception(
        self,
        exc: requests.RequestException,
        attempt: int,
    ) -> bool:
        """Return whether a transport exception should be retried."""
        del exc
        return attempt < self.max_attempts

    def pause_before_retry(self, attempt: int) -> None:
        """Sleep before the next attempt when backoff/jitter is configured."""
        delay = self.next_delay(attempt)
        if delay > 0:
            self.sleep_fn(delay)

    def next_delay(self, attempt: int) -> float:
        """Return the delay before the next retry attempt."""
        jitter = self.rng.uniform(0.0, self.jitter_seconds) if self.jitter_seconds else 0.0
        return max(0.0, self.backoff_seconds * attempt + jitter)
