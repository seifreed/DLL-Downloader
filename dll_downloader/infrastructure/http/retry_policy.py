"""
Retry policy for infrastructure HTTP requests.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from random import Random, SystemRandom
from time import sleep

import requests
from requests import exceptions as requests_exceptions

from ..validation import validate_non_negative_number

_NON_RETRYABLE_EXCEPTIONS: tuple[type[requests.RequestException], ...] = (
    requests_exceptions.InvalidSchema,
    requests_exceptions.MissingSchema,
    requests_exceptions.InvalidURL,
    requests.URLRequired,
    requests_exceptions.InvalidHeader,
    requests.TooManyRedirects,
)


_MAX_RETRY_ATTEMPTS = 100


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
        try:
            self.retryable_status_codes = frozenset(self.retryable_status_codes)
        except TypeError as exc:
            raise ValueError(
                "retryable_status_codes must contain integer HTTP status codes"
            ) from exc
        if not all(
            isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and 100 <= status_code <= 599
            for status_code in self.retryable_status_codes
        ):
            raise ValueError(
                "retryable_status_codes must contain integer HTTP status codes"
            )
        if isinstance(self.max_attempts, bool) or not isinstance(
            self.max_attempts, int
        ):
            raise ValueError("max_attempts must be a positive integer")
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.max_attempts > _MAX_RETRY_ATTEMPTS:
            raise ValueError(f"max_attempts must not exceed {_MAX_RETRY_ATTEMPTS}")
        validate_non_negative_number(self.backoff_seconds, "backoff_seconds")
        validate_non_negative_number(self.jitter_seconds, "jitter_seconds")

    def should_retry_status(self, status_code: int, attempt: int) -> bool:
        """Return whether a response status should be retried."""
        return (
            status_code in self.retryable_status_codes and attempt < self.max_attempts
        )

    def should_retry_exception(
        self,
        exc: requests.RequestException,
        attempt: int,
    ) -> bool:
        """Return whether a transport exception should be retried."""
        if isinstance(exc, _NON_RETRYABLE_EXCEPTIONS):
            return False
        return attempt < self.max_attempts

    def pause_before_retry(self, attempt: int) -> None:
        """Sleep before the next attempt when backoff/jitter is configured."""
        delay = self.next_delay(attempt)
        if delay > 0:
            self.sleep_fn(delay)

    def next_delay(self, attempt: int) -> float:
        """Return the delay before the next retry attempt."""
        jitter = (
            float(self.rng.uniform(0.0, self.jitter_seconds))
            if self.jitter_seconds
            else 0.0
        )
        backoff = max(0.0, self.backoff_seconds * (2 ** (attempt - 1)))
        capped_backoff = min(backoff, 60.0 - jitter if jitter else 60.0)
        return float(capped_backoff + jitter)
