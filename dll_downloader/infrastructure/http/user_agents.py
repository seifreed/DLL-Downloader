"""
User-Agent rotation helpers for HTTP infrastructure.
"""

from collections.abc import Sequence
from random import Random, SystemRandom
from typing import Protocol


class UserAgentProvider(Protocol):
    """Return the next User-Agent string for an outgoing request."""

    def next_user_agent(self) -> str:
        """Select the next User-Agent."""


class FixedUserAgentProvider:
    """Always return the same configured User-Agent."""

    def __init__(self, user_agent: str) -> None:
        self._user_agent = user_agent

    def next_user_agent(self) -> str:
        return self._user_agent


class RandomUserAgentProvider:
    """Select a User-Agent at random from a fixed, trusted pool."""

    DEFAULT_USER_AGENTS: tuple[str, ...] = (
        "Mozilla/5.0 (Linux; Android 15; CPH2641 Build/AP3A.240617.008) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.120 "
        "Mobile Safari/537.36 OPX/2.6",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/134.0.7188.88 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 "
        "OPR/126.0.0.0 (Edition Yx 05),gzip(gfe)",
        "Mozilla/5.0 (Linux; Android 12; DBR-W10 Build/HUAWEIDBR-W10) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 "
        "Chrome/114.0.5735.196 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "GSA/411.0.879111500 Mobile/15E148 Safari/604.1",
    )

    def __init__(
        self,
        user_agents: Sequence[str] | None = None,
        rng: Random | None = None,
    ) -> None:
        self._user_agents = (
            tuple(self.DEFAULT_USER_AGENTS)
            if user_agents is None
            else tuple(user_agents)
        )
        if not self._user_agents:
            raise ValueError("user_agents must contain at least one value")
        self._rng = rng or SystemRandom()

    @property
    def pool(self) -> tuple[str, ...]:
        """Expose the configured User-Agent pool for verification."""
        return self._user_agents

    def next_user_agent(self) -> str:
        return self._rng.choice(self._user_agents)
