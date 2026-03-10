"""
Request header construction helpers for infrastructure HTTP requests.
"""

from collections.abc import Mapping

from .user_agents import UserAgentProvider


class RequestHeaderBuilder:
    """Build consistent headers for outgoing HTTP requests."""

    def __init__(self, user_agent_provider: UserAgentProvider) -> None:
        self._user_agent_provider = user_agent_provider

    def initial_session_headers(self) -> dict[str, str]:
        """Return default headers for a new session."""
        return {"User-Agent": self._user_agent_provider.next_user_agent()}

    def build(self, headers: Mapping[str, str] | None = None) -> dict[str, str] | None:
        """Merge caller headers with a selected User-Agent."""
        request_headers = dict(headers) if headers else {}
        if "User-Agent" not in request_headers:
            request_headers["User-Agent"] = self._user_agent_provider.next_user_agent()
        return request_headers or None
