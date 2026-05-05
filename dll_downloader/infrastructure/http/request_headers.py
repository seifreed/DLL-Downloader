"""
Request header construction helpers for infrastructure HTTP requests.
"""

from collections.abc import Mapping

from .user_agents import UserAgentProvider, _validate_user_agent


class RequestHeaderBuilder:
    """Build consistent headers for outgoing HTTP requests."""

    def __init__(self, user_agent_provider: UserAgentProvider) -> None:
        self._user_agent_provider = user_agent_provider

    def initial_session_headers(self) -> dict[str, str]:
        """Return default headers for a new session."""
        return {
            "User-Agent": _validate_user_agent(
                self._user_agent_provider.next_user_agent(),
                "user_agent",
            )
        }

    def build(self, headers: Mapping[str, str] | None = None) -> dict[str, str]:
        """Merge caller headers with a selected User-Agent."""
        request_headers = dict(headers) if headers else {}
        user_agent_header: str | None = None
        for header_name, header_value in request_headers.items():
            if header_name.lower() == "user-agent":
                if user_agent_header is not None:
                    raise ValueError("duplicate User-Agent header")
                request_headers[header_name] = _validate_user_agent(
                    header_value,
                    "User-Agent header",
                )
                user_agent_header = header_name
        if user_agent_header is not None:
            return request_headers
        request_headers["User-Agent"] = _validate_user_agent(
            self._user_agent_provider.next_user_agent(),
            "user_agent",
        )
        return request_headers
