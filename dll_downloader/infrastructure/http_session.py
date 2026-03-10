"""
Shared HTTP session resource for infrastructure adapters.
"""

from collections.abc import Iterator, MutableMapping
from typing import Any, Protocol, cast

import requests


class HTTPResponseProtocol(Protocol):
    """Structural response contract returned by the shared HTTP session."""

    status_code: int
    headers: MutableMapping[str, str]
    content: bytes
    url: str
    ok: bool

    def json(self) -> object:
        """Deserialize the response body as JSON."""

    def iter_content(self, chunk_size: int = 1) -> Iterator[bytes]:
        """Iterate over streamed response chunks."""


class HTTPSessionProtocol(Protocol):
    """Minimal HTTP session contract shared by infrastructure adapters."""

    headers: MutableMapping[str, str]

    def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
        """Perform a GET request."""

    def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
        """Perform a HEAD request."""

    def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
        """Perform a POST request."""

    def close(self) -> None:
        """Release network resources."""


class HTTPSessionResource:
    """Reusable composition-based session manager for infrastructure adapters."""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        session: HTTPSessionProtocol | None = None,
    ) -> None:
        self._session: HTTPSessionProtocol | None = session
        self._headers = headers or {}

    @property
    def session(self) -> HTTPSessionProtocol:
        """Return a lazily created configured HTTP session."""
        if self._session is None:
            session = cast(HTTPSessionProtocol, requests.Session())
            session.headers.update(self._headers)
            self._session = session
        assert self._session is not None
        return self._session

    @property
    def has_session(self) -> bool:
        """Report whether a concrete session instance is currently active."""
        return self._session is not None

    def close(self) -> None:
        """Close and discard the current session if present."""
        if self._session is not None:
            self._session.close()
            self._session = None
