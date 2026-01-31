"""
Infrastructure Base Classes

Shared base classes and mixins for infrastructure components.

Design Rationale
----------------
This module contains cross-cutting infrastructure concerns shared across
multiple infrastructure components. The use of mixins follows Python best
practices for composable behavior in infrastructure layers.

Architectural Decision: SessionMixin
------------------------------------
SessionMixin is intentionally shared between HTTP clients and API scanners
because both require identical session management behavior:
- Lazy initialization of HTTP sessions
- Context manager protocol for resource management
- Proper cleanup and connection pooling

This is NOT a violation of separation of concerns because:
1. Both consumers are in the infrastructure layer (no layer boundary crossing)
2. The coupling is on a technical cross-cutting concern, not business logic
3. The mixin provides reusable behavior without imposing inheritance hierarchies
4. Alternative (composition with SessionManager) would add unnecessary indirection

This design prioritizes pragmatism over architectural purity while maintaining
clean separation of domain concerns.
"""


import requests


class SessionMixin:
    """
    Mixin providing lazy-initialized requests session management.

    This mixin implements the shared session lifecycle pattern for any
    infrastructure component that needs to make HTTP requests. It provides:
    - Lazy session initialization (created on first use)
    - Configurable default headers via _session_headers
    - Context manager protocol for automatic cleanup
    - Explicit cleanup via close() method

    Usage:
        class MyHTTPClient(SessionMixin):
            def __init__(self):
                super().__init__()
                self._session_headers = {'User-Agent': 'MyApp/1.0'}

            def make_request(self, url: str):
                return self.session.get(url)  # Session auto-created

        with MyHTTPClient() as client:
            client.make_request('https://api.example.com')
        # Session automatically closed on context exit

    Note:
        Classes using this mixin should call super().__init__() and can
        override _session_headers after initialization if custom headers
        are needed.
    """

    def __init__(self) -> None:
        """Initialize session management attributes."""
        self._session: requests.Session | None = None
        self._session_headers: dict[str, str] = {}

    @property
    def session(self) -> requests.Session:
        """Lazy initialization of requests session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update(self._session_headers)
        return self._session

    def close(self) -> None:
        """Close the HTTP session and release resources."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> "SessionMixin":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        self.close()
