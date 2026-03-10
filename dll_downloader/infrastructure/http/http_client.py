"""
HTTP client adapter built on top of the shared requests transport.
"""

from collections.abc import Mapping

from ...domain.services.http_client import HTTPFileInfo
from ..http_session import HTTPSessionProtocol, HTTPSessionResource
from .request_headers import RequestHeaderBuilder
from .retry_policy import RetryPolicy
from .transport import HTTPClientError, HTTPResponse, RequestsTransport
from .user_agents import (
    FixedUserAgentProvider,
    RandomUserAgentProvider,
    UserAgentProvider,
)

__all__ = ["HTTPClientError", "HTTPResponse", "RequestsHTTPClient"]


class RequestsHTTPClient:
    """HTTP client implementation satisfying the domain HTTP protocol."""

    DEFAULT_MAX_RETRIES = 5
    DEFAULT_USER_AGENT = RandomUserAgentProvider.DEFAULT_USER_AGENTS[0]

    def __init__(
        self,
        timeout: float = 60,
        user_agent: str | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_seconds: float = 0.0,
        retry_jitter_seconds: float = 0.0,
        verify_ssl: bool = True,
        session_resource: HTTPSessionResource | None = None,
        user_agent_provider: UserAgentProvider | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._timeout = timeout
        self._user_agent = user_agent
        self._verify_ssl = verify_ssl
        self._user_agent_provider = user_agent_provider or self._default_user_agent_provider(
            user_agent
        )
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=max_retries,
            backoff_seconds=retry_backoff_seconds,
            jitter_seconds=retry_jitter_seconds,
        )
        self._header_builder = RequestHeaderBuilder(self._user_agent_provider)
        self._transport = RequestsTransport(
            session_resource=session_resource
            or HTTPSessionResource(headers=self._header_builder.initial_session_headers()),
            retry_policy=self._retry_policy,
            header_builder=self._header_builder,
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    @staticmethod
    def _default_user_agent_provider(user_agent: str | None) -> UserAgentProvider:
        if user_agent:
            return FixedUserAgentProvider(user_agent)
        return RandomUserAgentProvider()

    @property
    def session(self) -> HTTPSessionProtocol:
        return self._transport.session

    @property
    def has_active_session(self) -> bool:
        return self._transport.has_active_session

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "RequestsHTTPClient":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        self.close()

    def get(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> HTTPResponse:
        response = self._transport.execute("GET", url, headers=headers)
        return HTTPResponse(
            status_code=response.status_code,
            content=response.content,
            headers=dict(response.headers),
            url=response.url,
        )

    def get_text(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        response = self.get(url, headers=headers)
        if not response.is_success:
            raise HTTPClientError(
                f"GET request failed with status {response.status_code}",
                status_code=response.status_code,
                url=url,
            )
        return response.content.decode("utf-8", errors="replace")

    def download(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        response = self._transport.execute("DOWNLOAD", url, headers=headers, stream=True)
        if not response.ok:
            raise HTTPClientError(
                f"Download failed with status {response.status_code}",
                status_code=response.status_code,
                url=url,
            )
        return b"".join(chunk for chunk in response.iter_content(chunk_size=8192) if chunk)

    def head(self, url: str) -> dict[str, str]:
        response = self._transport.execute("HEAD", url, allow_redirects=True)
        return dict(response.headers)

    def get_file_info(self, url: str) -> HTTPFileInfo:
        headers = self.head(url)
        content_length = headers.get("content-length")
        try:
            length_value = int(content_length) if content_length else 0
        except ValueError:
            length_value = 0
        return {
            "content_type": headers.get("content-type"),
            "content_length": length_value,
            "last_modified": headers.get("last-modified"),
            "etag": headers.get("etag"),
            "accept_ranges": headers.get("accept-ranges") == "bytes",
        }
