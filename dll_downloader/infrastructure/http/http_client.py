"""
HTTP client adapter built on top of the shared requests transport.
"""

import logging
from collections.abc import Mapping

from ...domain.services.http_client import HTTPFileInfo
from ..http_session import HTTPSessionProtocol, HTTPSessionResource
from .request_headers import RequestHeaderBuilder
from .response_stream import (
    close_response,
    declared_content_length,
    decode_text,
    file_info_from_headers,
    read_bounded_response,
    validate_positive_size,
    validate_positive_timeout,
)
from .retry_policy import RetryPolicy
from .transport import (
    HTTP_STREAM_ERROR_TYPES,
    HTTPClientError,
    HTTPResponse,
    RequestsTransport,
)
from .user_agents import (
    FixedUserAgentProvider,
    RandomUserAgentProvider,
    UserAgentProvider,
)

logger = logging.getLogger(__name__)
__all__ = ["HTTPClientError", "HTTPResponse", "RequestsHTTPClient"]

_DEFAULT_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024  # 512 MiB
_DEFAULT_STREAM_WALL_LIMIT = 600  # 10 minutes total per streaming read


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
        max_download_bytes: int = _DEFAULT_MAX_DOWNLOAD_BYTES,
        allowed_redirect_domains: set[str] | None = None,
    ) -> None:
        timeout = validate_positive_timeout(timeout)
        max_download_bytes = validate_positive_size(max_download_bytes)
        if not isinstance(verify_ssl, bool):
            raise ValueError("verify_ssl must be a boolean")
        self._timeout = timeout
        self._max_download_bytes = max_download_bytes
        self._user_agent = user_agent
        self._verify_ssl = verify_ssl
        if not verify_ssl:
            logger.warning(
                "SSL certificate verification is disabled; "
                "HTTPS connections will be vulnerable to man-in-the-middle attacks"
            )
        self._user_agent_provider = (
            user_agent_provider or self._default_user_agent_provider(user_agent)
        )
        self._retry_policy = retry_policy or RetryPolicy(
            max_attempts=max_retries,
            backoff_seconds=retry_backoff_seconds,
            jitter_seconds=retry_jitter_seconds,
        )
        self._header_builder = RequestHeaderBuilder(self._user_agent_provider)
        self._transport = RequestsTransport(
            session_resource=session_resource
            or HTTPSessionResource(
                headers=self._header_builder.initial_session_headers()
            ),
            retry_policy=self._retry_policy,
            header_builder=self._header_builder,
            timeout=timeout,
            verify_ssl=verify_ssl,
            allowed_redirect_domains=allowed_redirect_domains,
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

    def __exit__(self, *_args: object) -> None:
        self.close()

    def get(self, url: str, headers: Mapping[str, str] | None = None) -> HTTPResponse:
        response = self._transport.execute("GET", url, headers=headers, stream=True)
        try:
            if not response.ok:
                raise HTTPClientError(
                    f"GET request failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=response.url or url,
                )
            content = read_bounded_response(
                response,
                max_bytes=self._max_download_bytes,
                wall_limit_seconds=_DEFAULT_STREAM_WALL_LIMIT,
                operation="GET response",
                url=response.url or url,
            )
            return HTTPResponse(
                status_code=response.status_code,
                content=content,
                headers=dict(response.headers),
                url=response.url,
            )
        except HTTP_STREAM_ERROR_TYPES as exc:
            raise HTTPClientError(
                f"GET response read failed: {exc}",
                status_code=response.status_code,
                url=response.url or url,
            ) from exc
        finally:
            close_response(response)

    def get_text(self, url: str, headers: Mapping[str, str] | None = None) -> str:
        response = self.get(url, headers=headers)
        return decode_text(response.content, response.headers)

    @staticmethod
    def _decode_text(content: bytes, headers: Mapping[str, str]) -> str:
        return decode_text(content, headers)

    def download(self, url: str, headers: Mapping[str, str] | None = None) -> bytes:
        response = self._transport.execute(
            "DOWNLOAD", url, headers=headers, stream=True
        )
        try:
            if not response.ok:
                raise HTTPClientError(
                    f"Download failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=url,
                )
            declared_size = declared_content_length(
                response,
                max_bytes=self._max_download_bytes,
                operation="download",
                url=url,
            )
            return read_bounded_response(
                response,
                max_bytes=self._max_download_bytes,
                wall_limit_seconds=_DEFAULT_STREAM_WALL_LIMIT,
                operation="Download",
                url=url,
                declared_size=declared_size,
            )
        except HTTP_STREAM_ERROR_TYPES as exc:
            raise HTTPClientError(
                f"Download stream failed: {exc}",
                status_code=response.status_code,
                url=response.url or url,
            ) from exc
        finally:
            close_response(response)

    def head(
        self, url: str, headers: Mapping[str, str] | None = None
    ) -> dict[str, str]:
        response = self._transport.execute(
            "HEAD", url, headers=headers, allow_redirects=True
        )
        try:
            if not getattr(response, "ok", False):
                raise HTTPClientError(
                    f"HEAD request failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=response.url if hasattr(response, "url") else url,
                )
            return dict(response.headers)
        finally:
            close_response(response)

    def get_file_info(
        self, url: str, headers: Mapping[str, str] | None = None
    ) -> HTTPFileInfo:
        return file_info_from_headers(self.head(url, headers=headers))
