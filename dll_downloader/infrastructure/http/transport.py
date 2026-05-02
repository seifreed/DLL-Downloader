"""
Transport primitives for HTTP adapters.
"""

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from ...domain.errors import HTTPServiceError
from ..http_session import (
    HTTPResponseProtocol,
    HTTPSessionProtocol,
    HTTPSessionResource,
)
from .request_headers import RequestHeaderBuilder
from .retry_policy import RetryPolicy

logger = logging.getLogger(__name__)


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    """Return an HTTP header value using case-insensitive field names."""
    direct_value = headers.get(name)
    if direct_value is not None:
        return direct_value

    normalized_name = name.lower()
    for header_name, header_value_text in headers.items():
        if header_name.lower() == normalized_name:
            return header_value_text
    return None


@dataclass(frozen=True)
class HTTPResponse:
    """Normalized HTTP response returned by infrastructure adapters."""

    status_code: int
    content: bytes
    headers: dict[str, str]
    url: str

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def content_length(self) -> int | None:
        length = header_value(self.headers, "content-length")
        if not length:
            return None
        try:
            return int(length)
        except ValueError:
            return None


class HTTPClientError(HTTPServiceError):
    """Exception raised for HTTP client errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        url: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(message)


HTTP_STREAM_ERROR_TYPES: tuple[type[Exception], ...] = (
    requests.RequestException,
    OSError,
)


class RequestsTransport:
    """Execute retried HTTP requests over a shared requests session."""

    def __init__(
        self,
        session_resource: HTTPSessionResource,
        retry_policy: RetryPolicy,
        header_builder: RequestHeaderBuilder,
        timeout: float,
        verify_ssl: bool,
        allowed_redirect_domains: set[str] | None = None,
    ) -> None:
        self._session_resource = session_resource
        self._retry_policy = retry_policy
        self._header_builder = header_builder
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._allowed_redirect_domains = allowed_redirect_domains

    @property
    def session(self) -> HTTPSessionProtocol:
        return self._session_resource.session

    @property
    def has_active_session(self) -> bool:
        return self._session_resource.has_session

    def close(self) -> None:
        self._session_resource.close()

    def execute(
        self,
        method_name: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        *,
        stream: bool = False,
        allow_redirects: bool = True,
    ) -> HTTPResponseProtocol:
        request_method = self._resolve_request_method(method_name)

        for attempt in range(1, self._retry_policy.max_attempts + 1):
            try:
                response = request_method(
                    url,
                    headers=self._prepare_request_headers(headers),
                    timeout=self._timeout,
                    verify=self._verify_ssl,
                    stream=stream,
                    allow_redirects=allow_redirects,
                )
            except requests.RequestException as exc:
                if attempt >= self._retry_policy.max_attempts:
                    raise self._request_error(method_name, url, exc) from exc
                if not self._retry_policy.should_retry_exception(exc, attempt):
                    raise self._request_error(method_name, url, exc) from exc
                self._log_retry_exception(method_name, url, attempt, exc)
                self._retry_policy.pause_before_retry(attempt)
                continue

            if self._retry_policy.should_retry_status(response.status_code, attempt):
                self._log_retryable_status(method_name, url, attempt, response.status_code)
                self._close_retryable_response(response)
                self._retry_policy.pause_before_retry(attempt)
                continue

            if (
                self._allowed_redirect_domains is not None
                and allow_redirects
                and hasattr(response, 'url')
                and response.url
            ):
                final_hostname = urlparse(response.url).hostname or ""
                if final_hostname and final_hostname not in self._allowed_redirect_domains:
                    self._close_retryable_response(response)
                    raise HTTPClientError(
                        f"Redirect to disallowed domain: {final_hostname}",
                        url=response.url,
                    )

            return response

        raise RuntimeError("unreachable transport retry state")

    def _resolve_request_method(
        self,
        method_name: str,
    ) -> Callable[..., HTTPResponseProtocol]:
        if method_name in {"GET", "DOWNLOAD"}:
            return self.session.get
        return self.session.head

    def _close_retryable_response(self, response: HTTPResponseProtocol) -> None:
        """Release a retryable response before issuing the next request."""
        close_response = getattr(response, "close", None)
        if not callable(close_response):
            return
        try:
            close_response()
        except HTTP_STREAM_ERROR_TYPES as exc:
            logger.warning("Failed to close retryable response: %s", exc)

    def _prepare_request_headers(
        self,
        headers: Mapping[str, str] | None,
    ) -> dict[str, str]:
        request_headers = self._header_builder.build(headers)
        if request_headers is None:
            request_headers = {}
        return request_headers

    def _request_error(
        self,
        method_name: str,
        url: str,
        error: requests.RequestException,
    ) -> HTTPClientError:
        message = f"{method_name} request failed: {error}"
        logger.error("%s for %s: %s", method_name, url, message)
        return HTTPClientError(message, url=url)

    def _log_retry_exception(
        self,
        method_name: str,
        url: str,
        attempt: int,
        error: requests.RequestException,
    ) -> None:
        logger.warning(
            "%s request failed for %s on attempt %s/%s: %s",
            method_name,
            url,
            attempt,
            self._retry_policy.max_attempts,
            error,
        )

    def _log_retryable_status(
        self,
        method_name: str,
        url: str,
        attempt: int,
        status_code: int,
    ) -> None:
        logger.warning(
            "%s request for %s returned retryable status %s on attempt %s/%s",
            method_name,
            url,
            status_code,
            attempt,
            self._retry_policy.max_attempts,
        )
