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
from ..net import hostname_resolves_to_private_ip, strip_url_credentials
from .request_headers import RequestHeaderBuilder
from .retry_policy import RetryPolicy

_MAX_REDIRECT_HOPS = 10
_MAX_LOCATION_HEADER_LENGTH = 8192


logger = logging.getLogger(__name__)


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    """Return an HTTP header value using case-insensitive field names.

    Per RFC 7230, multiple headers with the same field name are
    combined with comma separators. Returns the first value found
    when headers use different casing for the same logical name.
    """
    normalized_name = name.lower()
    values: list[str] = []
    for header_name, header_value_text in headers.items():
        if header_name.lower() == normalized_name:
            values.append(header_value_text)
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    return ", ".join(values)


class _FrozenHeaders(dict[str, str]):
    def __init__(self, headers: Mapping[str, str]) -> None:
        super().__init__(headers)

    def __setitem__(self, key: str, value: str) -> None:
        raise TypeError("HTTPResponse headers are immutable")

    def __delitem__(self, key: str) -> None:
        raise TypeError("HTTPResponse headers are immutable")

    def clear(self) -> None:
        raise TypeError("HTTPResponse headers are immutable")

    def pop(self, key: str, default: object = None) -> object:  # type: ignore[override]
        raise TypeError("HTTPResponse headers are immutable")

    def popitem(self) -> tuple[str, str]:
        raise TypeError("HTTPResponse headers are immutable")

    def setdefault(self, key: str, default: str = "") -> str:
        raise TypeError("HTTPResponse headers are immutable")

    def update(self, *args: object, **kwargs: str) -> None:
        raise TypeError("HTTPResponse headers are immutable")

    def __ior__(self, value: object) -> "_FrozenHeaders":  # type: ignore[misc,override]
        raise TypeError("HTTPResponse headers are immutable")


@dataclass(frozen=True)
class HTTPResponse:
    """Normalized HTTP response returned by infrastructure adapters."""

    status_code: int
    content: bytes
    headers: dict[str, str]
    url: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", _FrozenHeaders(self.headers))

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400 and "location" in {
            k.lower(): v for k, v in self.headers.items()
        }

    @property
    def content_length(self) -> int | None:
        length = header_value(self.headers, "content-length")
        if not length:
            return None
        try:
            parsed_length = int(length)
        except ValueError:
            return None
        return parsed_length if parsed_length >= 0 else None


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
        self._allowed_redirect_domains = (
            frozenset(allowed_redirect_domains)
            if allowed_redirect_domains is not None
            else None
        )

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
        if not allow_redirects:
            return self._single_request(
                method_name,
                url,
                headers,
                stream=stream,
                allow_redirects=False,
            )

        # Follow redirects manually so every hop is validated for SSRF.
        current_url = url
        visited_urls: set[str] = set()
        for _hop in range(_MAX_REDIRECT_HOPS):
            if current_url in visited_urls:
                raise HTTPClientError(
                    f"Redirect cycle detected: {current_url}",
                    url=url,
                )
            visited_urls.add(current_url)
            parsed_target = urlparse(current_url)
            target_hostname = parsed_target.hostname
            # Always check for private IP resolution. When an explicit domain
            # allowlist is configured, allow private IPs only for allowlisted hosts.
            is_allowlisted = (
                self._allowed_redirect_domains is not None
                and target_hostname in self._allowed_redirect_domains
            )
            if (
                target_hostname
                and hostname_resolves_to_private_ip(target_hostname)
                and not is_allowlisted
            ):
                raise HTTPClientError(
                    f"Request to {target_hostname} rejected: "
                    "resolves to private/reserved address",
                    url=current_url,
                )
            if (
                self._allowed_redirect_domains is not None
                and target_hostname
                and target_hostname not in self._allowed_redirect_domains
            ):
                raise HTTPClientError(
                    f"Redirect to disallowed domain: {target_hostname}",
                    url=current_url,
                )
            response = self._single_request(
                method_name,
                current_url,
                headers,
                stream=stream,
                allow_redirects=False,
            )
            if not response.is_redirect:
                return response
            try:
                redirect_url = self._resolve_redirect(current_url, response)
            finally:
                self._close_retryable_response(response)
            current_url = redirect_url
        raise HTTPClientError(
            f"Too many redirects (> {_MAX_REDIRECT_HOPS})",
            url=url,
        )

    def _single_request(
        self,
        method_name: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        *,
        stream: bool = False,
        allow_redirects: bool = True,
    ) -> HTTPResponseProtocol:
        """Execute a single HTTP request with retry logic (no redirect following)."""
        # Check domain allowlist once (URL does not change across retries).
        if self._allowed_redirect_domains is not None:
            parsed = urlparse(url)
            if (
                parsed.hostname
                and parsed.hostname not in self._allowed_redirect_domains
            ):
                raise HTTPClientError(
                    f"Request to disallowed domain: {parsed.hostname}",
                    url=url,
                )
        request_method = self._resolve_request_method(method_name)

        for attempt in range(1, self._retry_policy.max_attempts + 1):
            # Per-request DNS rebinding check: resolve the target hostname
            # immediately before connecting to avoid TOCTOU with config-time validation.
            self._validate_single_request_target(url)
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

            if self._status_should_retry(response.status_code, attempt):
                self._log_retryable_status(
                    method_name, url, attempt, response.status_code
                )
                self._close_retryable_response(response)
                self._retry_policy.pause_before_retry(attempt)
                continue

            if not getattr(response, "ok", False) and method_name == "HEAD":
                self._close_retryable_response(response)
                raise HTTPClientError(
                    f"{method_name} request failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=response.url or url,
                )

            return response

        raise HTTPClientError(
            f"{method_name} request failed: no successful response",
            url=url,
        )

    def _validate_single_request_target(self, url: str) -> None:
        parsed_target = urlparse(url)
        if parsed_target.scheme.lower() not in {"http", "https"}:
            raise HTTPClientError(
                f"Request to non-HTTP scheme rejected: {url}",
                url=url,
            )
        target_hostname = parsed_target.hostname
        if target_hostname is None:
            raise HTTPClientError(
                "Request to URL without hostname rejected",
                url=url,
            )
        try:
            _ = parsed_target.port
        except ValueError as exc:
            raise HTTPClientError(
                f"Request URL has invalid port: {url}",
                url=url,
            ) from exc
        if parsed_target.username is not None or parsed_target.password is not None:
            raise HTTPClientError(
                "Request URL credentials rejected",
                url=url,
            )
        is_allowlisted = (
            self._allowed_redirect_domains is not None
            and target_hostname in self._allowed_redirect_domains
        )
        if (
            target_hostname
            and hostname_resolves_to_private_ip(target_hostname)
            and not is_allowlisted
        ):
            raise HTTPClientError(
                f"Request to {target_hostname} rejected: "
                "resolves to private/reserved address",
                url=url,
            )

    def _status_should_retry(self, status_code: int, attempt: int) -> bool:
        return (
            status_code in self._retry_policy.retryable_status_codes
            and attempt < self._retry_policy.max_attempts
        )

    def _resolve_request_method(
        self,
        method_name: str,
    ) -> Callable[..., HTTPResponseProtocol]:
        if method_name == "GET" or method_name == "DOWNLOAD":
            return self.session.get
        if method_name == "HEAD":
            return self.session.head
        raise HTTPClientError(f"Unknown HTTP method: {method_name}", url="")

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
        logger.error("%s for %s: %s", method_name, url, error)
        return HTTPClientError(f"{method_name} request failed", url=url)

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

    @staticmethod
    def _resolve_redirect(original_url: str, response: HTTPResponseProtocol) -> str:
        """Compute the absolute redirect URL from a 3xx response."""
        from urllib.parse import urljoin

        location = header_value(response.headers, "location") or ""
        if not location:
            raise HTTPClientError(
                "Redirect response missing Location header",
                url=original_url,
            )
        if len(location) > _MAX_LOCATION_HEADER_LENGTH:
            raise HTTPClientError(
                f"Redirect Location header exceeds {_MAX_LOCATION_HEADER_LENGTH} bytes",
                url=original_url,
            )
        location = location.strip()
        location_lower = location.lower()
        original_url_lower = original_url.lower()
        if location_lower.startswith(("http://", "https://")):
            if original_url_lower.startswith("https://") and location_lower.startswith(
                "http://"
            ):
                raise HTTPClientError(
                    f"HTTPS to HTTP redirect rejected: {location}",
                    url=original_url,
                )
            return RequestsTransport._strip_url_credentials(location)
        # Reject absolute URLs with non-HTTP schemes (ftp://, file://, etc.)
        # and scheme-less forms like data: or javascript: that use `:` without `://`.
        if "://" in location and not location.startswith(("//", "/")):
            raise HTTPClientError(
                f"Redirect to non-HTTP scheme rejected: {location}",
                url=original_url,
            )
        if (
            ":" in location
            and not location.startswith(("//", "/"))
            and "/" not in location.split(":")[0]
        ):
            raise HTTPClientError(
                f"Redirect to non-HTTP scheme rejected: {location}",
                url=original_url,
            )
        resolved = urljoin(original_url, location)
        if original_url_lower.startswith("https://") and resolved.lower().startswith(
            "http://"
        ):
            raise HTTPClientError(
                f"HTTPS to HTTP redirect rejected: {resolved}",
                url=original_url,
            )
        return RequestsTransport._strip_url_credentials(resolved)

    @staticmethod
    def _strip_url_credentials(location: str) -> str:
        try:
            return strip_url_credentials(location)
        except ValueError as exc:
            raise HTTPClientError(str(exc), url=location) from exc
