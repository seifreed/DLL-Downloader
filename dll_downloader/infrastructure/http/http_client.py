"""
HTTP client adapter built on top of the shared requests transport.
"""

import logging
from collections.abc import Mapping

from ...domain.services.http_client import HTTPFileInfo
from ..http_session import (
    HTTPResponseProtocol,
    HTTPSessionProtocol,
    HTTPSessionResource,
)
from .request_headers import RequestHeaderBuilder
from .retry_policy import RetryPolicy
from .transport import (
    HTTP_STREAM_ERROR_TYPES,
    HTTPClientError,
    HTTPResponse,
    RequestsTransport,
    header_value,
)
from .user_agents import (
    FixedUserAgentProvider,
    RandomUserAgentProvider,
    UserAgentProvider,
)

logger = logging.getLogger(__name__)
__all__ = ["HTTPClientError", "HTTPResponse", "RequestsHTTPClient"]


_DEFAULT_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024  # 512 MiB


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
    ) -> None:
        self._timeout = timeout
        self._max_download_bytes = max_download_bytes
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
        response = self._transport.execute("GET", url, headers=headers, stream=True)
        try:
            chunks: list[bytes] = []
            total_bytes = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    total_bytes += len(chunk)
                    if total_bytes > self._max_download_bytes:
                        raise HTTPClientError(
                            f"GET response exceeds size limit {self._max_download_bytes}",
                            status_code=response.status_code,
                            url=response.url or url,
                        )
                    chunks.append(chunk)
            content = b"".join(chunks)
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
            self._close_response(response)

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
        return self._decode_text(response.content, response.headers)

    def download(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        response = self._transport.execute("DOWNLOAD", url, headers=headers, stream=True)
        try:
            if not response.ok:
                raise HTTPClientError(
                    f"Download failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=url,
                )
            content_length = header_value(dict(response.headers), "content-length")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                    if declared_size > self._max_download_bytes:
                        raise HTTPClientError(
                            f"Content-Length {declared_size} exceeds download limit "
                            f"{self._max_download_bytes}",
                            status_code=response.status_code,
                            url=url,
                        )
                except ValueError:
                    raise HTTPClientError(
                        f"Invalid Content-Length header: {content_length!r}",
                        status_code=response.status_code,
                        url=url,
                    )
            chunks: list[bytes] = []
            total_bytes = 0
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    total_bytes += len(chunk)
                    if total_bytes > self._max_download_bytes:
                        raise HTTPClientError(
                            f"Download exceeded size limit {self._max_download_bytes}",
                            status_code=response.status_code,
                            url=url,
                        )
                    chunks.append(chunk)
            result = b"".join(chunks)
            if content_length is not None:
                try:
                    if len(result) != int(content_length):
                        raise HTTPClientError(
                            f"Incomplete download: received {len(result)} bytes, "
                            f"expected {content_length}",
                            status_code=response.status_code,
                            url=url,
                        )
                except ValueError:
                    pass
            return result
        except HTTP_STREAM_ERROR_TYPES as exc:
            raise HTTPClientError(
                f"Download stream failed: {exc}",
                status_code=response.status_code,
                url=response.url or url,
            ) from exc
        finally:
            self._close_response(response)

    _TEXT_CHARSETS = frozenset({
        "utf-8", "utf8", "utf-16", "utf-16-le", "utf-16-be",
        "utf-32", "utf-32-le", "utf-32-be",
        "ascii", "latin-1", "iso-8859-1", "iso-8859-15",
        "cp1252", "windows-1252", "cp1250", "windows-1250", "cp1251", "windows-1251",
        "shift_jis", "shift-jis", "euc-jp", "euc-kr", "gb2312", "gbk", "gb18030",
        "big5", "iso-2022-jp",
    })

    @classmethod
    def _decode_text(cls, content: bytes, headers: dict[str, str]) -> str:
        content_type = header_value(headers, "content-type") or ""
        charset = "utf-8"
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                candidate = part.split("=", 1)[1].strip().strip('"').strip("'").lower()
                if candidate in cls._TEXT_CHARSETS:
                    charset = candidate
                break
        try:
            return content.decode(charset)
        except LookupError:
            return content.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            if charset == "utf-8":
                return content.decode("utf-8", errors="replace")
            return content.decode(charset, errors="replace")

    @staticmethod
    def _close_response(response: HTTPResponseProtocol) -> None:
        close_response = getattr(response, "close", None)
        if not callable(close_response):
            return
        try:
            close_response()
        except HTTP_STREAM_ERROR_TYPES as exc:
            logger.warning("Failed to close response: %s", exc)

    def head(self, url: str) -> dict[str, str]:
        response = self._transport.execute("HEAD", url, allow_redirects=True)
        try:
            return dict(response.headers)
        finally:
            self._close_response(response)

    def get_file_info(self, url: str) -> HTTPFileInfo:
        headers = self.head(url)
        content_length = header_value(headers, "content-length")
        length_value: int | None = None
        if content_length:
            try:
                length_value = int(content_length)
            except ValueError:
                length_value = None
        accept_ranges = header_value(headers, "accept-ranges")
        return {
            "content_type": header_value(headers, "content-type"),
            "content_length": length_value,
            "last_modified": header_value(headers, "last-modified"),
            "etag": header_value(headers, "etag"),
            "accept_ranges": bool(accept_ranges is not None and accept_ranges.lower() == "bytes"),
        }
