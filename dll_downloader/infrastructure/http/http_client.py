"""
HTTP Client

Implementation of HTTP operations for the infrastructure layer.

The IHTTPClient Protocol is defined in the domain layer at:
    dll_downloader.domain.services.http_client

This module provides concrete implementations that satisfy that Protocol
through structural typing (duck typing).
"""

import logging
from dataclasses import dataclass

import requests

from ..base import SessionMixin

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HTTPResponse:
    """
    Represents an HTTP response.

    Attributes:
        status_code: HTTP status code
        content: Response body as bytes
        headers: Response headers
        url: Final URL (after redirects)
    """

    status_code: int
    content: bytes
    headers: dict[str, str]
    url: str

    @property
    def is_success(self) -> bool:
        """Check if the response indicates success (2xx status)."""
        return 200 <= self.status_code < 300

    @property
    def content_length(self) -> int | None:
        """Get content length from headers if available."""
        length = self.headers.get('content-length')
        return int(length) if length else None


class HTTPClientError(Exception):
    """Exception raised for HTTP client errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        url: str | None = None
    ) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(message)


class RequestsHTTPClient(SessionMixin):
    """
    HTTP client implementation using the requests library.

    This implementation provides a robust HTTP client with:
    - Connection pooling and retry logic
    - Timeout handling
    - Progress callbacks for large downloads
    - User-agent customization

    This class satisfies the IHTTPClient Protocol defined in the domain layer
    through structural typing (implements download() and get_file_info() methods).

    Architecture Notes:
        Inherits from SessionMixin to reuse HTTP session management logic.
        This is an intentional infrastructure-layer coupling for shared
        technical concerns (connection pooling, resource cleanup).
        See base.py for design rationale.

    Example:
        >>> client = RequestsHTTPClient(timeout=30)
        >>> content = client.download("https://example.com/file.dll")
    """

    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        timeout: int = 60,
        user_agent: str | None = None,
        verify_ssl: bool = True
    ) -> None:
        """
        Initialize the HTTP client.

        Args:
            timeout: Request timeout in seconds
            user_agent: Custom User-Agent header
            verify_ssl: Whether to verify SSL certificates
        """
        super().__init__()
        self._timeout = timeout
        self._user_agent = user_agent or self.DEFAULT_USER_AGENT
        self._verify_ssl = verify_ssl
        self._session_headers = {'User-Agent': self._user_agent}

    def get(self, url: str, headers: dict[str, str] | None = None) -> HTTPResponse:
        """
        Perform an HTTP GET request.

        Args:
            url: The URL to request
            headers: Optional additional headers

        Returns:
            HTTPResponse with the response data
        """
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self._timeout,
                verify=self._verify_ssl
            )

            return HTTPResponse(
                status_code=response.status_code,
                content=response.content,
                headers=dict(response.headers),
                url=response.url
            )

        except requests.RequestException as e:
            logger.error(f"GET request failed for {url}: {e}")
            raise HTTPClientError(f"GET request failed: {e}", url=url) from e

    def download(self, url: str, headers: dict[str, str] | None = None) -> bytes:
        """
        Download binary content from a URL with streaming.

        Args:
            url: The URL to download from
            headers: Optional additional headers

        Returns:
            Raw bytes of the downloaded content
        """
        try:
            response = self.session.get(
                url,
                headers=headers,
                timeout=self._timeout,
                verify=self._verify_ssl,
                stream=True
            )

            if not response.ok:
                raise HTTPClientError(
                    f"Download failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=url
                )

            # Stream content for memory efficiency
            chunks = []
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    chunks.append(chunk)

            return b''.join(chunks)

        except requests.RequestException as e:
            logger.error(f"Download failed for {url}: {e}")
            raise HTTPClientError(f"Download failed: {e}", url=url) from e

    def head(self, url: str) -> dict[str, str]:
        """
        Perform an HTTP HEAD request.

        Args:
            url: The URL to check

        Returns:
            Dictionary of response headers
        """
        try:
            response = self.session.head(
                url,
                timeout=self._timeout,
                verify=self._verify_ssl,
                allow_redirects=True
            )
            return dict(response.headers)

        except requests.RequestException as e:
            logger.error(f"HEAD request failed for {url}: {e}")
            raise HTTPClientError(f"HEAD request failed: {e}", url=url) from e

    def get_file_info(self, url: str) -> dict[str, object]:
        """
        Get file metadata from a URL.

        Args:
            url: The URL to check

        Returns:
            Dictionary with file information
        """
        headers = self.head(url)
        content_length = headers.get('content-length')
        try:
            length_value = int(content_length) if content_length else 0
        except ValueError:
            length_value = 0
        return {
            'content_type': headers.get('content-type'),
            'content_length': length_value,
            'last_modified': headers.get('last-modified'),
            'etag': headers.get('etag'),
            'accept_ranges': headers.get('accept-ranges') == 'bytes'
        }
