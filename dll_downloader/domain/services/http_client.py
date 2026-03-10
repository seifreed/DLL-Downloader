"""
HTTP Client Interface for domain layer.

Defines the contract for HTTP operations used by the application layer.
This Protocol enables structural typing for dependency injection without
requiring infrastructure implementations to explicitly inherit from it.
"""

from collections.abc import Mapping
from typing import Protocol, TypedDict


class HTTPFileInfo(TypedDict):
    """Structured metadata returned by an HTTP adapter."""

    content_type: str | None
    content_length: int
    last_modified: str | None
    etag: str | None
    accept_ranges: bool


class ITextHTTPClient(Protocol):
    """Protocol for adapters that only need text-fetching behavior."""

    def get_text(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        """
        Fetch a text response from a URL.

        Args:
            url: The URL to fetch
            headers: Optional HTTP headers

        Returns:
            Response body decoded as text
        """
        ...


class IHTTPClient(ITextHTTPClient, Protocol):
    """
    Protocol defining HTTP client interface for dependency injection.

    This interface abstracts HTTP operations to allow for different
    implementations (requests, aiohttp, httpx) and easier testing.
    Any class implementing these methods will satisfy the protocol.

    Example:
        >>> def download_file(client: IHTTPClient, url: str) -> bytes:
        ...     return client.download(url)
    """

    def download(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        """
        Download binary content from a URL.

        Args:
            url: The URL to download from

        Returns:
            Raw bytes of the downloaded content

        Raises:
            Exception: If the download fails (implementation-specific)
        """
        ...

    def get_file_info(self, url: str) -> HTTPFileInfo:
        """
        Get file metadata from a URL without downloading.

        Args:
            url: The URL to check

        Returns:
            Structured file information
        """
        ...
