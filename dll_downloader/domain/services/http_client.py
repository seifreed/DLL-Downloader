"""
HTTP Client Interface for domain layer.

Defines the contract for HTTP operations used by the application layer.
This Protocol enables structural typing for dependency injection without
requiring infrastructure implementations to explicitly inherit from it.
"""

from typing import Protocol


class IHTTPClient(Protocol):
    """
    Protocol defining HTTP client interface for dependency injection.

    This interface abstracts HTTP operations to allow for different
    implementations (requests, aiohttp, httpx) and easier testing.
    Any class implementing these methods will satisfy the protocol.

    Example:
        >>> def download_file(client: IHTTPClient, url: str) -> bytes:
        ...     return client.download(url)
    """

    def download(self, url: str) -> bytes:
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

    def get_file_info(self, url: str) -> dict[str, object]:
        """
        Get file metadata from a URL without downloading.

        Args:
            url: The URL to check

        Returns:
            Dictionary with file information (size, content-type, etc.)
        """
        ...
