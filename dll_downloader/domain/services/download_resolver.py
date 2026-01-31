"""
Download URL Resolver Interface.

Defines the contract for resolving a DLL name + architecture into a direct
download URL.
"""

from typing import Protocol

from ..entities.dll_file import Architecture


class IDownloadURLResolver(Protocol):
    """Protocol for download URL resolution."""

    def resolve_download_url(self, dll_name: str, architecture: Architecture) -> str:
        """
        Resolve a direct download URL for a DLL.

        Args:
            dll_name: Name of the DLL (with or without .dll extension)
            architecture: Target architecture
        """
        ...
