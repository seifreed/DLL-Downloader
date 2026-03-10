"""
Explicit library-facing API for programmatic use of DLL Downloader.
"""

from .application.use_cases import DownloadDLLRequest, DownloadDLLResponse
from .domain.entities import Architecture
from .infrastructure.config.settings import Settings

API_VERSION = "1"


__all__ = [
    "API_VERSION",
    "Architecture",
    "Settings",
    "DownloadDLLRequest",
    "DownloadDLLResponse",
]
