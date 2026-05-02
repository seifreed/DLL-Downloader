"""
Domain Service Interfaces

Abstract interfaces for domain services that don't naturally fit into entities.
These define contracts for cross-cutting concerns like security scanning and HTTP operations.
"""

from .download_resolver import IDownloadURLResolver
from .hash_service import calculate_sha256
from .http_client import HTTPFileInfo, IHTTPClient, ITextHTTPClient
from .pe_validation import (
    PEDllInspection,
    detect_pe_dll_architecture,
    expected_optional_magic,
    has_loadable_section,
    inspect_pe_dll_architecture,
    pe_image_layout_is_valid,
)
from .security_scanner import ISecurityScanner, ScanResult

__all__ = [
    "HTTPFileInfo",
    "IHTTPClient",
    "ITextHTTPClient",
    "ISecurityScanner",
    "ScanResult",
    "IDownloadURLResolver",
    "PEDllInspection",
    "calculate_sha256",
    "detect_pe_dll_architecture",
    "expected_optional_magic",
    "has_loadable_section",
    "inspect_pe_dll_architecture",
    "pe_image_layout_is_valid",
]
