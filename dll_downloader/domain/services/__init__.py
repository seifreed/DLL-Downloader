"""
Domain Service Interfaces

Abstract interfaces for domain services that don't naturally fit into entities.
These define contracts for cross-cutting concerns like security scanning and HTTP operations.
"""

from .download_resolver import IDownloadURLResolver
from .hash_service import calculate_sha256
from .http_client import IHTTPClient
from .security_scanner import ISecurityScanner, ScanResult

__all__ = [
    "IHTTPClient",
    "ISecurityScanner",
    "ScanResult",
    "IDownloadURLResolver",
    "calculate_sha256",
]
