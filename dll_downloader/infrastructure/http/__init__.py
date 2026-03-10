"""
HTTP Infrastructure

Provides HTTP client implementations for making web requests.

Note: The IHTTPClient Protocol interface is defined in the domain layer at:
    dll_downloader.domain.services.http_client
"""

from .dll_files_resolver import DllFilesResolver, DllFilesResolverError
from .http_client import HTTPClientError, HTTPResponse, RequestsHTTPClient

__all__ = [
    "DllFilesResolver",
    "DllFilesResolverError",
    "HTTPClientError",
    "HTTPResponse",
    "RequestsHTTPClient",
]
