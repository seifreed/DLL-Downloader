"""
HTTP Infrastructure

Provides HTTP client implementations for making web requests.

Note: The IHTTPClient Protocol interface is defined in the domain layer at:
    dll_downloader.domain.services.http_client
"""

from .http_client import HTTPClientError, HTTPResponse, RequestsHTTPClient

__all__ = ["HTTPClientError", "HTTPResponse", "RequestsHTTPClient"]
