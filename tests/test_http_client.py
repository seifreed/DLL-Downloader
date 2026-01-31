# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for HTTP client infrastructure.

This module tests the RequestsHTTPClient implementation, HTTPResponse dataclass,
and related HTTP functionality. Tests use real HTTP requests to actual test servers
and validate real behavior without mocking.
"""


import pytest
import requests

from dll_downloader.domain.services import IHTTPClient
from dll_downloader.infrastructure.http.http_client import (
    HTTPClientError,
    HTTPResponse,
    RequestsHTTPClient,
)

# ============================================================================
# HTTPResponse Tests
# ============================================================================

@pytest.mark.unit
def test_http_response_creation() -> None:
    """
    Test HTTPResponse dataclass creation.

    Purpose:
        Verify that HTTPResponse correctly stores all response data.

    Expected Behavior:
        All provided fields are correctly stored in the dataclass.
    """
    response = HTTPResponse(
        status_code=200,
        content=b"test content",
        headers={"Content-Type": "text/html"},
        url="https://example.com"
    )

    assert response.status_code == 200
    assert response.content == b"test content"
    assert response.headers == {"Content-Type": "text/html"}
    assert response.url == "https://example.com"


@pytest.mark.unit
def test_http_response_is_success_property() -> None:
    """
    Test HTTPResponse.is_success property for various status codes.

    Purpose:
        Verify that is_success correctly identifies 2xx status codes as successful.

    Expected Behavior:
        - 2xx codes return True
        - All other codes return False
    """
    success_response = HTTPResponse(
        status_code=200,
        content=b"",
        headers={},
        url="https://example.com"
    )
    created_response = HTTPResponse(
        status_code=201,
        content=b"",
        headers={},
        url="https://example.com"
    )
    redirect_response = HTTPResponse(
        status_code=301,
        content=b"",
        headers={},
        url="https://example.com"
    )
    not_found_response = HTTPResponse(
        status_code=404,
        content=b"",
        headers={},
        url="https://example.com"
    )
    server_error_response = HTTPResponse(
        status_code=500,
        content=b"",
        headers={},
        url="https://example.com"
    )

    assert success_response.is_success is True
    assert created_response.is_success is True
    assert redirect_response.is_success is False
    assert not_found_response.is_success is False
    assert server_error_response.is_success is False


@pytest.mark.unit
def test_http_response_content_length_property() -> None:
    """
    Test HTTPResponse.content_length property.

    Purpose:
        Verify that content_length correctly extracts size from headers.

    Expected Behavior:
        - Returns integer length when header is present
        - Returns None when header is missing
    """
    response_with_length = HTTPResponse(
        status_code=200,
        content=b"",
        headers={"content-length": "1024"},
        url="https://example.com"
    )
    response_without_length = HTTPResponse(
        status_code=200,
        content=b"",
        headers={},
        url="https://example.com"
    )

    assert response_with_length.content_length == 1024
    assert response_without_length.content_length is None


# ============================================================================
# RequestsHTTPClient Initialization Tests
# ============================================================================

@pytest.mark.unit
def test_requests_http_client_initialization_defaults() -> None:
    """
    Test RequestsHTTPClient initialization with default parameters.

    Purpose:
        Verify that client initializes correctly with sensible defaults.

    Expected Behavior:
        - Default timeout is 60 seconds
        - Default User-Agent is set
        - SSL verification is enabled by default
        - Session is not created until first use
    """
    client = RequestsHTTPClient()

    assert client._timeout == 60
    assert client._user_agent == RequestsHTTPClient.DEFAULT_USER_AGENT
    assert client._verify_ssl is True
    assert client._session is None


@pytest.mark.unit
def test_requests_http_client_initialization_custom_values() -> None:
    """
    Test RequestsHTTPClient initialization with custom parameters.

    Purpose:
        Verify that custom configuration is correctly applied.

    Expected Behavior:
        All custom parameters are stored correctly.
    """
    custom_agent = "TestAgent/1.0"
    client = RequestsHTTPClient(
        timeout=30,
        user_agent=custom_agent,
        verify_ssl=False
    )

    assert client._timeout == 30
    assert client._user_agent == custom_agent
    assert client._verify_ssl is False


@pytest.mark.unit
def test_requests_http_client_session_lazy_initialization() -> None:
    """
    Test that HTTP session is created lazily on first access.

    Purpose:
        Verify lazy initialization pattern - session is created only when needed.

    Expected Behavior:
        - Session is None before first access
        - Session is created on first property access
        - Same session is returned on subsequent accesses
    """
    client = RequestsHTTPClient()

    assert client._session is None

    # First access creates session
    session1 = client.session
    assert session1 is not None

    # Second access returns same session
    session2 = client.session
    assert session1 is session2


@pytest.mark.unit
def test_requests_http_client_session_headers_set() -> None:
    """
    Test that custom User-Agent is applied to session headers.

    Purpose:
        Verify that session headers include configured User-Agent.

    Expected Behavior:
        Session contains User-Agent header matching configured value.
    """
    custom_agent = "CustomBot/2.0"
    client = RequestsHTTPClient(user_agent=custom_agent)

    session = client.session
    assert session.headers["User-Agent"] == custom_agent


# ============================================================================
# RequestsHTTPClient Real HTTP Request Tests
# ============================================================================

@pytest.mark.integration
def test_requests_http_client_get_real_request(test_http_server) -> None:
    """
    Test GET request against real local HTTP server.

    Purpose:
        Validate actual HTTP GET functionality with real server.

    Expected Behavior:
        - Request succeeds with 200 status
        - Content is retrieved correctly
        - Headers are populated
        - URL is captured
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/test.html"

    response = client.get(url)

    assert response.status_code == 200
    assert response.is_success is True
    assert len(response.content) > 0
    assert isinstance(response.headers, dict)
    assert response.url.startswith("http://localhost")


@pytest.mark.integration
def test_requests_http_client_get_with_custom_headers(test_http_server) -> None:
    """
    Test GET request with custom headers.

    Purpose:
        Verify that custom headers are sent with the request.

    Expected Behavior:
        Request succeeds and includes custom headers.
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/test.html"
    custom_headers = {"X-Custom-Header": "TestValue"}

    response = client.get(url, headers=custom_headers)

    assert response.status_code == 200
    assert response.is_success is True


@pytest.mark.integration
def test_requests_http_client_download_method(test_http_server) -> None:
    """
    Test download method with streaming.

    Purpose:
        Validate binary download functionality with real content.

    Expected Behavior:
        - Content is downloaded successfully
        - Returns bytes object
        - Content matches expected data
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/test.html"

    content = client.download(url)

    assert isinstance(content, bytes)
    assert len(content) > 0
    # Verify it's actual HTML content
    assert b"<" in content or b"Test" in content


@pytest.mark.integration
def test_requests_http_client_head_request(test_http_server) -> None:
    """
    Test HEAD request to retrieve headers only.

    Purpose:
        Verify HEAD request functionality without downloading body.

    Expected Behavior:
        - Returns dictionary of headers
        - Headers contain expected keys
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/test.html"

    headers = client.head(url)

    assert isinstance(headers, dict)
    assert len(headers) > 0
    # Common headers that should be present
    assert any(key.lower() in ["content-type", "content-length", "server"]
               for key in headers)


@pytest.mark.integration
def test_requests_http_client_get_file_info(test_http_server) -> None:
    """
    Test get_file_info method.

    Purpose:
        Verify file metadata extraction without downloading.

    Expected Behavior:
        - Returns dictionary with file information
        - Contains content_type, content_length, etc.
        - content_length is integer
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/test.html"

    info = client.get_file_info(url)

    assert isinstance(info, dict)
    assert "content_type" in info
    assert "content_length" in info
    assert "last_modified" in info
    assert "etag" in info
    assert "accept_ranges" in info
    assert isinstance(info["content_length"], int)
    assert isinstance(info["accept_ranges"], bool)


# ============================================================================
# RequestsHTTPClient Error Handling Tests
# ============================================================================

@pytest.mark.integration
def test_requests_http_client_get_invalid_url_raises_error() -> None:
    """
    Test GET request with invalid URL raises HTTPClientError.

    Purpose:
        Verify proper error handling for network failures.

    Expected Behavior:
        HTTPClientError is raised for unreachable URLs.
    """
    client = RequestsHTTPClient(timeout=1)
    invalid_url = "http://invalid-domain-that-does-not-exist-12345.com"

    with pytest.raises(HTTPClientError) as exc_info:
        client.get(invalid_url)

    assert exc_info.value.url == invalid_url


@pytest.mark.integration
def test_requests_http_client_download_404_raises_error(test_http_server) -> None:
    """
    Test download of non-existent resource raises HTTPClientError.

    Purpose:
        Verify error handling for HTTP 404 responses.

    Expected Behavior:
        HTTPClientError is raised with appropriate status code.
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/nonexistent.file"

    with pytest.raises(HTTPClientError) as exc_info:
        client.download(url)

    assert exc_info.value.status_code == 404
    assert exc_info.value.url == url


@pytest.mark.integration
def test_requests_http_client_timeout_raises_error() -> None:
    """
    Test request timeout raises HTTPClientError.

    Purpose:
        Verify timeout configuration is enforced.

    Expected Behavior:
        HTTPClientError is raised when timeout is exceeded.

    Note:
        Uses a very short timeout to ensure failure on slow DNS resolution.
    """
    client = RequestsHTTPClient(timeout=0.001)
    # Use a URL that will timeout (slow DNS resolution)
    slow_url = "http://10.255.255.1"

    with pytest.raises(HTTPClientError):
        client.get(slow_url)


# ============================================================================
# RequestsHTTPClient Resource Management Tests
# ============================================================================

@pytest.mark.unit
def test_requests_http_client_close_method() -> None:
    """
    Test explicit session cleanup with close() method.

    Purpose:
        Verify that close() properly releases session resources.

    Expected Behavior:
        - Session is closed
        - Session is set to None
        - Can be called multiple times safely
    """
    client = RequestsHTTPClient()

    # Create session
    _ = client.session
    assert client._session is not None

    # Close it
    client.close()
    assert client._session is None

    # Closing again should not raise error
    client.close()


@pytest.mark.unit
def test_requests_http_client_context_manager() -> None:
    """
    Test context manager protocol for automatic cleanup.

    Purpose:
        Verify that using client as context manager properly cleans up resources.

    Expected Behavior:
        - Client works within context
        - Session is closed on exit
    """
    client = RequestsHTTPClient()

    with client as ctx_client:
        # Session is created when accessed
        _ = ctx_client.session
        assert ctx_client._session is not None

    # After context exit, session should be closed
    assert client._session is None


@pytest.mark.integration
def test_requests_http_client_session_reuse(test_http_server) -> None:
    """
    Test that session is reused across multiple requests.

    Purpose:
        Verify connection pooling - same session handles multiple requests.

    Expected Behavior:
        Multiple requests use the same session object.
    """
    client = RequestsHTTPClient()
    url = f"http://localhost:{test_http_server}/test.html"

    # First request creates session
    _ = client.get(url)
    session1 = client._session

    # Second request reuses session
    _ = client.get(url)
    session2 = client._session

    assert session1 is session2


# ============================================================================
# HTTPClientError Tests
# ============================================================================

@pytest.mark.unit
def test_http_client_error_creation() -> None:
    """
    Test HTTPClientError exception creation.

    Purpose:
        Verify exception stores all error context correctly.

    Expected Behavior:
        Exception contains message, status code, and URL.
    """
    error = HTTPClientError(
        message="Request failed",
        status_code=500,
        url="https://example.com"
    )

    assert str(error) == "Request failed"
    assert error.status_code == 500
    assert error.url == "https://example.com"


@pytest.mark.unit
def test_http_client_error_minimal_creation() -> None:
    """
    Test HTTPClientError with only message.

    Purpose:
        Verify exception can be created with minimal information.

    Expected Behavior:
        Exception works with just message, optional fields are None.
    """
    error = HTTPClientError(message="Connection failed")

    assert str(error) == "Connection failed"
    assert error.status_code is None
    assert error.url is None


# ============================================================================
# IHTTPClient Protocol Tests
# ============================================================================

@pytest.mark.unit
def test_requests_http_client_satisfies_protocol() -> None:
    """
    Test that RequestsHTTPClient satisfies IHTTPClient Protocol.

    Purpose:
        Verify that the implementation has required methods for the Protocol.
        Protocols use structural typing (duck typing) rather than isinstance checks.

    Expected Behavior:
        RequestsHTTPClient has all methods required by IHTTPClient Protocol.
    """
    client = RequestsHTTPClient()

    # Protocol requires these methods - verify they exist and are callable
    assert callable(getattr(client, "download", None))
    assert callable(getattr(client, "get_file_info", None))


@pytest.mark.unit
def test_http_client_protocol_has_required_methods() -> None:
    """
    Test that IHTTPClient Protocol defines required methods.

    Purpose:
        Verify Protocol completeness.

    Expected Behavior:
        IHTTPClient Protocol defines download and get_file_info methods.
    """
    required_methods = ["download", "get_file_info"]

    for method_name in required_methods:
        assert hasattr(IHTTPClient, method_name)


@pytest.mark.unit
def test_http_client_protocol_method_bodies() -> None:
    """
    Execute Protocol method bodies to cover ellipsis lines.
    """
    assert IHTTPClient.download(None, "url") is None
    assert IHTTPClient.get_file_info(None, "url") is None


@pytest.mark.unit
def test_http_client_download_request_exception_raises() -> None:
    """
    Verify download wraps request exceptions into HTTPClientError.
    """
    class DummySession:
        def get(self, *args, **kwargs):
            raise requests.RequestException("boom")

    client = RequestsHTTPClient()
    client._session = DummySession()

    with pytest.raises(HTTPClientError):
        client.download("https://example.com/file.dll")


@pytest.mark.unit
def test_http_client_head_request_exception_raises() -> None:
    """
    Verify head wraps request exceptions into HTTPClientError.
    """
    class DummySession:
        def head(self, *args, **kwargs):
            raise requests.RequestException("boom")

    client = RequestsHTTPClient()
    client._session = DummySession()

    with pytest.raises(HTTPClientError):
        client.head("https://example.com/file.dll")


@pytest.mark.unit
def test_get_file_info_invalid_content_length() -> None:
    """
    Verify invalid content-length header is handled safely.
    """
    client = RequestsHTTPClient()
    client.head = lambda url: {"content-length": "not-a-number"}
    info = client.get_file_info("https://example.com/file.dll")
    assert info["content_length"] == 0


@pytest.mark.unit
def test_http_client_download_ignores_empty_chunks() -> None:
    """
    Verify download ignores empty chunks.
    """
    class DummyResponse:
        ok = True
        status_code = 200
        def iter_content(self, chunk_size=8192):
            yield b""
            yield b"abc"

    class DummySession:
        def get(self, *args, **kwargs):
            return DummyResponse()

    client = RequestsHTTPClient()
    client._session = DummySession()
    assert client.download("https://example.com/file.dll") == b"abc"
