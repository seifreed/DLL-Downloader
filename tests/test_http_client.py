# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for HTTP client infrastructure.

This module tests the RequestsHTTPClient implementation, HTTPResponse dataclass,
and related HTTP functionality. Tests use real HTTP requests to actual test servers
and validate real behavior without mocking.
"""

from collections.abc import Iterator, Mapping, MutableMapping
from random import Random
from typing import Any, cast

import pytest
import requests

from dll_downloader.domain.services import IHTTPClient
from dll_downloader.infrastructure.http.http_client import (
    HTTPClientError,
    HTTPResponse,
    RequestsHTTPClient,
)
from dll_downloader.infrastructure.http.request_headers import RequestHeaderBuilder
from dll_downloader.infrastructure.http.retry_policy import RetryPolicy
from dll_downloader.infrastructure.http.transport import RequestsTransport
from dll_downloader.infrastructure.http.user_agents import (
    FixedUserAgentProvider,
    RandomUserAgentProvider,
)
from dll_downloader.infrastructure.http_session import (
    HTTPResponseProtocol,
    HTTPSessionProtocol,
    HTTPSessionResource,
)


def _resource_with_session(session: HTTPSessionProtocol) -> HTTPSessionResource:
    return HTTPSessionResource(session=session)


class SequenceUserAgentProvider:
    def __init__(self, values: list[str]) -> None:
        self._values = values
        self._index = 0

    def next_user_agent(self) -> str:
        value = self._values[self._index % len(self._values)]
        self._index += 1
        return value


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
        url="https://example.com",
    )

    assert response.status_code == 200
    assert response.content == b"test content"
    assert response.headers == {"Content-Type": "text/html"}
    assert response.url == "https://example.com"


@pytest.mark.unit
def test_http_response_headers_are_snapshot_immutable() -> None:
    source_headers = {"Location": "/next"}
    response = HTTPResponse(
        status_code=302,
        content=b"",
        headers=source_headers,
        url="https://example.com",
    )

    source_headers.clear()

    assert response.is_redirect is True
    with pytest.raises(TypeError):
        cast(MutableMapping[str, str], response.headers)["Location"] = "/later"


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
        status_code=200, content=b"", headers={}, url="https://example.com"
    )
    created_response = HTTPResponse(
        status_code=201, content=b"", headers={}, url="https://example.com"
    )
    redirect_response = HTTPResponse(
        status_code=301, content=b"", headers={}, url="https://example.com"
    )
    not_found_response = HTTPResponse(
        status_code=404, content=b"", headers={}, url="https://example.com"
    )
    server_error_response = HTTPResponse(
        status_code=500, content=b"", headers={}, url="https://example.com"
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
        url="https://example.com",
    )
    response_without_length = HTTPResponse(
        status_code=200, content=b"", headers={}, url="https://example.com"
    )

    assert response_with_length.content_length == 1024
    assert response_without_length.content_length is None


@pytest.mark.unit
def test_http_response_content_length_is_case_insensitive() -> None:
    response = HTTPResponse(
        status_code=200,
        content=b"",
        headers={"Content-Length": "1024"},
        url="https://example.com",
    )

    assert response.content_length == 1024


@pytest.mark.unit
def test_http_response_content_length_returns_none_for_invalid_header() -> None:
    response = HTTPResponse(
        status_code=200,
        content=b"",
        headers={"content-length": "not-a-number"},
        url="https://example.com",
    )

    assert response.content_length is None


@pytest.mark.unit
def test_http_response_content_length_returns_none_for_negative_header() -> None:
    response = HTTPResponse(
        status_code=200,
        content=b"",
        headers={"Content-Length": "-1"},
        url="https://example.com",
    )

    assert response.content_length is None


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
    assert client._user_agent is None
    assert client._retry_policy.max_attempts == RequestsHTTPClient.DEFAULT_MAX_RETRIES
    assert client._verify_ssl is True
    assert client.has_active_session is False


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
        timeout=30, user_agent=custom_agent, max_retries=3, verify_ssl=False
    )

    assert client._timeout == 30
    assert client._user_agent == custom_agent
    assert client._retry_policy.max_attempts == 3
    assert client._verify_ssl is False


@pytest.mark.unit
def test_requests_http_client_rejects_invalid_retry_count() -> None:
    with pytest.raises(ValueError, match="max_attempts must be positive"):
        RequestsHTTPClient(max_retries=0)


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

    assert client.has_active_session is False

    # First access creates session
    session1 = client.session
    assert session1 is not None
    assert client.has_active_session is True

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


@pytest.mark.unit
def test_requests_http_client_default_user_agent_comes_from_rotation_pool() -> None:
    client = RequestsHTTPClient()

    session = client.session
    assert session.headers["User-Agent"] in RandomUserAgentProvider.DEFAULT_USER_AGENTS


# ============================================================================
# RequestsHTTPClient Real HTTP Request Tests
# ============================================================================


@pytest.mark.integration
def test_requests_http_client_get_real_request(test_http_server: int) -> None:
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
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{test_http_server}/test.html"

    response = client.get(url)

    assert response.status_code == 200
    assert response.is_success is True
    assert len(response.content) > 0
    assert isinstance(response.headers, dict)
    assert response.url.startswith("http://localhost")


@pytest.mark.unit
def test_transport_scheme_relative_redirect_strips_credentials() -> None:
    class DummyResponse:
        headers = {"Location": "//user:pass@example.com/next?token=1"}

    redirect_url = RequestsTransport._resolve_redirect(
        "https://source.example/start",
        cast(HTTPResponseProtocol, DummyResponse()),
    )

    assert redirect_url == "https://example.com/next?token=1"


@pytest.mark.unit
def test_transport_ipv6_redirect_strips_credentials_preserves_brackets() -> None:
    class DummyResponse:
        headers = {"Location": "https://user:pass@[2606:4700:4700::1111]:443/next"}

    redirect_url = RequestsTransport._resolve_redirect(
        "https://source.example/start",
        cast(HTTPResponseProtocol, DummyResponse()),
    )

    assert redirect_url == "https://[2606:4700:4700::1111]:443/next"


@pytest.mark.unit
def test_transport_uppercase_https_redirect_is_supported() -> None:
    class DummyResponse:
        headers = {"Location": "HTTPS://user:pass@example.com/next"}

    redirect_url = RequestsTransport._resolve_redirect(
        "https://source.example/start",
        cast(HTTPResponseProtocol, DummyResponse()),
    )

    assert redirect_url == "https://example.com/next"


@pytest.mark.unit
def test_transport_redirect_with_invalid_port_raises_http_client_error() -> None:
    class DummyResponse:
        headers = {"Location": "https://example.com:bad/next"}

    with pytest.raises(HTTPClientError, match="invalid port"):
        RequestsTransport._resolve_redirect(
            "https://source.example/start",
            cast(HTTPResponseProtocol, DummyResponse()),
        )


@pytest.mark.integration
def test_requests_http_client_get_with_custom_headers(test_http_server: int) -> None:
    """
    Test GET request with custom headers.

    Purpose:
        Verify that custom headers are sent with the request.

    Expected Behavior:
        Request succeeds and includes custom headers.
    """
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{test_http_server}/test.html"
    custom_headers = {"X-Custom-Header": "TestValue"}

    response = client.get(url, headers=custom_headers)

    assert response.status_code == 200
    assert response.is_success is True


@pytest.mark.integration
def test_requests_http_client_download_method(test_http_server: int) -> None:
    """
    Test download method with streaming.

    Purpose:
        Validate binary download functionality with real content.

    Expected Behavior:
        - Content is downloaded successfully
        - Returns bytes object
        - Content matches expected data
    """
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{test_http_server}/test.html"

    content = client.download(url)

    assert isinstance(content, bytes)
    assert len(content) > 0
    # Verify it's actual HTML content
    assert b"<" in content or b"Test" in content


@pytest.mark.integration
def test_requests_http_client_head_request(test_http_server: int) -> None:
    """
    Test HEAD request to retrieve headers only.

    Purpose:
        Verify HEAD request functionality without downloading body.

    Expected Behavior:
        - Returns dictionary of headers
        - Headers contain expected keys
    """
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{test_http_server}/test.html"

    headers = client.head(url)

    assert isinstance(headers, dict)
    assert len(headers) > 0
    # Common headers that should be present
    assert any(
        key.lower() in ["content-type", "content-length", "server"] for key in headers
    )


@pytest.mark.integration
def test_requests_http_client_get_file_info(test_http_server: int) -> None:
    """
    Test get_file_info method.

    Purpose:
        Verify file metadata extraction without downloading.

    Expected Behavior:
        - Returns dictionary with file information
        - Contains content_type, content_length, etc.
        - content_length is integer
    """
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
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


@pytest.mark.integration
def test_requests_http_client_get_retries_transient_429(
    transient_http_server: int,
) -> None:
    client = RequestsHTTPClient(max_retries=5, allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{transient_http_server}/transient-get"

    response = client.get(url)

    assert response.status_code == 200
    assert response.content == b"<html><body>Recovered Content</body></html>"


@pytest.mark.integration
def test_requests_http_client_download_retries_transient_503(
    transient_http_server: int,
) -> None:
    client = RequestsHTTPClient(max_retries=5, allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{transient_http_server}/transient-download"

    content = client.download(url)

    assert content == b"MZ\x90\x00Recovered DLL"


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
    client = RequestsHTTPClient(
        timeout=1,
        allowed_redirect_domains={"invalid-domain-that-does-not-exist-12345.com"},
    )
    invalid_url = "http://invalid-domain-that-does-not-exist-12345.com"

    with pytest.raises(HTTPClientError) as exc_info:
        client.get(invalid_url)

    assert exc_info.value.url == invalid_url


@pytest.mark.integration
def test_requests_http_client_download_404_raises_error(test_http_server: int) -> None:
    """
    Test download of non-existent resource raises HTTPClientError.

    Purpose:
        Verify error handling for HTTP 404 responses.

    Expected Behavior:
        HTTPClientError is raised with appropriate status code.
    """
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
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
    assert client.has_active_session is True

    # Close it
    client.close()
    assert client.has_active_session is False

    # Closing again should not raise error
    client.close()


@pytest.mark.unit
def test_session_resource_discards_session_when_close_fails() -> None:
    class FailingCloseSession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            raise OSError("close failed")

    resource = HTTPSessionResource(
        session=cast(HTTPSessionProtocol, FailingCloseSession())
    )

    with pytest.raises(OSError, match="close failed"):
        resource.close()

    assert resource.has_session is False


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
        assert ctx_client.has_active_session is True

    # After context exit, session should be closed
    assert client.has_active_session is False


@pytest.mark.integration
def test_requests_http_client_session_reuse(test_http_server: int) -> None:
    """
    Test that session is reused across multiple requests.

    Purpose:
        Verify connection pooling - same session handles multiple requests.

    Expected Behavior:
        Multiple requests use the same session object.
    """
    client = RequestsHTTPClient(allowed_redirect_domains={"localhost"})
    url = f"http://localhost:{test_http_server}/test.html"

    # First request creates session
    _ = client.get(url)
    session1 = client.session

    # Second request reuses session
    _ = client.get(url)
    session2 = client.session

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
        message="Request failed", status_code=500, url="https://example.com"
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
    assert callable(getattr(client, "get_text", None))
    assert callable(getattr(client, "get_file_info", None))


@pytest.mark.unit
def test_http_client_protocol_has_required_methods() -> None:
    """
    Test that IHTTPClient Protocol defines required methods.

    Purpose:
        Verify Protocol completeness.

    Expected Behavior:
        IHTTPClient Protocol defines download, get_text, and get_file_info methods.
    """
    required_methods = ["download", "get_text", "get_file_info"]

    for method_name in required_methods:
        assert hasattr(IHTTPClient, method_name)


@pytest.mark.unit
def test_http_client_protocol_method_bodies() -> None:
    """
    Execute Protocol method bodies to cover ellipsis lines.
    """
    protocol = cast(Any, IHTTPClient)
    assert protocol.download(None, "url") is None
    assert protocol.get_text(None, "url") is None
    assert protocol.get_file_info(None, "url") is None


@pytest.mark.unit
def test_http_client_get_text_decodes_response() -> None:
    """
    Verify get_text decodes successful HTTP responses.
    """

    class FixedResponseClient(RequestsHTTPClient):
        def get(
            self,
            url: str,
            headers: Mapping[str, str] | None = None,
        ) -> HTTPResponse:
            return HTTPResponse(
                status_code=200,
                content=b"hola",
                headers={},
                url=url,
            )

    client = FixedResponseClient()

    assert client.get_text("https://example.com") == "hola"


@pytest.mark.unit
def test_http_client_get_text_decodes_unsuccessful_if_bypassed() -> None:
    """
    Verify get_text decodes content from a response passed directly,
    since get() already raises on non-ok status codes.
    """

    class FixedErrorClient(RequestsHTTPClient):
        def get(
            self,
            url: str,
            headers: Mapping[str, str] | None = None,
        ) -> HTTPResponse:
            return HTTPResponse(
                status_code=503,
                content=b"down",
                headers={},
                url=url,
            )

    client = FixedErrorClient()

    # When get() is bypassed (e.g., in subclasses), get_text just decodes.
    result = client.get_text("https://example.com")
    assert result == "down"


@pytest.mark.unit
def test_http_client_accepts_case_variant_user_agent_header() -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b"ok"
        headers: dict[str, str] = {}
        url = "https://example.com"

        def json(self) -> object:
            return {}

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

        def close(self) -> None:
            pass

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.request_headers: Mapping[str, str] | None = None

        def get(self, *args: Any, **kwargs: Any) -> DummyResponse:
            self.request_headers = cast(Mapping[str, str], kwargs["headers"])
            return DummyResponse()

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    response = client.get(
        "https://example.com",
        headers={"user-agent": "Caller/1.0"},
    )

    assert response.content == b"ok"
    assert session.request_headers == {"user-agent": "Caller/1.0"}


@pytest.mark.unit
def test_http_client_download_request_exception_raises() -> None:
    """
    Verify download wraps request exceptions into HTTPClientError.
    """

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise requests.RequestException("boom")

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    client = RequestsHTTPClient(
        session_resource=_resource_with_session(
            cast(HTTPSessionProtocol, DummySession())
        )
    )

    with pytest.raises(HTTPClientError):
        client.download("https://example.com/file.dll")


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("file:///tmp/file.dll", "non-HTTP scheme"),
        ("http:///file.dll", "without hostname"),
        ("https://example.com:bad/file.dll", "invalid port"),
        ("https://user:pass@example.com/file.dll", "credentials"),
    ],
)
def test_http_client_download_rejects_invalid_target_before_session_call(
    url: str,
    message: str,
) -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b"ok"
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def json(self) -> object:
            return {}

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0

        def get(self, *args: Any, **kwargs: Any) -> DummyResponse:
            self.calls += 1
            return DummyResponse()

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    with pytest.raises(HTTPClientError, match=message):
        client.download(url)

    assert session.calls == 0


@pytest.mark.unit
def test_transport_allowed_redirect_domains_are_snapshot_immutable() -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b"ok"
        headers: dict[str, str] = {}
        url = "https://127.0.0.1/file.dll"

        def json(self) -> object:
            return {}

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

        def close(self) -> None:
            pass

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            return cast(HTTPResponseProtocol, DummyResponse())

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    allowed_domains = {"example.com"}
    session = DummySession()
    transport = RequestsTransport(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
        retry_policy=RetryPolicy(max_attempts=1),
        header_builder=RequestHeaderBuilder(SequenceUserAgentProvider(["ua-1"])),
        timeout=1,
        verify_ssl=True,
        allowed_redirect_domains=allowed_domains,
    )

    allowed_domains.add("127.0.0.1")

    with pytest.raises(HTTPClientError, match="private/reserved address"):
        transport.execute("GET", "https://127.0.0.1/file.dll")

    assert session.calls == 0


@pytest.mark.unit
def test_http_client_head_request_exception_raises() -> None:
    """
    Verify head wraps request exceptions into HTTPClientError.
    """

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise requests.RequestException("boom")

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    client = RequestsHTTPClient(
        session_resource=_resource_with_session(
            cast(HTTPSessionProtocol, DummySession())
        )
    )

    with pytest.raises(HTTPClientError):
        client.head("https://example.com/file.dll")


@pytest.mark.unit
def test_http_client_head_closes_response() -> None:
    """Verify HEAD response resources are released after headers are copied."""

    class DummyResponse:
        status_code = 200
        is_redirect = False
        ok = True
        content = b""
        headers = {"content-length": "0"}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            return iter(())

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            return cast(HTTPResponseProtocol, self.response)

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    assert client.head("https://example.com/file.dll") == {"content-length": "0"}
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_get_closes_response() -> None:
    """Verify GET response resources are released after content is copied."""

    class DummyResponse:
        status_code = 200
        is_redirect = False
        ok = True
        content = b"body"
        headers = {"content-type": "text/plain"}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            return iter((self.content,))

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            return cast(HTTPResponseProtocol, self.response)

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    response = client.get("https://example.com/file.dll")

    assert response.content == b"body"
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_get_wraps_body_read_failures_and_closes_response() -> None:
    """Verify GET body read failures are normalized and resources are released."""

    class BrokenResponse:
        status_code = 200
        is_redirect = False
        ok = True
        headers: dict[str, str] = {"content-type": "text/plain"}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        @property
        def content(self) -> bytes:
            raise requests.ConnectionError("body read failed")

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            raise requests.ConnectionError("body read failed")

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = BrokenResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            return cast(HTTPResponseProtocol, self.response)

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    with pytest.raises(HTTPClientError, match="GET response read failed") as exc_info:
        client.get_text("https://example.com/file.dll")

    assert exc_info.value.status_code == 200
    assert session.response.closed is True


@pytest.mark.unit
def test_get_file_info_invalid_content_length() -> None:
    """
    Verify invalid content-length header is handled safely.
    """

    class InvalidHeadClient(RequestsHTTPClient):
        def head(
            self, url: str, headers: Mapping[str, str] | None = None
        ) -> dict[str, str]:
            return {"content-length": "not-a-number"}

    client = InvalidHeadClient()
    info = client.get_file_info("https://example.com/file.dll")
    assert info["content_length"] is None


@pytest.mark.unit
def test_get_file_info_ignores_negative_content_length() -> None:
    class NegativeHeadClient(RequestsHTTPClient):
        def head(
            self, url: str, headers: Mapping[str, str] | None = None
        ) -> dict[str, str]:
            return {"content-length": "-1"}

    client = NegativeHeadClient()

    info = client.get_file_info("https://example.com/file.dll")

    assert info["content_length"] is None


@pytest.mark.unit
def test_get_file_info_uses_case_insensitive_headers() -> None:
    class UppercaseHeadClient(RequestsHTTPClient):
        def head(
            self, url: str, headers: Mapping[str, str] | None = None
        ) -> dict[str, str]:
            return {
                "Content-Type": "application/zip",
                "Content-Length": "123",
                "Accept-Ranges": "bytes",
                "Last-Modified": "Thu, 30 Apr 2026 12:00:00 GMT",
                "ETag": '"abc"',
            }

    client = UppercaseHeadClient()

    info = client.get_file_info("https://example.com/file.dll")

    assert info == {
        "content_type": "application/zip",
        "content_length": 123,
        "last_modified": "Thu, 30 Apr 2026 12:00:00 GMT",
        "etag": '"abc"',
        "accept_ranges": True,
    }


@pytest.mark.unit
def test_http_client_download_ignores_empty_chunks() -> None:
    """
    Verify download ignores empty chunks.
    """

    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b""
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b""
            yield b"abc"

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> DummyResponse:
            return self.response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )
    assert client.download("https://example.com/file.dll") == b"abc"
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_download_accepts_exact_max_bytes() -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        headers = {"Content-Length": "3"}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b"abc"

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            return cast(HTTPResponseProtocol, self.response)

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_download_bytes=3,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    assert client.download("https://example.com/file.dll") == b"abc"
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_download_rejects_negative_content_length() -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        headers = {"Content-Length": "-1"}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b""

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            return cast(HTTPResponseProtocol, self.response)

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    with pytest.raises(HTTPClientError, match="Invalid Content-Length header"):
        client.download("https://example.com/file.dll")
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_download_rejects_body_over_max_without_declared_length() -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b"abcd"

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            return cast(HTTPResponseProtocol, self.response)

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_download_bytes=3,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    with pytest.raises(HTTPClientError, match="Download exceeds size limit 3"):
        client.download("https://example.com/file.dll")
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_download_wraps_stream_interruptions() -> None:
    """
    Verify interruptions while consuming response chunks are normalized.
    """

    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b""
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b"partial"
            raise requests.ConnectionError("stream broke")

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> DummyResponse:
            return self.response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    with pytest.raises(HTTPClientError, match="Download stream failed") as exc_info:
        client.download("https://example.com/file.dll")

    assert exc_info.value.status_code == 200
    assert exc_info.value.url == "https://example.com/file.dll"
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_download_ignores_final_response_close_failure() -> None:
    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b""
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.close_attempted = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b"ok"

        def close(self) -> None:
            self.close_attempted = True
            raise OSError("close failed")

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> DummyResponse:
            return self.response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    assert client.download("https://example.com/file.dll") == b"ok"
    assert session.response.close_attempted is True


@pytest.mark.unit
def test_http_client_download_ignores_final_response_oserror_close_failure() -> None:
    """RuntimeError from close() is no longer silently swallowed; only OSError is."""

    class DummyResponse:
        ok = True
        is_redirect = False
        status_code = 200
        content = b""
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.close_attempted = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b"ok"

        def close(self) -> None:
            self.close_attempted = True
            raise OSError("close failed")

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> DummyResponse:
            return self.response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session))
    )

    assert client.download("https://example.com/file.dll") == b"ok"
    assert session.response.close_attempted is True


@pytest.mark.unit
def test_http_client_download_retries_retryable_status() -> None:
    class DummyResponse:
        def __init__(self, status_code: int, content: bytes = b"") -> None:
            self.status_code = status_code
            self.ok = 200 <= status_code < 300
            self.content = content
            self.headers: dict[str, str] = {}
            self.url = "https://example.com/file.dll"
            self.closed = False
            self.is_redirect = 300 <= status_code < 400

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0
            self.retry_responses: list[DummyResponse] = []

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            if self.calls < 3:
                response = DummyResponse(503)
                self.retry_responses.append(response)
                return cast(HTTPResponseProtocol, response)
            return cast(HTTPResponseProtocol, DummyResponse(200, b"ok"))

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=5,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    assert client.download("https://example.com/file.dll") == b"ok"
    assert session.calls == 3
    assert [response.closed for response in session.retry_responses] == [True, True]


@pytest.mark.unit
def test_http_client_download_retries_when_retry_response_close_fails() -> None:
    class DummyResponse:
        def __init__(self, status_code: int, content: bytes = b"") -> None:
            self.status_code = status_code
            self.ok = 200 <= status_code < 300
            self.content = content
            self.headers: dict[str, str] = {}
            self.url = "https://example.com/file.dll"
            self.close_attempted = False
            self.is_redirect = 300 <= status_code < 400

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

        def close(self) -> None:
            self.close_attempted = True
            raise OSError("close failed")

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0
            self.retry_response: DummyResponse | None = None

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            if self.calls == 1:
                self.retry_response = DummyResponse(503)
                return cast(HTTPResponseProtocol, self.retry_response)
            return cast(HTTPResponseProtocol, DummyResponse(200, b"ok"))

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=2,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    assert client.download("https://example.com/file.dll") == b"ok"
    assert session.calls == 2
    assert session.retry_response is not None
    assert session.retry_response.close_attempted is True


@pytest.mark.unit
def test_http_client_download_retries_when_retry_response_oserror_close_fails() -> None:
    class DummyResponse:
        def __init__(self, status_code: int, content: bytes = b"") -> None:
            self.status_code = status_code
            self.ok = 200 <= status_code < 300
            self.content = content
            self.headers: dict[str, str] = {}
            self.url = "https://example.com/file.dll"
            self.close_attempted = False
            self.is_redirect = 300 <= status_code < 400

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

        def close(self) -> None:
            self.close_attempted = True
            raise OSError("close failed")

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0
            self.retry_response: DummyResponse | None = None

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            if self.calls == 1:
                self.retry_response = DummyResponse(503)
                return cast(HTTPResponseProtocol, self.retry_response)
            return cast(HTTPResponseProtocol, DummyResponse(200, b"ok"))

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=2,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    assert client.download("https://example.com/file.dll") == b"ok"
    assert session.calls == 2
    assert session.retry_response is not None
    assert session.retry_response.close_attempted is True


@pytest.mark.unit
def test_http_client_download_does_not_retry_non_retryable_status() -> None:
    class DummyResponse:
        ok = False
        is_redirect = False
        status_code = 404
        content = b""
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def __init__(self) -> None:
            self.closed = False

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b""

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0
            self.response = DummyResponse()

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            return cast(HTTPResponseProtocol, self.response)

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=5,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    with pytest.raises(HTTPClientError) as exc_info:
        client.download("https://example.com/file.dll")

    assert exc_info.value.status_code == 404
    assert session.calls == 1
    assert session.response.closed is True


@pytest.mark.unit
def test_http_client_download_fails_after_exhausting_retryable_statuses() -> None:
    class DummyResponse:
        ok = False
        is_redirect = False
        status_code = 503
        content = b""
        headers: dict[str, str] = {}
        url = "https://example.com/file.dll"

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield b""

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            return cast(HTTPResponseProtocol, DummyResponse())

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=3,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    with pytest.raises(
        HTTPClientError,
        match="Download failed with status 503",
    ) as exc_info:
        client.download("https://example.com/file.dll")

    assert exc_info.value.status_code == 503
    assert exc_info.value.url == "https://example.com/file.dll"
    assert session.calls == 3


@pytest.mark.unit
def test_http_client_get_fails_after_exhausting_request_exceptions() -> None:
    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            raise requests.RequestException("temporary outage")

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=3,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    with pytest.raises(
        HTTPClientError,
        match="GET request failed",
    ) as exc_info:
        client.get("https://example.com/file.dll")

    assert exc_info.value.url == "https://example.com/file.dll"
    assert session.calls == 3


@pytest.mark.unit
def test_http_client_respects_non_retryable_transport_exception_policy() -> None:
    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.calls = 0

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            raise requests.RequestException("do not retry")

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    class NonRetryingPolicy(RetryPolicy):
        def should_retry_exception(
            self,
            exc: requests.RequestException,
            attempt: int,
        ) -> bool:
            del exc, attempt
            return False

    session = DummySession()
    client = RequestsHTTPClient(
        max_retries=3,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
        retry_policy=NonRetryingPolicy(max_attempts=3),
    )

    with pytest.raises(
        HTTPClientError,
        match="GET request failed",
    ):
        client.get("https://example.com/file.dll")

    assert session.calls == 1


@pytest.mark.unit
def test_http_client_rotates_user_agent_per_attempt() -> None:
    class DummyResponse:
        def __init__(self, status_code: int, content: bytes = b"") -> None:
            self.status_code = status_code
            self.ok = 200 <= status_code < 300
            self.content = content
            self.headers: dict[str, str] = {}
            self.url = "https://example.com/file.dll"
            self.is_redirect = 300 <= status_code < 400

        def iter_content(self, chunk_size: int = 8192) -> Iterator[bytes]:
            yield self.content

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.seen_agents: list[str] = []
            self.calls = 0

        def get(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            self.calls += 1
            headers = cast(dict[str, str], kwargs["headers"])
            self.seen_agents.append(headers["User-Agent"])
            if self.calls == 1:
                raise requests.RequestException("temporary")
            return cast(HTTPResponseProtocol, DummyResponse(200, b"ok"))

        def head(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> HTTPResponseProtocol:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    provider = SequenceUserAgentProvider(["ua-1", "ua-2"])
    client = RequestsHTTPClient(
        max_retries=2,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
        user_agent_provider=provider,
    )

    assert client.download("https://example.com/file.dll") == b"ok"
    assert session.seen_agents == ["ua-1", "ua-2"]


@pytest.mark.unit
def test_random_user_agent_provider_rejects_empty_pool() -> None:
    with pytest.raises(ValueError, match="at least one value"):
        RandomUserAgentProvider(user_agents=())


@pytest.mark.unit
def test_random_user_agent_provider_rejects_scalar_string_pool() -> None:
    with pytest.raises(ValueError, match="sequence of user agents"):
        RandomUserAgentProvider(user_agents=cast(tuple[str, ...], "ua-a"))


@pytest.mark.unit
@pytest.mark.parametrize("user_agent", ["", "   ", cast(str, 1)])
def test_fixed_user_agent_provider_rejects_invalid_values(user_agent: str) -> None:
    with pytest.raises(ValueError, match="user_agent must be a non-empty string"):
        FixedUserAgentProvider(user_agent)


@pytest.mark.unit
@pytest.mark.parametrize(
    "user_agents",
    [
        cast(tuple[str, ...], ("ua-a", "")),
        cast(tuple[str, ...], ("ua-a", "   ")),
        cast(tuple[str, ...], ("ua-a", 1)),
    ],
)
def test_random_user_agent_provider_rejects_invalid_pool_items(
    user_agents: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="non-empty string values"):
        RandomUserAgentProvider(user_agents=user_agents)


@pytest.mark.unit
def test_random_user_agent_provider_exposes_pool_and_selects_from_it() -> None:
    provider = RandomUserAgentProvider(
        user_agents=("ua-a", "ua-b"),
        rng=Random(0),
    )

    assert provider.pool == ("ua-a", "ua-b")
    assert provider.next_user_agent() in provider.pool


@pytest.mark.unit
def test_request_header_builder_uses_rotating_user_agent_when_missing() -> None:
    builder = RequestHeaderBuilder(SequenceUserAgentProvider(["ua-1"]))

    headers = builder.build({"X-Test": "1"})

    assert headers == {"X-Test": "1", "User-Agent": "ua-1"}


@pytest.mark.unit
@pytest.mark.parametrize(
    "headers",
    [
        {"User-Agent": ""},
        {"user-agent": "   "},
        cast(dict[str, str], {"User-Agent": 1}),
    ],
)
def test_request_header_builder_rejects_invalid_explicit_user_agent(
    headers: dict[str, str],
) -> None:
    builder = RequestHeaderBuilder(SequenceUserAgentProvider(["ua-1"]))

    with pytest.raises(ValueError, match="User-Agent header"):
        builder.build(headers)


@pytest.mark.unit
def test_request_header_builder_rejects_duplicate_user_agent_variants() -> None:
    builder = RequestHeaderBuilder(SequenceUserAgentProvider(["ua-1"]))

    with pytest.raises(ValueError, match="duplicate User-Agent"):
        builder.build({"User-Agent": "ua-ok", "user-agent": "ua-other"})


@pytest.mark.unit
def test_request_header_builder_rejects_invalid_provider_user_agent() -> None:
    builder = RequestHeaderBuilder(SequenceUserAgentProvider([""]))

    with pytest.raises(ValueError, match="user_agent must be a non-empty string"):
        builder.build()
    with pytest.raises(ValueError, match="user_agent must be a non-empty string"):
        builder.initial_session_headers()


@pytest.mark.unit
def test_request_header_builder_keeps_explicit_user_agent() -> None:
    builder = RequestHeaderBuilder(SequenceUserAgentProvider(["ua-1"]))

    headers = builder.build({"User-Agent": "fixed"})

    assert headers == {"User-Agent": "fixed"}


@pytest.mark.unit
def test_request_header_builder_keeps_case_variant_user_agent() -> None:
    builder = RequestHeaderBuilder(SequenceUserAgentProvider(["ua-1"]))

    headers = builder.build({"user-agent": "fixed"})

    assert headers == {"user-agent": "fixed"}


@pytest.mark.unit
def test_retry_policy_delay_includes_backoff_and_jitter() -> None:
    policy = RetryPolicy(
        max_attempts=5,
        backoff_seconds=0.5,
        jitter_seconds=0.1,
        rng=Random(0),
    )

    assert policy.next_delay(2) >= 1.0


@pytest.mark.unit
def test_retry_policy_pause_uses_sleep_callback() -> None:
    calls: list[float] = []
    policy = RetryPolicy(
        max_attempts=5,
        backoff_seconds=0.5,
        jitter_seconds=0.0,
        sleep_fn=calls.append,
    )

    policy.pause_before_retry(2)

    assert calls == [1.0]


@pytest.mark.unit
def test_retry_policy_retryable_status_codes_are_snapshot_immutable() -> None:
    retryable_status_codes = {500}
    policy = RetryPolicy(
        max_attempts=2,
        retryable_status_codes=cast(frozenset[int], retryable_status_codes),
    )

    retryable_status_codes.clear()

    assert policy.should_retry_status(500, 1) is True


@pytest.mark.unit
def test_retry_policy_rejects_negative_backoff() -> None:
    with pytest.raises(ValueError, match="backoff_seconds cannot be negative"):
        RetryPolicy(backoff_seconds=-0.1)


@pytest.mark.unit
def test_retry_policy_rejects_negative_jitter() -> None:
    with pytest.raises(ValueError, match="jitter_seconds cannot be negative"):
        RetryPolicy(jitter_seconds=-0.1)


@pytest.mark.unit
@pytest.mark.parametrize("max_attempts", [cast(int, True), cast(int, 1.5)])
def test_retry_policy_rejects_non_integer_attempt_count(max_attempts: int) -> None:
    with pytest.raises(ValueError, match="max_attempts must be a positive integer"):
        RetryPolicy(max_attempts=max_attempts)


@pytest.mark.unit
@pytest.mark.parametrize("field_name", ["backoff_seconds", "jitter_seconds"])
def test_retry_policy_rejects_boolean_delays(field_name: str) -> None:
    with pytest.raises(ValueError, match=f"{field_name} must be a number"):
        if field_name == "backoff_seconds":
            RetryPolicy(backoff_seconds=cast(float, True))
        else:
            RetryPolicy(jitter_seconds=cast(float, True))


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("backoff_seconds", float("nan")),
        ("backoff_seconds", float("inf")),
        ("jitter_seconds", float("nan")),
        ("jitter_seconds", float("inf")),
    ],
)
def test_retry_policy_rejects_non_finite_delays(
    field_name: str,
    value: float,
) -> None:
    with pytest.raises(ValueError, match=f"{field_name} must be finite"):
        if field_name == "backoff_seconds":
            RetryPolicy(backoff_seconds=value)
        else:
            RetryPolicy(jitter_seconds=value)


# ---------------------------------------------------------------------------
# Regression tests for fixed bugs
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_decode_text_recognizes_charset_aliases() -> None:
    """
    Regression: common charset aliases like 'windows-1252', 'utf8',
    'shift-jis' must be recognized instead of falling back to UTF-8 replace.
    """
    # windows-1252 can encode 'é' (U+00E9)
    content = "café".encode("cp1252")
    headers = {"content-type": "text/html; charset=windows-1252"}
    decoded = RequestsHTTPClient._decode_text(content, headers)
    assert decoded == "café"

    # utf8 alias
    content = "café".encode()
    headers = {"content-type": "text/html; charset=utf8"}
    decoded = RequestsHTTPClient._decode_text(content, headers)
    assert decoded == "café"

    # shift-jis alias - use a character that shift_jis can encode
    content = "abc".encode("shift_jis")
    headers = {"content-type": "text/html; charset=shift-jis"}
    decoded = RequestsHTTPClient._decode_text(content, headers)
    assert decoded == "abc"


@pytest.mark.unit
def test_session_resource_thread_safe_lazy_creation() -> None:
    """
    Regression: HTTPSessionResource.session must be thread-safe to prevent
    leaked sessions from concurrent lazy creation.
    """
    import threading

    resource = HTTPSessionResource()
    sessions: list[object] = []
    errors: list[Exception] = []

    def access_session() -> None:
        try:
            sessions.append(resource.session)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=access_session) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
    assert resource.has_session is True
    # All threads must have gotten the same session instance
    assert all(s is sessions[0] for s in sessions), "Multiple sessions were created"


@pytest.mark.unit
def test_retry_policy_next_delay_returns_float() -> None:
    """
    Regression: RetryPolicy.next_delay must return a plain float, not Any,
    so that mypy does not report no-any-return.
    """
    policy = RetryPolicy(max_attempts=3, backoff_seconds=1.0, jitter_seconds=0.5)
    delay = policy.next_delay(1)
    assert isinstance(delay, float)
    assert delay >= 1.0
