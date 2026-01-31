# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Pytest configuration and shared fixtures for DLL-Downloader tests.

This module provides reusable fixtures for testing the DLL downloader
functionality, including temporary directories, sample files, and
test configurations.
"""

import os
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def tmp_download_dir() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test downloads.

    Yields:
        Path object pointing to a temporary directory that is automatically
        cleaned up after the test completes.

    Example:
        >>> def test_download(tmp_download_dir):
        ...     file_path = tmp_download_dir / "test.dll"
        ...     file_path.write_bytes(b"test content")
        ...     assert file_path.exists()
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_dll_file(tmp_download_dir: Path) -> Path:
    """
    Create a sample DLL file for testing.

    Creates a small binary file with a realistic PE header signature
    and known content for hash validation.

    Args:
        tmp_download_dir: Temporary directory fixture

    Returns:
        Path to the created sample DLL file
    """
    dll_path = tmp_download_dir / "test_library.dll"

    # Create a minimal PE header-like structure
    # MZ header (DOS stub) followed by test content
    content = (
        b'MZ\x90\x00'  # DOS signature
        b'\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
        + b'\x00' * 32  # Padding
        + b'PE\x00\x00'  # PE signature
        + b'Test DLL content for unit testing purposes.' * 10
    )

    dll_path.write_bytes(content)
    return dll_path


@pytest.fixture
def sample_zip_with_dll(tmp_download_dir: Path) -> Path:
    """
    Create a sample ZIP file containing a DLL.

    Args:
        tmp_download_dir: Temporary directory fixture

    Returns:
        Path to the created ZIP file
    """
    import zipfile

    zip_path = tmp_download_dir / "test_archive.zip"
    dll_content = b'MZ\x90\x00' + b'Test DLL inside ZIP' * 20

    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("test.dll", dll_content)

    return zip_path


@pytest.fixture
def mock_config() -> dict[str, Any]:
    """
    Provide a test configuration dictionary.

    Returns:
        Configuration dictionary with safe default values for testing

    Example:
        >>> def test_config_loading(mock_config):
        ...     vt_enabled = mock_config["virustotal"]["enabled"]
        ...     assert vt_enabled is False
    """
    return {
        "virustotal": {
            "api_key": "test_api_key_1234567890abcdef",
            "enabled": False,
            "timeout": 30
        },
        "download": {
            "extract_zip": True,
            "verify_hash": True
        }
    }


@pytest.fixture
def config_file(tmp_download_dir: Path, mock_config: dict[str, Any]) -> Path:
    """
    Create a temporary configuration file.

    Args:
        tmp_download_dir: Temporary directory fixture
        mock_config: Configuration dictionary fixture

    Returns:
        Path to the created configuration file

    Example:
        >>> def test_config_file_loading(config_file):
        ...     import json
        ...     with open(config_file) as f:
        ...         config = json.load(f)
        ...     assert "virustotal" in config
    """
    import json

    config_path = tmp_download_dir / ".config.json"
    config_path.write_text(json.dumps(mock_config, indent=2))
    return config_path


@pytest.fixture
def sample_html_file(tmp_download_dir: Path) -> Path:
    """
    Create a sample HTML file to test HTML detection.

    Args:
        tmp_download_dir: Temporary directory fixture

    Returns:
        Path to the created HTML file
    """
    html_path = tmp_download_dir / "error_page.html"
    content = b'<!DOCTYPE html><html><head><title>Error</title></head><body>Not Found</body></html>'
    html_path.write_bytes(content)
    return html_path


@pytest.fixture(autouse=True)
def reset_debug_mode() -> Generator[None, None, None]:
    """
    Automatically reset debug mode before and after each test.

    This fixture ensures that DEBUG_MODE environment variable doesn't
    leak between tests, providing test isolation.

    Yields:
        None
    """
    # Save original state
    original_debug = os.environ.get('DEBUG_MODE')

    # Reset to known state
    os.environ['DEBUG_MODE'] = '0'

    yield

    # Restore original state
    if original_debug is not None:
        os.environ['DEBUG_MODE'] = original_debug
    elif 'DEBUG_MODE' in os.environ:
        del os.environ['DEBUG_MODE']


@pytest.fixture
def empty_zip_file(tmp_download_dir: Path) -> Path:
    """
    Create an empty ZIP file for testing error conditions.

    Args:
        tmp_download_dir: Temporary directory fixture

    Returns:
        Path to the created empty ZIP file
    """
    import zipfile

    zip_path = tmp_download_dir / "empty.zip"
    with zipfile.ZipFile(zip_path, 'w'):
        pass  # Create empty ZIP

    return zip_path


@pytest.fixture
def test_http_server() -> Generator[int, None, None]:
    """
    Create a local HTTP server for testing real HTTP requests.

    Yields:
        Port number of the running test server
    """
    import http.server
    import socketserver
    import threading

    class TestHandler(http.server.SimpleHTTPRequestHandler):
        """Simple handler that serves test content."""

        TEST_CONTENT = b"<html><body>Test Content</body></html>"

        def do_GET(self) -> None:
            """Handle GET requests with test responses."""
            if self.path == "/test.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(self.TEST_CONTENT)))
                self.end_headers()
                self.wfile.write(self.TEST_CONTENT)
            else:
                self.send_response(404)
                self.end_headers()

        def do_HEAD(self) -> None:
            """Handle HEAD requests."""
            if self.path == "/test.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(self.TEST_CONTENT)))
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            """Suppress logging."""
            pass

    # Find available port
    with socketserver.TCPServer(("", 0), TestHandler) as httpd:
        port = httpd.server_address[1]

        # Start server in thread
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()

        yield port

        httpd.shutdown()


@pytest.fixture
def vt_mock_server() -> Generator[int, None, None]:
    """
    Create a mock VirusTotal API server for testing.

    Yields:
        Port number of the running mock VT server
    """
    import http.server
    import json
    import socketserver
    import threading

    class VTMockHandler(http.server.BaseHTTPRequestHandler):
        """Mock VirusTotal API handler."""

        def do_GET(self) -> None:
            """Handle GET requests with mock VT responses."""
            # Mock clean file response
            response = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 70,
                            "harmless": 2,
                            "timeout": 0
                        },
                        "last_analysis_results": {},
                        "last_analysis_date": 1706745600
                    }
                }
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps(response).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            """Suppress logging."""
            pass

    # Find available port
    with socketserver.TCPServer(("", 0), VTMockHandler) as httpd:
        port = httpd.server_address[1]

        # Start server in thread
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()

        yield port

        httpd.shutdown()
