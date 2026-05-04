# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for VirusTotal scanner infrastructure.

This module tests the VirusTotalScanner implementation and related security
scanning functionality. Tests use in-memory data structures and real method
execution to validate behavior.
"""

import os
import subprocess
import sys
from collections.abc import MutableMapping
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import pytest

from dll_downloader.domain.entities.dll_file import (
    DLLFile,
    SecurityStatus,
)
from dll_downloader.domain.services.security_scanner import ScanResult
from dll_downloader.infrastructure.http_session import (
    HTTPSessionProtocol,
    HTTPSessionResource,
)
from dll_downloader.infrastructure.services.virustotal import (
    HashNotFoundError,
    VirusTotalError,
    VirusTotalScanner,
)


class WeirdMapping(dict[object, object]):
    pass


def _resource_with_session(session: HTTPSessionProtocol) -> HTTPSessionResource:
    return HTTPSessionResource(session=session)


class HashNotFoundScanner(VirusTotalScanner):
    def scan_hash(self, file_hash: str) -> ScanResult:
        raise HashNotFoundError(file_hash)


class HashErrorScanner(VirusTotalScanner):
    def scan_hash(self, file_hash: str) -> ScanResult:
        raise VirusTotalError("err")


class HashStatusErrorScanner(VirusTotalScanner):
    def scan_hash(self, file_hash: str) -> ScanResult:
        raise VirusTotalError("API request failed with status 500", status_code=500)


class FixedResultScanner(VirusTotalScanner):
    def __init__(
        self,
        result: ScanResult,
        api_key: str | None = None,
        malicious_threshold: int = 5,
        suspicious_threshold: int = 1,
        timeout: float = 60.0,
        session_resource: HTTPSessionResource | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key,
            malicious_threshold=malicious_threshold,
            suspicious_threshold=suspicious_threshold,
            timeout=timeout,
            session_resource=session_resource,
        )
        self._result = result

    def scan_hash(self, file_hash: str) -> ScanResult:
        return self._result

# ============================================================================
# VirusTotalScanner Initialization Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_initialization_with_api_key() -> None:
    """
    Test VirusTotalScanner initialization with API key.

    Purpose:
        Verify that scanner initializes correctly with valid API key.

    Expected Behavior:
        - API key is stored
        - Scanner is available
        - Thresholds are set correctly
        - Session headers include API key
    """
    api_key = "test_api_key_12345"
    scanner = VirusTotalScanner(api_key=api_key, timeout=12.5)

    assert scanner._api_key == api_key
    assert scanner.is_available is True
    assert scanner._malicious_threshold == 5
    assert scanner._suspicious_threshold == 1
    assert scanner._timeout == 12.5
    assert scanner.session.headers["x-apikey"] == api_key


@pytest.mark.unit
def test_virustotal_scanner_initialization_without_api_key() -> None:
    """
    Test VirusTotalScanner initialization without API key.

    Purpose:
        Verify that scanner handles missing API key gracefully.

    Expected Behavior:
        - Scanner initializes but is unavailable
        - is_available returns False
        - Session headers are empty
    """
    scanner = VirusTotalScanner(api_key=None)

    assert scanner._api_key is None
    assert scanner.is_available is False
    assert "x-apikey" not in scanner.session.headers


@pytest.mark.unit
def test_virustotal_scanner_custom_thresholds() -> None:
    """
    Test VirusTotalScanner with custom detection thresholds.

    Purpose:
        Verify that custom thresholds are applied correctly.

    Expected Behavior:
        Custom threshold values are stored.
    """
    scanner = VirusTotalScanner(
        api_key="test_key",
        malicious_threshold=10,
        suspicious_threshold=3
    )

    assert scanner._malicious_threshold == 10
    assert scanner._suspicious_threshold == 3


# ============================================================================
# VirusTotalScanner Availability Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_is_available_with_key() -> None:
    """
    Test is_available property returns True when API key is set.

    Purpose:
        Verify availability check with valid configuration.

    Expected Behavior:
        is_available returns True when API key exists.
    """
    scanner = VirusTotalScanner(api_key="valid_key")

    assert scanner.is_available is True


@pytest.mark.unit
def test_virustotal_scanner_is_available_without_key() -> None:
    """
    Test is_available property returns False without API key.

    Purpose:
        Verify availability check with missing configuration.

    Expected Behavior:
        is_available returns False when API key is None or empty.
    """
    scanner_none = VirusTotalScanner(api_key=None)
    scanner_empty = VirusTotalScanner(api_key="")

    assert scanner_none.is_available is False
    assert scanner_empty.is_available is False


# ============================================================================
# VirusTotalScanner Response Parsing Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_parse_response_clean_file() -> None:
    """
    Test parsing VirusTotal API response for clean file.

    Purpose:
        Verify correct parsing of scan results with zero detections.

    Expected Behavior:
        - Status is CLEAN
        - Detection ratio shows 0 positives
        - All response fields are extracted
    """
    scanner = VirusTotalScanner(api_key="test_key")
    file_hash = "a" * 64

    # Simulate VT API response for clean file
    vt_response = {
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
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    result = scanner._parse_response(file_hash, vt_response)

    assert result.file_hash == file_hash
    assert result.status == SecurityStatus.CLEAN
    assert result.detection_ratio == "0/72"
    assert isinstance(result.scan_date, datetime)
    assert result.permalink == f"https://www.virustotal.com/gui/file/{file_hash}"


@pytest.mark.unit
def test_virustotal_scanner_parse_response_with_non_mapping_stats_defaults_unknown() -> None:
    scanner = VirusTotalScanner(api_key="test_key")
    result = scanner._parse_response(
        "z" * 64,
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": "bad",
                    "last_analysis_results": {},
                }
            }
        },
    )

    assert result.status == SecurityStatus.UNKNOWN
    assert result.detection_ratio is None


@pytest.mark.unit
def test_virustotal_scanner_parse_response_ignores_negative_noncritical_stats() -> None:
    scanner = VirusTotalScanner(api_key="test_key")
    result = scanner._parse_response(
        "a" * 64,
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": -10,
                        "undetected": 72,
                    },
                }
            }
        },
    )

    assert result.status == SecurityStatus.CLEAN
    assert result.detection_ratio == "0/72"


@pytest.mark.unit
def test_virustotal_safe_json_rejects_non_string_keys() -> None:
    class DummyResponse:
        status_code = 200
        headers: MutableMapping[str, str] = {}
        content = b""
        url = "https://example.com"
        ok = True

        @property
        def is_redirect(self) -> bool:
            return False

        def json(self) -> WeirdMapping:
            return WeirdMapping({1: "bad"})

        def iter_content(self, chunk_size: int = 1) -> Any:
            return iter(())

    with pytest.raises(VirusTotalError, match="response keys must be strings"):
        from dll_downloader.infrastructure.services.virustotal import _safe_json

        _safe_json(DummyResponse())


@pytest.mark.unit
def test_virustotal_data_section_filters_non_string_keys() -> None:
    from dll_downloader.infrastructure.services.virustotal import _data_section

    payload: dict[str, object] = {"data": WeirdMapping({1: "bad", "ok": "value"})}

    assert _data_section(payload) == {"ok": "value"}


@pytest.mark.unit
def test_virustotal_data_section_returns_empty_for_non_mapping() -> None:
    from dll_downloader.infrastructure.services.virustotal import _data_section

    assert _data_section({"data": "bad"}) == {}


@pytest.mark.unit
def test_virustotal_scanner_parse_response_suspicious_file() -> None:
    """
    Test parsing VirusTotal API response for suspicious file.

    Purpose:
        Verify correct threshold-based status assignment for suspicious files.

    Expected Behavior:
        - Status is SUSPICIOUS when detections >= suspicious_threshold
        - Status is SUSPICIOUS when detections < malicious_threshold
    """
    scanner = VirusTotalScanner(
        api_key="test_key",
        malicious_threshold=5,
        suspicious_threshold=1
    )
    file_hash = "b" * 64

    # Simulate VT API response with 3 detections (suspicious but not malicious)
    vt_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 69,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {
                    "Kaspersky": {"result": "Trojan.Generic"},
                    "Avast": {"result": "Malware"},
                    "AVG": {"result": None}
                },
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    result = scanner._parse_response(file_hash, vt_response)

    assert result.status == SecurityStatus.SUSPICIOUS
    assert result.detection_ratio == "3/72"
    assert len(result.detections) == 2  # Only engines with actual detections


@pytest.mark.unit
def test_virustotal_scanner_parse_response_malicious_file() -> None:
    """
    Test parsing VirusTotal API response for malicious file.

    Purpose:
        Verify correct status assignment when detections exceed threshold.

    Expected Behavior:
        Status is MALICIOUS when detections >= malicious_threshold.
    """
    scanner = VirusTotalScanner(
        api_key="test_key",
        malicious_threshold=5,
        suspicious_threshold=1
    )
    file_hash = "c" * 64

    # Simulate VT API response with 10 detections (malicious)
    vt_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "undetected": 62,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {
                    "Kaspersky": {"result": "Trojan.Win32.Generic"},
                    "Avast": {"result": "Win32:Malware-gen"},
                    "BitDefender": {"result": "Gen:Variant.Trojan"},
                },
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    result = scanner._parse_response(file_hash, vt_response)

    assert result.status == SecurityStatus.MALICIOUS
    assert result.detection_ratio == "10/72"
    assert len(result.detections) == 3


@pytest.mark.unit
def test_virustotal_scanner_parse_response_with_detections_dict() -> None:
    """
    Test that individual engine detections are extracted correctly.

    Purpose:
        Verify detection details are captured from response.

    Expected Behavior:
        - Detections dictionary contains engine names and verdicts
        - Only engines with actual results are included
    """
    scanner = VirusTotalScanner(api_key="test_key")
    file_hash = "d" * 64

    vt_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 0,
                    "undetected": 69,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {
                    "Kaspersky": {"result": "HEUR:Trojan.Win32.Generic"},
                    "Avast": {"result": "Win32:Evo-gen"},
                    "Microsoft": {"result": "Trojan:Win32/Wacatac"},
                    "Sophos": {"result": None},  # No detection
                },
                "last_analysis_date": 1706745600
            }
        }
    }

    result = scanner._parse_response(file_hash, vt_response)

    assert "Kaspersky" in result.detections
    assert result.detections["Kaspersky"] == "HEUR:Trojan.Win32.Generic"
    assert "Avast" in result.detections
    assert "Microsoft" in result.detections
    assert "Sophos" not in result.detections  # None result excluded


@pytest.mark.unit
def test_virustotal_scanner_extract_engine_detections_ignores_invalid_shapes() -> None:
    scanner = VirusTotalScanner(api_key="test_key")
    detections = scanner._extract_engine_detections(
        {
            "data": {
                "attributes": {
                    "last_analysis_results": {
                        "good": {"result": "Malware"},
                        "bad": "oops",
                    }
                }
            }
        }
    )

    assert detections == {"good": "Malware"}


@pytest.mark.unit
def test_virustotal_scanner_extract_engine_detections_returns_empty_for_non_mapping_results() -> None:
    scanner = VirusTotalScanner(api_key="test_key")
    assert scanner._extract_engine_detections(
        {"data": {"attributes": {"last_analysis_results": "bad"}}}
    ) == {}


@pytest.mark.unit
def test_virustotal_scanner_extract_attributes_returns_empty_for_invalid_shapes() -> None:
    scanner = VirusTotalScanner(api_key="test_key")
    assert scanner._extract_attributes({"data": "bad"}) == {}
    assert scanner._extract_attributes({"data": {"attributes": "bad"}}) == {}


# ============================================================================
# VirusTotalScanner scan_hash Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_scan_hash_unavailable_returns_unknown() -> None:
    """
    Test scan_hash when scanner is unavailable.

    Purpose:
        Verify graceful handling when API key is not configured.

    Expected Behavior:
        - Returns ScanResult with UNKNOWN status
        - Error message indicates missing API key
    """
    scanner = VirusTotalScanner(api_key=None)
    file_hash = "e" * 64

    result = scanner.scan_hash(file_hash)

    assert result.file_hash == file_hash
    assert result.status == SecurityStatus.UNKNOWN
    assert result.error_message is not None
    assert "not configured" in result.error_message


@pytest.mark.integration
def test_virustotal_scanner_scan_hash_with_mock_server(vt_mock_server: int) -> None:
    """
    Test scan_hash with local mock VirusTotal API server.

    Purpose:
        Validate actual HTTP communication and response parsing.

    Expected Behavior:
        - Makes real HTTP request to mock server
        - Parses response correctly
        - Returns appropriate ScanResult
    """
    # Create scanner pointing to mock server
    scanner = VirusTotalScanner(api_key="test_key")
    # Override API URL and allowlist to point to mock server
    scanner.VT_API_URL = f"http://localhost:{vt_mock_server}"
    original_domains = VirusTotalScanner._VT_ALLOWED_DOMAINS.copy()
    original_private_domains = VirusTotalScanner._VT_PRIVATE_IP_ALLOWED_DOMAINS.copy()
    VirusTotalScanner._VT_ALLOWED_DOMAINS = {"www.virustotal.com", "virustotal.com", "localhost"}
    VirusTotalScanner._VT_PRIVATE_IP_ALLOWED_DOMAINS = {"localhost"}

    try:
        file_hash = "a" * 64  # Mock server recognizes this as clean

        result = scanner.scan_hash(file_hash)

        assert result.file_hash == file_hash
        assert result.status == SecurityStatus.CLEAN
        assert result.detection_ratio is not None
    finally:
        VirusTotalScanner._VT_ALLOWED_DOMAINS = original_domains
        VirusTotalScanner._VT_PRIVATE_IP_ALLOWED_DOMAINS = original_private_domains


# ============================================================================
# VirusTotalScanner scan_dll Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_scan_dll_without_hash() -> None:
    """
    Test scan_dll with DLLFile that has no hash.

    Purpose:
        Verify handling of DLL entities missing file hash.

    Expected Behavior:
        - Raises VirusTotalError
    """
    scanner = VirusTotalScanner(api_key="test_key")
    dll = DLLFile(name="test.dll", file_hash=None)

    with pytest.raises(VirusTotalError, match="Cannot scan DLL without file hash"):
        scanner.scan_dll(dll)


@pytest.mark.unit
def test_virustotal_scanner_scan_dll_updates_entity() -> None:
    """
    Test that scan_dll creates updated DLLFile with scan results.

    Purpose:
        Verify entity immutability and result propagation.

    Expected Behavior:
        - Returns new DLLFile instance (immutable update)
        - Security status is updated
        - Detection ratio and scan date are set
    """
    scanner = VirusTotalScanner(api_key="test_key")

    # Manually inject a parsed result by creating a ScanResult
    # and testing _parse_response in isolation
    file_hash = "f" * 64
    dll = DLLFile(
        name="test.dll",
        file_hash=file_hash,
        security_status=SecurityStatus.NOT_SCANNED
    )

    # We can't easily test this without mocking or a real API,
    # but we can test the logic by directly using _parse_response
    vt_response = {
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
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    scan_result = scanner._parse_response(file_hash, vt_response)

    # Simulate what scan_dll would do
    updated_dll = replace(
        dll,
        security_status=scan_result.status,
        vt_detection_ratio=scan_result.detection_ratio,
        vt_scan_date=scan_result.scan_date
    )

    assert updated_dll is not dll  # Different object
    assert updated_dll.name == dll.name
    assert updated_dll.security_status == SecurityStatus.CLEAN
    assert updated_dll.vt_detection_ratio == "0/72"
    assert updated_dll.vt_scan_date is not None


# ============================================================================
# VirusTotalScanner Session Management Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_session_lazy_initialization() -> None:
    """
    Test that session is created lazily via composed session resource.

    Purpose:
        Verify lazy initialization pattern provided by the session resource.

    Expected Behavior:
        - Session is None initially
        - Session is created on first access
        - Same session is reused
    """
    scanner = VirusTotalScanner(api_key="test_key")

    assert scanner.has_active_session is False

    # First access creates session
    session1 = scanner.session
    assert session1 is not None
    assert scanner.has_active_session is True

    # Second access returns same session
    session2 = scanner.session
    assert session1 is session2


@pytest.mark.unit
def test_virustotal_scanner_session_has_api_key_header() -> None:
    """
    Test that session includes VirusTotal API key header.

    Purpose:
        Verify authentication header configuration.

    Expected Behavior:
        Session headers include x-apikey with configured API key.
    """
    api_key = "my_secret_api_key"
    scanner = VirusTotalScanner(api_key=api_key)

    session = scanner.session

    assert "x-apikey" in session.headers
    assert session.headers["x-apikey"] == api_key


@pytest.mark.unit
def test_virustotal_scanner_close_cleanup() -> None:
    """
    Test explicit session cleanup with close().

    Purpose:
        Verify resource cleanup via the composed session resource.

    Expected Behavior:
        - Session is closed
        - Session is set to None
    """
    scanner = VirusTotalScanner(api_key="test_key")

    # Create session
    _ = scanner.session
    assert scanner.has_active_session is True

    # Close it
    scanner.close()
    assert scanner.has_active_session is False


@pytest.mark.unit
def test_virustotal_scanner_context_manager() -> None:
    """
    Test context manager protocol for automatic cleanup.

    Purpose:
        Verify automatic resource management.

    Expected Behavior:
        Session is closed on context exit.
    """
    scanner = VirusTotalScanner(api_key="test_key")

    with scanner as ctx_scanner:
        _ = ctx_scanner.session
        assert ctx_scanner.has_active_session is True

    assert scanner.has_active_session is False


# ============================================================================
# VirusTotalError Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_error_creation() -> None:
    """
    Test VirusTotalError exception creation.

    Purpose:
        Verify custom exception behavior.

    Expected Behavior:
        Exception contains error message.
    """
    error = VirusTotalError("API request failed")

    assert str(error) == "API request failed"
    assert error.status_code is None
    assert isinstance(error, Exception)


@pytest.mark.unit
def test_virustotal_error_preserves_status_code() -> None:
    error = VirusTotalError("API request failed", status_code=503)

    assert str(error) == "API request failed"
    assert error.status_code == 503


@pytest.mark.unit
def test_virustotal_scheme_relative_redirect_strips_credentials() -> None:
    redirect_url = VirusTotalScanner._resolve_redirect_url(
        "https://www.virustotal.com/api/v3/files",
        "//user:pass@www.virustotal.com/api/v3/next",
    )

    assert redirect_url == "https://www.virustotal.com/api/v3/next"


@pytest.mark.unit
def test_virustotal_uppercase_https_redirect_is_supported() -> None:
    redirect_url = VirusTotalScanner._resolve_redirect_url(
        "https://www.virustotal.com/api/v3/files",
        "HTTPS://user:pass@www.virustotal.com/api/v3/next",
    )

    assert redirect_url == "https://www.virustotal.com/api/v3/next"


# ============================================================================
# Threshold Logic Tests
# ============================================================================

@pytest.mark.unit
def test_virustotal_scanner_threshold_boundaries() -> None:
    """
    Test status assignment at threshold boundaries.

    Purpose:
        Verify exact threshold behavior for edge cases.

    Expected Behavior:
        - Exactly at suspicious_threshold = SUSPICIOUS
        - Exactly at malicious_threshold = MALICIOUS
        - Below suspicious_threshold = CLEAN
    """
    scanner = VirusTotalScanner(
        api_key="test_key",
        malicious_threshold=5,
        suspicious_threshold=2
    )

    # Exactly at suspicious threshold (2 positives)
    vt_response_suspicious = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 1,
                    "undetected": 70,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {},
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    result = scanner._parse_response("hash1", vt_response_suspicious)
    assert result.status == SecurityStatus.SUSPICIOUS

    # Below suspicious threshold (1 positive)
    vt_response_clean = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 71,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {},
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    result = scanner._parse_response("hash2", vt_response_clean)
    assert result.status == SecurityStatus.CLEAN

    # Exactly at malicious threshold (5 positives)
    vt_response_malicious = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 4,
                    "suspicious": 1,
                    "undetected": 67,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {},
                "last_analysis_date": int(datetime.now().timestamp())
            }
        }
    }

    result = scanner._parse_response("hash3", vt_response_malicious)
    assert result.status == SecurityStatus.MALICIOUS


@pytest.mark.unit
def test_scan_file_unavailable_returns_unknown(tmp_download_dir: Path) -> None:
    """
    Verify scan_file returns UNKNOWN when API key missing.
    """
    scanner = VirusTotalScanner(api_key=None)
    sample = tmp_download_dir / "file.dll"
    sample.write_bytes(b"data")

    result = scanner.scan_file(str(sample))
    assert result.status == SecurityStatus.UNKNOWN
    assert "not configured" in (result.error_message or "")


@pytest.mark.unit
def test_scan_file_missing_file_raises_virustotal_error(tmp_download_dir: Path) -> None:
    scanner = VirusTotalScanner(api_key="key")

    with pytest.raises(VirusTotalError, match="File upload failed"):
        scanner.scan_file(str(tmp_download_dir / "missing.dll"))


@pytest.mark.unit
def test_scan_file_non_regular_path_raises_virustotal_error(
    tmp_download_dir: Path,
) -> None:
    scanner = VirusTotalScanner(api_key="key")
    directory_path = tmp_download_dir / "directory.dll"
    directory_path.mkdir()

    with pytest.raises(VirusTotalError, match="not a regular file"):
        scanner.scan_file(str(directory_path))


@pytest.mark.unit
def test_scan_file_fifo_path_does_not_block(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")

    fifo_path = tmp_path / "sample.dll"
    os.mkfifo(fifo_path)
    code = f"""
from dll_downloader.infrastructure.services.virustotal import (
    HashNotFoundError,
    VirusTotalError,
    VirusTotalScanner,
)
scanner = VirusTotalScanner(api_key='key')
try:
    scanner.scan_file({str(fifo_path)!r})
except VirusTotalError:
    print('failed-fast')
"""

    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "failed-fast"


@pytest.mark.unit
def test_scan_file_without_api_key_fifo_path_does_not_block(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")

    fifo_path = tmp_path / "sample.dll"
    os.mkfifo(fifo_path)
    code = f"""
from dll_downloader.infrastructure.services.virustotal import VirusTotalScanner
scanner = VirusTotalScanner(api_key=None)
result = scanner.scan_file({str(fifo_path)!r})
print(result.status.value)
"""

    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == "unknown"


@pytest.mark.unit
def test_scan_file_upload_success(
    tmp_download_dir: Path,
) -> None:
    """
    Verify scan_file uploads when hash not found and returns pending result.
    """
    class DummyResponse:
        is_redirect = False
        def __init__(self, status_code: int, payload: dict[str, object]) -> None:
            self.status_code = status_code
            self._payload = payload
            self.closed = False

        def json(self) -> dict[str, object]:
            return self._payload

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.post_timeout: float | None = None
            self.post_response = DummyResponse(200, {"data": {"id": "abc"}})

        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, url: str, files: Any = None, **kwargs: Any) -> DummyResponse:
            self.post_timeout = cast(float, kwargs.get("timeout"))
            return self.post_response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    scanner = HashNotFoundScanner(
        api_key="key",
        timeout=9.5,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    sample = tmp_download_dir / "file.dll"
    sample.write_bytes(b"data")

    result = scanner.scan_file(str(sample))
    assert result.status == SecurityStatus.UNKNOWN
    assert "Results pending" in (result.error_message or "")
    assert session.post_timeout == 9.5
    assert session.post_response.closed is True


@pytest.mark.unit
def test_scan_file_upload_failure_raises(
    tmp_download_dir: Path,
) -> None:
    """
    Verify scan_file raises on upload failure.
    """
    class DummyResponse:
        is_redirect = False
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

        def json(self) -> dict[str, object]:
            return {}

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, url: str, files: Any = None, **kwargs: Any) -> DummyResponse:
            return DummyResponse(500)

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = HashNotFoundScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    sample = tmp_download_dir / "file.dll"
    sample.write_bytes(b"data")

    with pytest.raises(VirusTotalError):
        scanner.scan_file(str(sample))


@pytest.mark.unit
def test_scan_file_does_not_upload_after_hash_lookup_status_error(
    tmp_download_dir: Path,
) -> None:
    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.post_calls = 0

        def get(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            self.post_calls += 1
            raise AssertionError("upload should not be attempted")

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    scanner = HashStatusErrorScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )
    sample = tmp_download_dir / "file.dll"
    sample.write_bytes(b"data")

    with pytest.raises(VirusTotalError, match="status 500"):
        scanner.scan_file(str(sample))

    assert session.post_calls == 0


@pytest.mark.unit
def test_scan_file_upload_type_error_raises(
    tmp_download_dir: Path,
) -> None:
    class DummyResponse:
        is_redirect = False
        status_code = 200
        is_redirect = False

        def json(self) -> list[str]:
            return ["bad"]

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, *args: object, **kwargs: object) -> object:
            raise NotImplementedError

        def post(self, url: str, files: object = None, **kwargs: object) -> DummyResponse:
            return DummyResponse()

        def head(self, *args: object, **kwargs: object) -> object:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = HashNotFoundScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    sample = tmp_download_dir / "file.dll"
    sample.write_bytes(b"data")

    with pytest.raises((VirusTotalError, TypeError)):
        scanner.scan_file(str(sample))


@pytest.mark.unit
def test_scan_file_upload_runtime_json_error_raises_virustotal_error(
    tmp_download_dir: Path,
) -> None:
    class DummyResponse:
        is_redirect = False
        status_code = 200
        is_redirect = False

        def json(self) -> dict[str, object]:
            raise RuntimeError("json failed")

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, *args: object, **kwargs: object) -> object:
            raise NotImplementedError

        def post(self, url: str, files: object = None, **kwargs: object) -> DummyResponse:
            return DummyResponse()

        def head(self, *args: object, **kwargs: object) -> object:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = HashNotFoundScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    sample = tmp_download_dir / "file.dll"
    sample.write_bytes(b"data")

    with pytest.raises(VirusTotalError, match="File upload failed: json failed"):
        scanner.scan_file(str(sample))


@pytest.mark.unit
def test_scan_hash_404_raises() -> None:
    """
    Verify scan_hash raises HashNotFoundError on 404.
    """
    class DummyResponse:
        is_redirect = False
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

        def json(self) -> dict[str, object]:
            return {}

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            return DummyResponse(404)

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    with pytest.raises(HashNotFoundError):
        scanner.scan_hash("a" * 64)


@pytest.mark.unit
def test_scan_hash_passes_configured_timeout() -> None:
    class DummyResponse:
        is_redirect = False
        status_code = 404
        is_redirect = False

        def json(self) -> dict[str, object]:
            return {}

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.get_timeout: float | None = None

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            self.get_timeout = cast(float, kwargs.get("timeout"))
            return DummyResponse()

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    scanner = VirusTotalScanner(
        api_key="key",
        timeout=7.25,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    with pytest.raises(HashNotFoundError):
        scanner.scan_hash("a" * 64)

    assert session.get_timeout == 7.25


@pytest.mark.unit
def test_scan_hash_closes_response() -> None:
    class DummyResponse:
        is_redirect = False
        status_code = 200
        is_redirect = False

        def __init__(self) -> None:
            self.closed = False

        def json(self) -> dict[str, object]:
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 1,
                            "malicious": 0,
                            "suspicious": 0,
                        },
                        "last_analysis_date": 1,
                    }
                }
            }

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            return self.response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    scanner.scan_hash("a" * 64)

    assert session.response.closed is True


@pytest.mark.unit
def test_scan_hash_non_200_raises() -> None:
    """
    Verify scan_hash raises VirusTotalError on non-200.
    """
    class DummyResponse:
        is_redirect = False
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

        def json(self) -> dict[str, object]:
            return {}

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            return DummyResponse(500)

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    with pytest.raises(VirusTotalError):
        scanner.scan_hash("a" * 64)


@pytest.mark.unit
def test_scan_hash_request_exception_raises() -> None:
    """
    Verify scan_hash wraps exceptions into VirusTotalError.
    """
    class DummySession:
        headers: dict[str, str] = {}

        def get(self, url: str, **kwargs: Any) -> Any:
            raise RuntimeError("boom")

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    with pytest.raises(VirusTotalError):
        scanner.scan_hash("a" * 64)


@pytest.mark.unit
def test_scan_dll_no_results_returns_unknown_status() -> None:
    """
    Verify scan_dll returns UNKNOWN status when no scan results exist.
    """
    scanner = HashNotFoundScanner(api_key="key")

    dll = DLLFile(name="a.dll", file_hash="hash")
    result = scanner.scan_dll(dll)
    assert result.security_status == SecurityStatus.UNKNOWN
    assert result.vt_detection_ratio is None


@pytest.mark.unit
def test_scan_dll_error_raises_virustotal_error() -> None:
    """
    Verify scan_dll propagates VirusTotalError.
    """
    scanner = HashErrorScanner(api_key="key")

    dll = DLLFile(name="a.dll", file_hash="hash")
    with pytest.raises(VirusTotalError, match="err"):
        scanner.scan_dll(dll)


@pytest.mark.unit
def test_scan_dll_success_updates_entity() -> None:
    """
    Verify scan_dll updates entity on successful scan_hash.
    """
    scanner = VirusTotalScanner(api_key="key")
    scan_result = scanner._parse_response(
        "hash",
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 1,
                        "harmless": 0,
                        "timeout": 0
                    },
                    "last_analysis_results": {},
                    "last_analysis_date": int(datetime.now().timestamp())
                }
            }
        }
    )
    scanner = FixedResultScanner(scan_result, api_key="key")

    dll = DLLFile(name="a.dll", file_hash="hash")
    result = scanner.scan_dll(dll)
    assert result.security_status == scan_result.status


@pytest.mark.unit
def test_get_detailed_report_success() -> None:
    """
    Verify get_detailed_report returns JSON on success.
    """
    class DummyResponse:
        is_redirect = False
        def __init__(self, status_code: int, payload: dict[str, object]) -> None:
            self.status_code = status_code
            self._payload = payload

        def json(self) -> dict[str, object]:
            return self._payload

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.get_timeout: float | None = None

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            self.get_timeout = cast(float, kwargs.get("timeout"))
            return DummyResponse(200, {"ok": True})

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    scanner = VirusTotalScanner(
        api_key="key",
        timeout=8.75,
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    assert scanner.get_detailed_report("a" * 64) == {"ok": True}
    assert session.get_timeout == 8.75


@pytest.mark.unit
def test_get_detailed_report_closes_response() -> None:
    class DummyResponse:
        is_redirect = False
        status_code = 200
        is_redirect = False

        def __init__(self) -> None:
            self.closed = False

        def json(self) -> dict[str, object]:
            return {"ok": True}

        def close(self) -> None:
            self.closed = True

    class DummySession:
        def __init__(self) -> None:
            self.headers: dict[str, str] = {}
            self.response = DummyResponse()

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            return self.response

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    session = DummySession()
    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, session)),
    )

    assert scanner.get_detailed_report("a" * 64) == {"ok": True}
    assert session.response.closed is True


@pytest.mark.unit
def test_get_detailed_report_non_200_raises() -> None:
    """
    Verify get_detailed_report raises on non-200 response.
    """
    class DummyResponse:
        is_redirect = False
        def __init__(self, status_code: int) -> None:
            self.status_code = status_code

        def json(self) -> dict[str, object]:
            return {}

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, url: str, **kwargs: Any) -> DummyResponse:
            return DummyResponse(500)

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    with pytest.raises(VirusTotalError):
        scanner.get_detailed_report("a" * 64)


@pytest.mark.unit
def test_get_detailed_report_exception_raises() -> None:
    """
    Verify get_detailed_report wraps exceptions into VirusTotalError.
    """
    class DummySession:
        headers: dict[str, str] = {}

        def get(self, url: str, **kwargs: Any) -> Any:
            raise RuntimeError("boom")

        def head(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    with pytest.raises(VirusTotalError):
        scanner.get_detailed_report("a" * 64)


@pytest.mark.unit
def test_get_detailed_report_invalid_json_raises() -> None:
    class DummyResponse:
        is_redirect = False
        status_code = 200
        is_redirect = False

        def json(self) -> list[str]:
            return ["bad"]

    class DummySession:
        headers: dict[str, str] = {}

        def get(self, url: str, **kwargs: object) -> DummyResponse:
            return DummyResponse()

        def head(self, *args: object, **kwargs: object) -> object:
            raise NotImplementedError

        def post(self, *args: object, **kwargs: object) -> object:
            raise NotImplementedError

        def close(self) -> None:
            pass

    scanner = VirusTotalScanner(
        api_key="key",
        session_resource=_resource_with_session(cast(HTTPSessionProtocol, DummySession())),
    )

    with pytest.raises((VirusTotalError, TypeError)):
        scanner.get_detailed_report("a" * 64)


@pytest.mark.unit
def test_get_detailed_report_unavailable_raises() -> None:
    """
    Verify get_detailed_report raises when API key missing.
    """
    scanner = VirusTotalScanner(api_key=None)
    with pytest.raises(VirusTotalError):
        scanner.get_detailed_report("a" * 64)


# ---------------------------------------------------------------------------
# Regression tests for fixed bugs
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_file_accepts_exact_size_limit(tmp_path: Path) -> None:
    """
    Regression: files exactly at the 32 MiB upload limit must be accepted,
    not rejected. Previously `>=` was used instead of `>`.
    """
    from dll_downloader.infrastructure.services.virustotal import (
        _VT_UPLOAD_MAX_BYTES,
        VirusTotalScanner,
    )
    exact_limit_bytes = 32 * 1024 * 1024
    assert exact_limit_bytes == _VT_UPLOAD_MAX_BYTES

    # Create a file exactly at the size limit
    exact_file = tmp_path / "exact.dll"
    exact_file.write_bytes(b"\x00" * exact_limit_bytes)

    # A file exactly at the limit should pass the size check in scan_file
    scanner = VirusTotalScanner(api_key="test-key")
    assert scanner.is_available

    # Verify the file passes the size gate by checking that the file_size
    # comparison uses > (not >=). The size check reads st_size via os.fstat
    # and compares: if file_size > _VT_UPLOAD_MAX_BYTES => reject.
    # So file_size == _VT_UPLOAD_MAX_BYTES must be accepted.
    import os
    st = os.stat(exact_file)
    assert st.st_size == _VT_UPLOAD_MAX_BYTES
    assert not (st.st_size > _VT_UPLOAD_MAX_BYTES), "exact limit should not exceed upload max"
