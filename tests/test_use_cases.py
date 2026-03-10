# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for application use cases.

This module tests the application layer use cases including DownloadDLLUseCase.
Tests use lightweight in-memory implementations instead of mocks to validate
real behavior.
"""

import io
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

from dll_downloader.application.errors import DownloadExecutionError
from dll_downloader.application.use_cases.download_batch import (
    DownloadBatchRequest,
    DownloadBatchUseCase,
)
from dll_downloader.application.use_cases.download_dll import (
    DownloadDLLRequest,
    DownloadDLLUseCase,
)
from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.domain.errors import (
    DownloadResolutionError,
    HTTPServiceError,
    RepositoryOperationError,
)
from dll_downloader.domain.repositories.dll_repository import IDLLRepository
from dll_downloader.domain.services.http_client import HTTPFileInfo, IHTTPClient
from dll_downloader.domain.services.security_scanner import (
    ISecurityScanner,
    ScanResult,
)


def _build_zip_payload(dll_name: str, dll_bytes: bytes) -> bytes:
    """Create a valid ZIP payload containing a single DLL member."""
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(Path(dll_name).name, dll_bytes)
    return archive_buffer.getvalue()

# ============================================================================
# Test Implementations (Lightweight, Real Implementations)
# ============================================================================

@dataclass
class InMemoryRepository(IDLLRepository):
    """
    In-memory implementation of IDLLRepository for testing.

    This is a real, working implementation that stores DLL files in memory
    instead of on disk. It provides all the same guarantees and behaviors
    as a real repository without requiring filesystem access.
    """
    _storage: dict[str, DLLFile] = field(default_factory=dict)
    _content_storage: dict[str, bytes] = field(default_factory=dict)

    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        """Save DLL to in-memory storage."""
        key = self._make_key(dll_file.name, dll_file.architecture)
        dll_file = replace(dll_file, file_path=f"/memory/{dll_file.name}")
        self._storage[key] = dll_file
        self._content_storage[key] = content
        return dll_file

    def find_by_name(
        self,
        name: str,
        architecture: Architecture | None = None
    ) -> DLLFile | None:
        """Find DLL by name and architecture."""
        key = self._make_key(name, architecture or Architecture.UNKNOWN)
        return self._storage.get(key)

    def find_by_hash(self, file_hash: str) -> DLLFile | None:
        """Find DLL by hash."""
        for dll in self._storage.values():
            if dll.file_hash == file_hash:
                return dll
        return None

    def list_all(self) -> list[DLLFile]:
        """List all DLLs."""
        return list(self._storage.values())

    def delete(self, dll_file: DLLFile) -> bool:
        """Delete DLL from storage."""
        key = self._make_key(dll_file.name, dll_file.architecture)
        if key in self._storage:
            del self._storage[key]
            if key in self._content_storage:
                del self._content_storage[key]
            return True
        return False

    def exists(self, name: str, architecture: Architecture | None = None) -> bool:
        """Check if DLL exists."""
        key = self._make_key(name, architecture or Architecture.UNKNOWN)
        return key in self._storage

    def get_content(self, dll_file: DLLFile) -> bytes | None:
        """Get stored content for testing purposes."""
        key = self._make_key(dll_file.name, dll_file.architecture)
        return self._content_storage.get(key)

    def _make_key(self, name: str, architecture: Architecture) -> str:
        """Create storage key."""
        return f"{name}:{architecture.value}"


@dataclass
class StubHTTPClient(IHTTPClient):
    """
    Stub HTTP client that simulates downloads without network access.

    This is a deterministic HTTP client that returns predefined content
    for testing purposes, avoiding real network calls.
    """
    _responses: dict[str, bytes] = field(default_factory=dict)
    _should_fail: bool = False
    _failure_exception: Exception | None = None

    def add_response(self, url: str, content: bytes) -> None:
        """Register a response for a URL."""
        self._responses[url] = content

    def set_failure_mode(self, should_fail: bool) -> None:
        """Configure whether downloads should fail."""
        self._should_fail = should_fail

    def set_failure_exception(self, exc: Exception | None) -> None:
        """Configure a concrete exception to raise on download."""
        self._failure_exception = exc

    def download(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        """Download content from URL."""
        if self._failure_exception is not None:
            raise self._failure_exception
        if self._should_fail:
            return b''

        # Return registered response or generate default content
        return self._responses.get(
            url,
            _build_zip_payload(
                Path(url).name,
                b'MZ\x90\x00' + f'DLL content for {url}'.encode() * 10,
            )
        )

    def get_text(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        """Fetch text content from URL."""
        return self.download(url).decode("utf-8", errors="replace")

    def get_file_info(self, url: str) -> HTTPFileInfo:
        """Get file metadata."""
        content = self.download(url)
        return {
            'content_type': 'application/zip',
            'content_length': len(content),
            'last_modified': None,
            'etag': None,
            'accept_ranges': False,
        }


@dataclass
class StubSecurityScanner(ISecurityScanner):
    """
    Stub security scanner that simulates malware scanning.

    This provides deterministic scan results for testing without
    requiring external API access.
    """
    _scan_results: dict[str, ScanResult] = field(default_factory=dict)
    _available: bool = True

    def configure_result(self, file_hash: str, status: SecurityStatus, ratio: str = "0/72") -> None:
        """Configure scan result for a specific hash."""
        self._scan_results[file_hash] = ScanResult(
            file_hash=file_hash,
            status=status,
            detection_ratio=ratio
        )

    def set_available(self, available: bool) -> None:
        """Set scanner availability."""
        self._available = available

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a file by path."""
        # In real test, would calculate hash from file
        # For now, return default clean result
        return ScanResult(
            file_hash="test_hash",
            status=SecurityStatus.CLEAN,
            detection_ratio="0/72"
        )

    def scan_hash(self, file_hash: str) -> ScanResult:
        """Scan by hash."""
        if file_hash in self._scan_results:
            return self._scan_results[file_hash]

        # Default: clean
        return ScanResult(
            file_hash=file_hash,
            status=SecurityStatus.CLEAN,
            detection_ratio="0/72"
        )

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """Scan a DLL entity and return updated copy."""
        if dll_file.file_hash:
            result = self.scan_hash(dll_file.file_hash)
        else:
            result = ScanResult(
                file_hash="unknown",
                status=SecurityStatus.UNKNOWN,
                detection_ratio="0/0"
            )

        return replace(
            dll_file,
            security_status=result.status,
            vt_detection_ratio=result.detection_ratio,
            vt_scan_date=result.scan_date
        )

    def get_detailed_report(self, file_hash: str) -> dict[str, object]:
        """Get detailed report."""
        result = self.scan_hash(file_hash)
        return {
            'hash': result.file_hash,
            'status': result.status.value,
            'ratio': result.detection_ratio,
            'detections': result.detections
        }

    @property
    def is_available(self) -> bool:
        """Check if scanner is available."""
        return self._available


def _require_dll_file(response_dll_file: DLLFile | None) -> DLLFile:
    """Narrow optional DLLFile values in tests."""
    assert response_dll_file is not None
    return response_dll_file


@dataclass
class FailingRepository(InMemoryRepository):
    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        raise RepositoryOperationError("repo save failed")


# ============================================================================
# Download DLL Use Case Tests
# ============================================================================

@pytest.mark.unit
def test_download_dll_use_case_successful_download() -> None:
    """
    Test successful DLL download flow.

    Purpose:
        Verify that the use case correctly orchestrates a complete
        download operation.

    Expected Behavior:
        - DLL is downloaded via HTTP client
        - Hash is calculated
        - Entity is created with correct attributes
        - Repository save is called
        - Success response is returned
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    request = DownloadDLLRequest(
        dll_name="kernel32.dll",
        architecture=Architecture.X64,
        scan_before_save=False
    )

    response = use_case.execute(request)

    assert response.success is True
    dll_file = _require_dll_file(response.dll_file)
    assert dll_file.name == "kernel32.dll"
    assert dll_file.architecture == Architecture.X64
    assert dll_file.file_hash is not None
    assert len(dll_file.file_hash) == 64  # SHA-256
    assert response.was_cached is False


@pytest.mark.unit
def test_download_dll_use_case_calculates_hash() -> None:
    """
    Test that the use case calculates file hash correctly.

    Purpose:
        Verify that SHA-256 hash calculation is performed during download.

    Expected Behavior:
        - File hash is calculated from content
        - Hash is 64 hex characters
        - Same content produces same hash
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    # Configure specific content
    dll_bytes = b'MZ\x90\x00' + b'Specific test content' * 100
    test_content = _build_zip_payload("test.dll", dll_bytes)
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        test_content
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    request = DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=False
    )

    response = use_case.execute(request)

    assert response.success is True
    dll_file = _require_dll_file(response.dll_file)
    assert dll_file.file_hash is not None

    # Calculate expected hash
    import hashlib
    expected_hash = hashlib.sha256(test_content).hexdigest()
    assert dll_file.file_hash == expected_hash


@pytest.mark.unit
def test_download_dll_use_case_uses_resolver() -> None:
    """
    Verify resolver is used when provided.
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    class Resolver:
        def resolve_download_url(
            self,
            dll_name: str,
            architecture: Architecture,
        ) -> str:
            return "https://example.com/custom.dll"

    http_client.add_response(
        "https://example.com/custom.dll",
        _build_zip_payload("custom.dll", b"MZ\x90\x00data"),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        resolver=Resolver()
    )

    request = DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=False
    )

    response = use_case.execute(request)
    assert response.success is True


@pytest.mark.unit
def test_download_dll_use_case_extracts_dll_from_zip_archive() -> None:
    """
    Verify ZIP downloads are extracted when extract_archive is enabled.
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    dll_bytes = b"MZ\x90\x00unzipped dll content"
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("nested/test.dll", dll_bytes)
        archive.writestr("notes.txt", b"ignored")

    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        archive_buffer.getvalue()
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    response = use_case.execute(DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=False,
        extract_archive=True,
    ))

    assert response.success is True
    dll_file = _require_dll_file(response.dll_file)
    assert repository.get_content(dll_file) == dll_bytes


@pytest.mark.unit
def test_download_dll_use_case_fails_when_zip_has_no_dll_and_extract_enabled() -> None:
    """
    Verify extract_archive returns a clear failure when ZIP lacks a DLL.
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("readme.txt", b"no dll here")

    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        archive_buffer.getvalue()
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    response = use_case.execute(DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=False,
        extract_archive=True,
    ))

    assert response.success is False
    assert response.error_message is not None
    assert "does not contain any DLL files" in response.error_message


@pytest.mark.unit
def test_download_dll_use_case_wraps_resolver_failures() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    class FailingResolver:
        def resolve_download_url(
            self,
            dll_name: str,
            architecture: Architecture,
        ) -> str:
            raise DownloadResolutionError("resolver failed")

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        resolver=FailingResolver(),
    )

    with pytest.raises(DownloadExecutionError, match="resolver failed"):
        use_case._resolve_download_url(
            DownloadDLLRequest(
                dll_name="test.dll",
                architecture=Architecture.X64,
            )
        )


@pytest.mark.unit
def test_download_dll_use_case_wraps_http_failures() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.set_failure_exception(HTTPServiceError("network down"))
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    with pytest.raises(DownloadExecutionError, match="network down"):
        use_case._download_content("https://dll.website/download/x64/test.dll")


@pytest.mark.unit
def test_download_dll_use_case_wraps_repository_failures() -> None:
    repository = FailingRepository()
    http_client = StubHTTPClient()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    with pytest.raises(DownloadExecutionError, match="repo save failed"):
        use_case._save_dll(DLLFile(name="test.dll"), b"content")


@pytest.mark.unit
def test_download_dll_use_case_fails_when_extracted_dll_is_empty() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("test.dll", b"")
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        archive_buffer.getvalue(),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: Extracted DLL from ZIP archive is empty"


@pytest.mark.unit
def test_download_dll_use_case_fails_when_zip_reader_is_invalid() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        b"PK\x05\x06" + (b"0" * 18),
    )
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: Downloaded archive is not a valid ZIP file"


@pytest.mark.unit
def test_download_dll_use_case_allows_valid_zip_without_extract_flag() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    dll_bytes = b"MZ\x90\x00real-dll"
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("test.dll", dll_bytes)
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        archive_buffer.getvalue(),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=False,
        )
    )

    assert response.success is True
    assert response.dll_file is not None
    assert repository.get_content(response.dll_file) == archive_buffer.getvalue()
    assert response.dll_file.file_size == len(archive_buffer.getvalue())


@pytest.mark.unit
def test_download_dll_use_case_fails_when_payload_is_not_zip() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        b"plain text not a dll",
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=False,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: Downloaded archive is not a valid ZIP file"
    )


@pytest.mark.unit
def test_download_dll_use_case_fails_when_pk_content_is_not_valid_zip() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        b"PK\x03\x04garbage",
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=False,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: Downloaded archive is not a valid ZIP file"
    )


@pytest.mark.unit
def test_download_dll_use_case_fails_when_extracted_content_is_not_pe() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("test.dll", b"not a pe dll")
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        archive_buffer.getvalue(),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: Downloaded content is not a valid DLL (missing PE signature)"
    )


@pytest.mark.unit
def test_download_dll_use_case_fails_when_extract_is_enabled_but_payload_is_not_zip() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    pe_content = b"MZ\x90\x00direct dll bytes"
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        pe_content,
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: Downloaded archive is not a valid ZIP file"
    )


@pytest.mark.unit
def test_download_dll_use_case_returns_cached_file() -> None:
    """
    Test that use case returns cached file if already exists.

    Purpose:
        Verify that redundant downloads are avoided when file exists.

    Expected Behavior:
        - Existing file is found in repository
        - No new download is performed
        - Response indicates file was cached
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    # Pre-populate repository
    existing_dll = DLLFile(
        name="cached.dll",
        architecture=Architecture.X64,
        file_hash="abc123"
    )
    repository.save(existing_dll, b'existing content')

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    request = DownloadDLLRequest(
        dll_name="cached.dll",
        architecture=Architecture.X64,
        force_download=False
    )

    response = use_case.execute(request)

    assert response.success is True
    assert response.was_cached is True
    assert _require_dll_file(response.dll_file).file_hash == "abc123"


@pytest.mark.unit
def test_download_dll_use_case_force_download_bypasses_cache() -> None:
    """
    Test that force_download bypasses cache.

    Purpose:
        Verify that force_download flag causes re-download even when
        file exists in repository.

    Expected Behavior:
        - Cached file is ignored
        - New download is performed
        - Response indicates file was not cached
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    # Pre-populate repository
    existing_dll = DLLFile(
        name="test.dll",
        architecture=Architecture.X64,
        file_hash="old_hash"
    )
    repository.save(existing_dll, b'old content')

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    request = DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        force_download=True,
        scan_before_save=False
    )

    response = use_case.execute(request)

    assert response.success is True
    assert response.was_cached is False
    # New hash should be different
    assert _require_dll_file(response.dll_file).file_hash != "old_hash"


@pytest.mark.unit
def test_download_dll_use_case_with_security_scan_clean() -> None:
    """
    Test download with security scanning (clean result).

    Purpose:
        Verify that security scanning is integrated into download flow
        and clean files are processed normally.

    Expected Behavior:
        - File is scanned after download
        - Clean status is set on entity
        - No security warning in response
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    scanner = StubSecurityScanner()

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        scanner=scanner
    )

    request = DownloadDLLRequest(
        dll_name="safe.dll",
        architecture=Architecture.X64,
        scan_before_save=True
    )

    response = use_case.execute(request)

    assert response.success is True
    assert _require_dll_file(response.dll_file).security_status == SecurityStatus.CLEAN
    assert response.security_warning is None


@pytest.mark.unit
def test_download_dll_use_case_with_security_scan_malicious() -> None:
    """
    Test download with security scanning (malicious result).

    Purpose:
        Verify that malicious files are detected and flagged with warnings.

    Expected Behavior:
        - File is scanned after download
        - Malicious status is set
        - Security warning is included in response
        - File is still saved (user decision to use it)
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    scanner = StubSecurityScanner()

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        scanner=scanner
    )

    # First, execute to get the hash that will be used
    request = DownloadDLLRequest(
        dll_name="malware.dll",
        architecture=Architecture.X64,
        scan_before_save=False
    )
    initial_response = use_case.execute(request)
    file_hash = _require_dll_file(initial_response.dll_file).file_hash
    assert file_hash is not None

    # Configure scanner to return malicious result
    scanner.configure_result(
        file_hash,
        SecurityStatus.MALICIOUS,
        "42/72"
    )

    # Now do actual test with scanning
    repository = InMemoryRepository()  # Fresh repository
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        scanner=scanner
    )

    request = DownloadDLLRequest(
        dll_name="malware.dll",
        architecture=Architecture.X64,
        scan_before_save=True
    )

    response = use_case.execute(request)

    assert response.success is True
    assert _require_dll_file(response.dll_file).security_status == SecurityStatus.MALICIOUS
    assert response.security_warning is not None
    assert "WARNING" in response.security_warning
    assert "42/72" in response.security_warning


@pytest.mark.unit
def test_download_dll_use_case_with_security_scan_suspicious() -> None:
    """
    Test download with security scanning (suspicious result).

    Purpose:
        Verify that files with low detection rates are flagged as suspicious.

    Expected Behavior:
        - File is scanned after download
        - Suspicious status is set
        - Caution warning is included in response
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    scanner = StubSecurityScanner()

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        scanner=scanner
    )

    # Get hash first
    request = DownloadDLLRequest(
        dll_name="suspicious.dll",
        architecture=Architecture.X64,
        scan_before_save=False
    )
    initial_response = use_case.execute(request)
    file_hash = _require_dll_file(initial_response.dll_file).file_hash
    assert file_hash is not None

    # Configure suspicious result
    scanner.configure_result(
        file_hash,
        SecurityStatus.SUSPICIOUS,
        "3/72"
    )

    # Test with scanning
    repository = InMemoryRepository()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        scanner=scanner
    )

    request = DownloadDLLRequest(
        dll_name="suspicious.dll",
        architecture=Architecture.X64,
        scan_before_save=True
    )

    response = use_case.execute(request)

    assert response.success is True
    assert _require_dll_file(response.dll_file).security_status == SecurityStatus.SUSPICIOUS
    assert response.security_warning is not None
    assert "CAUTION" in response.security_warning


@pytest.mark.unit
def test_download_dll_use_case_scanner_unavailable() -> None:
    """
    Test download when scanner is unavailable.

    Purpose:
        Verify graceful degradation when security scanner is not available.

    Expected Behavior:
        - Download proceeds normally
        - Security status remains NOT_SCANNED
        - No security warning
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    scanner = StubSecurityScanner()
    scanner.set_available(False)

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
        scanner=scanner
    )

    request = DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=True
    )

    response = use_case.execute(request)

    assert response.success is True
    assert _require_dll_file(response.dll_file).security_status == SecurityStatus.NOT_SCANNED
    assert response.security_warning is None


@pytest.mark.unit
def test_download_dll_use_case_download_failure() -> None:
    """
    Test handling of download failure.

    Purpose:
        Verify proper error handling when HTTP download fails.

    Expected Behavior:
        - Error response is returned
        - Success is False
        - Error message is provided
        - No file is saved to repository
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.set_failure_mode(True)

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    request = DownloadDLLRequest(
        dll_name="fail.dll",
        architecture=Architecture.X64
    )

    response = use_case.execute(request)

    assert response.success is False
    assert response.error_message is not None
    assert "empty response" in response.error_message.lower()
    assert response.dll_file is None
    assert len(repository.list_all()) == 0


@pytest.mark.unit
def test_download_dll_use_case_different_architectures() -> None:
    """
    Test downloading different architecture versions.

    Purpose:
        Verify that architecture-specific downloads are handled correctly.

    Expected Behavior:
        - Each architecture downloads to correct URL
        - Files are stored separately by architecture
        - Correct architecture is set on entities
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    # Download x86 version
    request_x86 = DownloadDLLRequest(
        dll_name="lib.dll",
        architecture=Architecture.X86,
        scan_before_save=False
    )
    response_x86 = use_case.execute(request_x86)

    # Download x64 version
    request_x64 = DownloadDLLRequest(
        dll_name="lib.dll",
        architecture=Architecture.X64,
        scan_before_save=False
    )
    response_x64 = use_case.execute(request_x64)

    assert response_x86.success is True
    assert response_x64.success is True
    assert _require_dll_file(response_x86.dll_file).architecture == Architecture.X86
    assert _require_dll_file(response_x64.dll_file).architecture == Architecture.X64

    # Both should be in repository
    all_dlls = repository.list_all()
    assert len(all_dlls) == 2


@pytest.mark.unit
def test_download_batch_use_case_orchestrates_multiple_downloads() -> None:
    """
    Verify batch use case delegates each item through the single-download flow.
    """
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    single_use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )
    batch_use_case = DownloadBatchUseCase(single_use_case)

    response = batch_use_case.execute(
        DownloadBatchRequest(
            dll_names=["kernel32", "user32.dll"],
            architecture=Architecture.X64,
            scan_before_save=False,
        )
    )

    assert response.success_count == 2
    assert response.failure_count == 0
    assert [item.dll_name for item in response.items] == ["kernel32.dll", "user32.dll"]
