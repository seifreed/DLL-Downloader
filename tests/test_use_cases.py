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
import os
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
    SecurityServiceError,
)
from dll_downloader.domain.repositories.dll_repository import IDLLRepository
from dll_downloader.domain.services import calculate_sha256
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


def _build_crc_corrupt_zip_payload(dll_name: str, dll_bytes: bytes) -> bytes:
    """Create a ZIP whose central directory is valid but member CRC is wrong."""
    payload = bytearray(_build_zip_payload(dll_name, dll_bytes))
    payload[payload.index(dll_bytes[:2])] ^= 0x01
    return bytes(payload)


def _build_encrypted_zip_payload(dll_name: str, dll_bytes: bytes) -> bytes:
    """Create a ZIP whose member is flagged as encrypted."""
    payload = bytearray(_build_zip_payload(dll_name, dll_bytes))
    local_header = payload.index(b"PK\x03\x04")
    central_directory_header = payload.index(b"PK\x01\x02")
    for flag_offset in (local_header + 6, central_directory_header + 8):
        flags = int.from_bytes(payload[flag_offset:flag_offset + 2], "little")
        payload[flag_offset:flag_offset + 2] = (flags | 0x01).to_bytes(2, "little")
    return bytes(payload)


def _build_pe_payload(
    architecture: Architecture,
    marker: bytes = b"",
    *,
    is_dll: bool = True,
) -> bytes:
    """Create a minimal PE DLL payload with a real machine field."""
    raw_data = marker or b"\x00"
    machine_by_architecture = {
        Architecture.X86: 0x014C,
        Architecture.X64: 0x8664,
    }
    machine = machine_by_architecture[architecture]
    pe_offset = 0x80
    optional_header_size = 0xF0 if architecture == Architecture.X64 else 0xE0
    optional_header_offset = pe_offset + 24
    section_table_offset = optional_header_offset + optional_header_size
    payload = bytearray(section_table_offset + 40)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    payload[pe_offset + 20:pe_offset + 22] = optional_header_size.to_bytes(2, "little")
    characteristics = 0x2000 if is_dll else 0x0002
    payload[pe_offset + 22:pe_offset + 24] = characteristics.to_bytes(2, "little")
    optional_magic = 0x20B if architecture == Architecture.X64 else 0x10B
    payload[optional_header_offset:optional_header_offset + 2] = optional_magic.to_bytes(
        2,
        "little",
    )
    payload[section_table_offset:section_table_offset + 5] = b".text"
    payload[section_table_offset + 8:section_table_offset + 12] = len(
        raw_data
    ).to_bytes(4, "little")
    payload[section_table_offset + 12:section_table_offset + 16] = (0x1000).to_bytes(
        4,
        "little",
    )
    payload[section_table_offset + 16:section_table_offset + 20] = len(
        raw_data
    ).to_bytes(4, "little")
    payload[section_table_offset + 20:section_table_offset + 24] = len(
        payload
    ).to_bytes(4, "little")
    return bytes(payload) + raw_data


def _build_pe_payload_with_machine(machine: int) -> bytes:
    """Create a minimal PE-like DLL payload with a custom machine field."""
    pe_offset = 0x80
    payload = bytearray(pe_offset + 24)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 22:pe_offset + 24] = (0x2000).to_bytes(2, "little")
    return bytes(payload)


def _build_pe_header_stub(architecture: Architecture) -> bytes:
    """Create a PE-looking stub without a loadable image layout."""
    machine_by_architecture = {
        Architecture.X86: 0x014C,
        Architecture.X64: 0x8664,
    }
    machine = machine_by_architecture[architecture]
    pe_offset = 0x80
    payload = bytearray(pe_offset + 24)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6:pe_offset + 8] = (0).to_bytes(2, "little")
    payload[pe_offset + 20:pe_offset + 22] = (0).to_bytes(2, "little")
    payload[pe_offset + 22:pe_offset + 24] = (0x2000).to_bytes(2, "little")
    return bytes(payload)


def _build_pe_payload_with_blank_section(architecture: Architecture) -> bytes:
    """Create a PE-looking DLL whose declared section table is empty."""
    machine_by_architecture = {
        Architecture.X86: 0x014C,
        Architecture.X64: 0x8664,
    }
    machine = machine_by_architecture[architecture]
    pe_offset = 0x80
    optional_header_size = 0xF0 if architecture == Architecture.X64 else 0xE0
    optional_header_offset = pe_offset + 24
    section_table_offset = optional_header_offset + optional_header_size
    payload = bytearray(section_table_offset + 40)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    payload[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    payload[pe_offset + 4:pe_offset + 6] = machine.to_bytes(2, "little")
    payload[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    payload[pe_offset + 20:pe_offset + 22] = optional_header_size.to_bytes(2, "little")
    payload[pe_offset + 22:pe_offset + 24] = (0x2000).to_bytes(2, "little")
    optional_magic = 0x20B if architecture == Architecture.X64 else 0x10B
    payload[optional_header_offset:optional_header_offset + 2] = optional_magic.to_bytes(
        2,
        "little",
    )
    return bytes(payload)


def _architecture_from_url(url: str) -> Architecture:
    """Infer requested test architecture from deterministic fixture URLs."""
    if "/x86/" in url:
        return Architecture.X86
    return Architecture.X64

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
                _build_pe_payload(
                    _architecture_from_url(url),
                    f'DLL content for {url}'.encode() * 10,
                ),
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


class FailingSecurityScanner(StubSecurityScanner):
    def scan_dll(self, _dll_file: DLLFile) -> DLLFile:
        raise SecurityServiceError("scanner down")


class UnknownSecurityScanner(StubSecurityScanner):
    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        return replace(dll_file, security_status=SecurityStatus.UNKNOWN)


class NotScannedSecurityScanner(StubSecurityScanner):
    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        return replace(dll_file, security_status=SecurityStatus.NOT_SCANNED)


def _require_dll_file(response_dll_file: DLLFile | None) -> DLLFile:
    """Narrow optional DLLFile values in tests."""
    assert response_dll_file is not None
    return response_dll_file


@dataclass
class FailingRepository(InMemoryRepository):
    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        raise RepositoryOperationError("repo save failed")


@dataclass
class FailingLookupRepository(InMemoryRepository):
    def find_by_name(
        self,
        name: str,
        architecture: Architecture | None = None,
    ) -> DLLFile | None:
        del name, architecture
        raise RepositoryOperationError("index read failed")


class NoDownloadHTTPClient(StubHTTPClient):
    def download(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        raise AssertionError("download should not be called")


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
def test_download_dll_use_case_normalizes_programmatic_name() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="kernel32",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
    )

    assert response.success is True
    assert _require_dll_file(response.dll_file).name == "kernel32.dll"


@pytest.mark.unit
def test_download_dll_use_case_invalid_programmatic_name_returns_failure() -> None:
    repository = InMemoryRepository()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="../bad",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: DLL name must be a simple filename"
    )
    assert repository.list_all() == []


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
    dll_bytes = _build_pe_payload(Architecture.X64, b'Specific test content' * 100)
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
        _build_zip_payload("test.dll", _build_pe_payload(Architecture.X64, b"data")),
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
    dll_bytes = _build_pe_payload(Architecture.X64, b"unzipped dll content")
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
def test_download_dll_use_case_rejects_zip_without_requested_dll_when_extracting() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(
            "other.dll",
            _build_pe_payload(Architecture.X64, b"wrong dll"),
        )

    http_client.add_response(
        "https://dll.website/download/x64/requested.dll",
        archive_buffer.getvalue(),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="requested.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: ZIP archive does not contain requested DLL requested.dll"
    )
    assert repository.list_all() == []


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
def test_download_dll_use_case_execute_returns_failure_for_resolver_http_error() -> None:
    repository = InMemoryRepository()

    class FailingResolver:
        def resolve_download_url(
            self,
            dll_name: str,
            architecture: Architecture,
        ) -> str:
            del dll_name, architecture
            raise HTTPServiceError("resolver transport failed")

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
        resolver=FailingResolver(),
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: resolver transport failed"
    assert repository.list_all() == []


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
def test_download_dll_use_case_execute_returns_failure_for_cache_lookup_error() -> None:
    repository = FailingLookupRepository()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: index read failed"
    assert repository.list_all() == []


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
def test_download_dll_use_case_selects_matching_architecture_duplicate_zip_member() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    x64_payload = _build_pe_payload(Architecture.X64, b"x64 payload")

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(
            "x86/requested.dll",
            _build_pe_payload(Architecture.X86, b"x86 payload"),
        )
        archive.writestr("x64/requested.dll", x64_payload)
    http_client.add_response(
        "https://dll.website/download/x64/requested.dll",
        archive_buffer.getvalue(),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="requested.dll",
            architecture=Architecture.X64,
            extract_archive=True,
        )
    )

    assert response.success is True
    dll_file = _require_dll_file(response.dll_file)
    assert repository.get_content(dll_file) == x64_payload


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
    dll_bytes = _build_pe_payload(Architecture.X64, b"real-dll")
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
def test_download_dll_use_case_extract_request_bypasses_cached_zip() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    dll_bytes = _build_pe_payload(Architecture.X64, b"real-dll")
    zip_bytes = _build_zip_payload("test.dll", dll_bytes)
    http_client.add_response("https://dll.website/download/x64/test.dll", zip_bytes)

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    cached_zip_response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=False,
        )
    )
    assert cached_zip_response.success is True
    cached_zip = _require_dll_file(cached_zip_response.dll_file)
    assert repository.get_content(cached_zip) == zip_bytes

    extracted_response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=True,
        )
    )

    assert extracted_response.success is True
    assert extracted_response.was_cached is False
    extracted_dll = _require_dll_file(extracted_response.dll_file)
    assert repository.get_content(extracted_dll) == dll_bytes


@pytest.mark.unit
def test_download_dll_use_case_non_extract_request_bypasses_extracted_cache(
    tmp_path: Path,
) -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    extracted_path = tmp_path / "test.dll"
    extracted_path.write_bytes(_build_pe_payload(Architecture.X64, b"extracted"))
    repository._storage[repository._make_key("test.dll", Architecture.X64)] = DLLFile(
        name="test.dll",
        architecture=Architecture.X64,
        file_path=str(extracted_path),
    )
    zip_bytes = _build_zip_payload(
        "test.dll",
        _build_pe_payload(Architecture.X64, b"zip-cache-contract"),
    )
    http_client.add_response("https://dll.website/download/x64/test.dll", zip_bytes)

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=False,
        )
    )

    assert response.success is True
    assert response.was_cached is False
    dll_file = _require_dll_file(response.dll_file)
    assert repository.get_content(dll_file) == zip_bytes


@pytest.mark.unit
def test_download_dll_use_case_redownloads_invalid_file_backed_cache(
    tmp_path: Path,
) -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    bad_path = tmp_path / "bad.dll"
    bad_path.write_bytes(b"not a PE DLL")
    repository._storage[repository._make_key("bad.dll", Architecture.X64)] = DLLFile(
        name="bad.dll",
        architecture=Architecture.X64,
        file_path=str(bad_path),
    )
    replacement_zip = _build_zip_payload(
        "bad.dll",
        _build_pe_payload(Architecture.X64, b"replacement"),
    )
    http_client.add_response(
        "https://dll.website/download/x64/bad.dll",
        replacement_zip,
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="bad.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
    )

    assert response.success is True
    assert response.was_cached is False
    dll_file = _require_dll_file(response.dll_file)
    assert repository.get_content(dll_file) == replacement_zip


@pytest.mark.unit
def test_download_dll_use_case_accepts_valid_file_backed_zip_cache(
    tmp_path: Path,
) -> None:
    cached_zip_path = tmp_path / "cached.dll"
    cached_zip_path.write_bytes(
        _build_zip_payload("cached.dll", _build_pe_payload(Architecture.X64))
    )
    repository = InMemoryRepository()
    repository._storage[repository._make_key("cached.dll", Architecture.X64)] = DLLFile(
        name="cached.dll",
        architecture=Architecture.X64,
        file_path=str(cached_zip_path),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="cached.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=False,
        )
    )

    assert response.success is True
    assert response.was_cached is True


@pytest.mark.unit
def test_download_dll_use_case_redownloads_missing_file_backed_cache(
    tmp_path: Path,
) -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    repository._storage[repository._make_key("ghost.dll", Architecture.X64)] = DLLFile(
        name="ghost.dll",
        architecture=Architecture.X64,
        file_path=str(tmp_path / "missing.dll"),
        file_hash="0" * 64,
    )
    replacement_zip = _build_zip_payload(
        "ghost.dll",
        _build_pe_payload(Architecture.X64, b"replacement"),
    )
    http_client.add_response(
        "https://dll.website/download/x64/ghost.dll",
        replacement_zip,
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="ghost.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
    )

    assert response.success is True
    assert response.was_cached is False
    assert repository.get_content(_require_dll_file(response.dll_file)) == replacement_zip


@pytest.mark.unit
def test_cached_extract_payload_check_rejects_non_extracted_cache(
    tmp_path: Path,
) -> None:
    no_path = DLLFile(name="no-path.dll", architecture=Architecture.X64)
    missing_path = DLLFile(
        name="missing.dll",
        architecture=Architecture.X64,
        file_path=str(tmp_path / "missing.dll"),
    )
    zip_path = tmp_path / "cached.zip"
    zip_path.write_bytes(
        _build_zip_payload("cached.dll", _build_pe_payload(Architecture.X64))
    )
    cached_zip = DLLFile(
        name="cached.dll",
        architecture=Architecture.X64,
        file_path=str(zip_path),
    )
    invalid_path = tmp_path / "invalid.dll"
    invalid_path.write_bytes(b"not a PE DLL")
    invalid_payload = DLLFile(
        name="invalid.dll",
        architecture=Architecture.X64,
        file_path=str(invalid_path),
    )
    valid_path = tmp_path / "valid.dll"
    valid_path.write_bytes(_build_pe_payload(Architecture.X64))
    valid_payload = DLLFile(
        name="valid.dll",
        architecture=Architecture.X64,
        file_path=str(valid_path),
    )

    assert not DownloadDLLUseCase._cached_payload_satisfies_extract(
        no_path,
        Architecture.X64,
    )
    assert not DownloadDLLUseCase._cached_payload_satisfies_extract(
        missing_path,
        Architecture.X64,
    )
    assert not DownloadDLLUseCase._cached_payload_satisfies_extract(
        cached_zip,
        Architecture.X64,
    )
    assert not DownloadDLLUseCase._cached_payload_satisfies_extract(
        invalid_payload,
        Architecture.X64,
    )
    assert DownloadDLLUseCase._cached_payload_satisfies_extract(
        valid_payload,
        Architecture.X64,
    )


@pytest.mark.unit
def test_cached_extract_payload_check_rejects_non_regular_path(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")

    fifo_path = tmp_path / "cached.dll"
    os.mkfifo(fifo_path)
    cached_fifo = DLLFile(
        name="cached.dll",
        architecture=Architecture.X64,
        file_path=str(fifo_path),
    )

    assert not DownloadDLLUseCase._cached_payload_satisfies_extract(
        cached_fifo,
        Architecture.X64,
    )


@pytest.mark.unit
def test_persist_cached_scan_result_without_path_returns_scanned_metadata() -> None:
    use_case = DownloadDLLUseCase(
        repository=InMemoryRepository(),
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )
    cached_dll = DLLFile(name="cached.dll", architecture=Architecture.X64)
    scanned_dll = replace(cached_dll, security_status=SecurityStatus.CLEAN)

    assert use_case._persist_cached_scan_result(cached_dll, scanned_dll) is scanned_dll


@pytest.mark.unit
def test_persist_cached_scan_result_rejects_missing_payload(
    tmp_path: Path,
) -> None:
    use_case = DownloadDLLUseCase(
        repository=InMemoryRepository(),
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )
    cached_dll = DLLFile(
        name="missing.dll",
        architecture=Architecture.X64,
        file_path=str(tmp_path / "missing.dll"),
    )
    scanned_dll = replace(cached_dll, security_status=SecurityStatus.CLEAN)

    with pytest.raises(DownloadExecutionError, match="Failed to read cached DLL"):
        use_case._persist_cached_scan_result(cached_dll, scanned_dll)


@pytest.mark.unit
def test_cached_payload_request_rejects_missing_path_and_invalid_zip(
    tmp_path: Path,
) -> None:
    use_case = DownloadDLLUseCase(
        repository=InMemoryRepository(),
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )
    request = DownloadDLLRequest(
        "cached.dll",
        Architecture.X64,
        extract_archive=False,
    )
    no_path = DLLFile(name="cached.dll", architecture=Architecture.X64)
    wrong_zip_path = tmp_path / "cached.dll"
    wrong_zip_path.write_bytes(
        _build_zip_payload("other.dll", _build_pe_payload(Architecture.X64))
    )
    wrong_zip = DLLFile(
        name="cached.dll",
        architecture=Architecture.X64,
        file_path=str(wrong_zip_path),
    )

    assert not use_case._cached_payload_satisfies_request(no_path, request)
    assert not use_case._cached_payload_satisfies_request(wrong_zip, request)


@pytest.mark.unit
def test_download_dll_use_case_rejects_zip_without_requested_dll_before_saving() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(
            "other.dll",
            _build_pe_payload(Architecture.X64, b"wrong dll"),
        )

    http_client.add_response(
        "https://dll.website/download/x64/requested.dll",
        archive_buffer.getvalue(),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="requested.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=False,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: ZIP archive does not contain requested DLL requested.dll"
    )
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_detects_x86_and_x64_pe_architectures() -> None:
    assert (
        DownloadDLLUseCase._detect_pe_architecture(
            _build_pe_payload(Architecture.X86)
        )
        == Architecture.X86
    )
    assert (
        DownloadDLLUseCase._detect_pe_architecture(
            _build_pe_payload(Architecture.X64)
        )
        == Architecture.X64
    )


@pytest.mark.unit
def test_download_dll_use_case_rejects_incomplete_pe_header() -> None:
    with pytest.raises(DownloadExecutionError, match="missing PE signature"):
        DownloadDLLUseCase._detect_pe_architecture(b"MZ")


@pytest.mark.unit
def test_download_dll_use_case_rejects_missing_pe_signature() -> None:
    payload = bytearray(0x90)
    payload[0:2] = b"MZ"
    payload[0x3C:0x40] = (0x80).to_bytes(4, "little")

    with pytest.raises(DownloadExecutionError, match="missing PE signature"):
        DownloadDLLUseCase._detect_pe_architecture(bytes(payload))


@pytest.mark.unit
def test_download_dll_use_case_rejects_pe_stub_without_image_layout() -> None:
    with pytest.raises(DownloadExecutionError, match="missing PE signature"):
        DownloadDLLUseCase._detect_pe_architecture(
            _build_pe_header_stub(Architecture.X64)
        )


@pytest.mark.unit
def test_download_dll_use_case_rejects_blank_pe_section_table() -> None:
    with pytest.raises(DownloadExecutionError, match="missing PE signature"):
        DownloadDLLUseCase._detect_pe_architecture(
            _build_pe_payload_with_blank_section(Architecture.X64)
        )


@pytest.mark.unit
def test_download_dll_use_case_rejects_zip_member_with_blank_pe_section_table() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/fake.dll",
        _build_zip_payload(
            "fake.dll",
            _build_pe_payload_with_blank_section(Architecture.X64),
        ),
    )
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="fake.dll",
            architecture=Architecture.X64,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: Downloaded content is not a valid DLL (missing PE signature)"
    )
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_rejects_missing_pe_characteristics() -> None:
    payload = _build_pe_payload(Architecture.X64)[:-2]

    with pytest.raises(DownloadExecutionError, match="missing PE signature"):
        DownloadDLLUseCase._detect_pe_architecture(payload)


@pytest.mark.unit
def test_download_dll_use_case_rejects_unsupported_pe_machine_type() -> None:
    with pytest.raises(DownloadExecutionError, match="0x0200"):
        DownloadDLLUseCase._detect_pe_architecture(
            _build_pe_payload_with_machine(0x0200)
        )


@pytest.mark.unit
def test_download_dll_use_case_rejects_pe_without_dll_characteristic() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/requested.dll",
        _build_zip_payload(
            "requested.dll",
            _build_pe_payload(Architecture.X64, is_dll=False),
        ),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="requested.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
            extract_archive=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: Downloaded PE file is not a DLL"
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_rejects_empty_requested_zip_member() -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr("empty.dll", b"")
    use_case = DownloadDLLUseCase(
        repository=InMemoryRepository(),
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )

    with pytest.raises(DownloadExecutionError, match="Extracted DLL from ZIP archive is empty"):
        use_case._extract_valid_dll_from_zip(
            archive_buffer.getvalue(),
            DownloadDLLRequest("empty.dll", Architecture.X64, extract_archive=True),
        )


@pytest.mark.unit
def test_download_dll_use_case_pe_layout_rejects_invalid_boundaries() -> None:
    def build_layout_probe(
        *,
        section_count: int = 1,
        optional_header_size: int = 0xF0,
        optional_magic: int = 0x20B,
        total_size: int | None = None,
    ) -> bytes:
        section_table_offset = 20 + optional_header_size
        payload_size = (
            section_table_offset + 40
            if total_size is None
            else total_size
        )
        payload = bytearray(max(payload_size, 22))
        payload[2:4] = section_count.to_bytes(2, "little")
        payload[16:18] = optional_header_size.to_bytes(2, "little")
        payload[20:22] = optional_magic.to_bytes(2, "little")
        return bytes(payload[:payload_size])

    assert not DownloadDLLUseCase._pe_image_layout_is_valid(
        build_layout_probe(optional_header_size=0),
        0,
        Architecture.X64,
    )
    assert not DownloadDLLUseCase._pe_image_layout_is_valid(
        build_layout_probe(total_size=40),
        0,
        Architecture.X64,
    )
    assert not DownloadDLLUseCase._pe_image_layout_is_valid(
        build_layout_probe(optional_magic=0x10B),
        0,
        Architecture.X64,
    )
    assert not DownloadDLLUseCase._pe_image_layout_is_valid(
        build_layout_probe(optional_header_size=2, total_size=22),
        0,
        Architecture.X64,
    )


@pytest.mark.unit
def test_download_dll_use_case_loadable_section_edges() -> None:
    section_table_offset = 0
    blank_section = bytearray(40)
    virtual_only_section = bytearray(40)
    virtual_only_section[:5] = b".text"
    virtual_only_section[8:12] = (1).to_bytes(4, "little")
    virtual_only_section[12:16] = (0x1000).to_bytes(4, "little")
    invalid_raw_section = bytearray(40)
    invalid_raw_section[:5] = b".text"
    invalid_raw_section[8:12] = (1).to_bytes(4, "little")
    invalid_raw_section[12:16] = (0x1000).to_bytes(4, "little")
    invalid_raw_section[16:20] = (4).to_bytes(4, "little")
    invalid_raw_section[20:24] = (1).to_bytes(4, "little")

    assert not DownloadDLLUseCase._has_loadable_section(
        bytes(blank_section),
        section_table_offset,
        1,
    )
    assert DownloadDLLUseCase._has_loadable_section(
        bytes(virtual_only_section),
        section_table_offset,
        1,
    )
    assert not DownloadDLLUseCase._has_loadable_section(
        bytes(invalid_raw_section),
        section_table_offset,
        1,
    )


@pytest.mark.unit
def test_download_dll_use_case_allows_unknown_requested_architecture() -> None:
    DownloadDLLUseCase._validate_dll_architecture(
        _build_pe_payload(Architecture.X64),
        Architecture.UNKNOWN,
    )


@pytest.mark.unit
def test_download_dll_use_case_rejects_mismatched_pe_architecture() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x86/test.dll",
        _build_zip_payload(
            "test.dll",
            _build_pe_payload(Architecture.X64, b"wrong architecture"),
        ),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X86,
            extract_archive=False,
        )
    )

    assert response.success is False
    assert response.error_message == (
        "Download failed: Downloaded DLL architecture x64 does not match "
        "requested architecture x86"
    )
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_accepts_requested_x86_pe_architecture() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    x86_zip = _build_zip_payload(
        "test.dll",
        _build_pe_payload(Architecture.X86, b"x86 content"),
    )
    http_client.add_response("https://dll.website/download/x86/test.dll", x86_zip)

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X86,
            extract_archive=False,
        )
    )

    assert response.success is True
    dll_file = _require_dll_file(response.dll_file)
    assert dll_file.architecture == Architecture.X86
    assert repository.get_content(dll_file) == x86_zip


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
def test_download_dll_use_case_fails_when_zip_member_crc_is_invalid() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        _build_crc_corrupt_zip_payload(
            "test.dll",
            _build_pe_payload(Architecture.X64, b"crc checked content"),
        ),
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
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_fails_when_zip_member_is_encrypted() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        _build_encrypted_zip_payload(
            "test.dll",
            _build_pe_payload(Architecture.X64, b"encrypted content"),
        ),
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
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_skips_unreadable_duplicate_zip_member() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()

    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as archive:
        archive.writestr(
            "bad/test.dll",
            _build_pe_payload(Architecture.X64, b"encrypted content"),
        )
        archive.writestr(
            "good/test.dll",
            _build_pe_payload(Architecture.X64, b"valid content"),
        )
    payload = bytearray(archive_buffer.getvalue())
    local_header = payload.index(b"PK\x03\x04")
    central_directory_header = payload.index(b"PK\x01\x02")
    for flag_offset in (local_header + 6, central_directory_header + 8):
        flags = int.from_bytes(payload[flag_offset:flag_offset + 2], "little")
        payload[flag_offset:flag_offset + 2] = (flags | 0x01).to_bytes(2, "little")

    http_client.add_response(
        "https://dll.website/download/x64/test.dll",
        bytes(payload),
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

    assert response.success is True
    dll_file = _require_dll_file(response.dll_file)
    stored_content = repository.get_content(dll_file)
    assert stored_content is not None
    assert stored_content.endswith(b"valid content")


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
def test_download_dll_use_case_returns_cached_file(tmp_path: Path) -> None:
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
    cache_path = tmp_path / "cached.dll"
    cache_path.write_bytes(
        _build_zip_payload("cached.dll", _build_pe_payload(Architecture.X64))
    )

    # Pre-populate repository
    existing_dll = DLLFile(
        name="cached.dll",
        architecture=Architecture.X64,
        file_hash="abc123",
        file_path=str(cache_path),
    )
    repository._storage[repository._make_key("cached.dll", Architecture.X64)] = existing_dll

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
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
def test_download_dll_use_case_warns_for_cached_malicious_dll(
    tmp_path: Path,
) -> None:
    repository = InMemoryRepository()
    cache_path = tmp_path / "bad.dll"
    cache_payload = _build_zip_payload("bad.dll", _build_pe_payload(Architecture.X64))
    cache_path.write_bytes(cache_payload)
    repository._storage[repository._make_key("bad.dll", Architecture.X64)] = DLLFile(
        name="bad.dll",
        architecture=Architecture.X64,
        file_hash=calculate_sha256(cache_payload),
        file_path=str(cache_path),
        security_status=SecurityStatus.MALICIOUS,
        vt_detection_ratio="7/70",
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="bad.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
    )

    assert response.success is True
    assert response.was_cached is True
    assert response.security_warning is not None
    assert "WARNING" in response.security_warning
    assert "7/70" in response.security_warning


@pytest.mark.unit
def test_download_dll_use_case_scans_cached_dll_when_requested(
    tmp_path: Path,
) -> None:
    repository = InMemoryRepository()
    scanner = StubSecurityScanner()
    cache_path = tmp_path / "cachedscan.dll"
    cache_payload = _build_zip_payload(
        "cachedscan.dll",
        _build_pe_payload(Architecture.X64),
    )
    cache_path.write_bytes(cache_payload)
    file_hash = calculate_sha256(cache_payload)
    scanner.configure_result(file_hash, SecurityStatus.SUSPICIOUS, "3/72")
    repository._storage[
        repository._make_key("cachedscan.dll", Architecture.X64)
    ] = DLLFile(
        name="cachedscan.dll",
        architecture=Architecture.X64,
        file_hash=file_hash,
        file_path=str(cache_path),
        security_status=SecurityStatus.NOT_SCANNED,
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
        scanner=scanner,
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="cachedscan.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
    )

    assert response.success is True
    assert response.was_cached is True
    dll_file = _require_dll_file(response.dll_file)
    assert dll_file.security_status == SecurityStatus.SUSPICIOUS
    assert response.security_warning is not None
    assert "CAUTION" in response.security_warning


@pytest.mark.unit
def test_download_dll_use_case_cached_scan_error_returns_failure(
    tmp_path: Path,
) -> None:
    repository = InMemoryRepository()
    cache_path = tmp_path / "scannerfail.dll"
    cache_payload = _build_zip_payload(
        "scannerfail.dll",
        _build_pe_payload(Architecture.X64),
    )
    cache_path.write_bytes(cache_payload)
    repository._storage[
        repository._make_key("scannerfail.dll", Architecture.X64)
    ] = DLLFile(
        name="scannerfail.dll",
        architecture=Architecture.X64,
        file_hash=calculate_sha256(cache_payload),
        file_path=str(cache_path),
    )

    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=NoDownloadHTTPClient(),
        download_base_url="https://dll.website/download",
        scanner=FailingSecurityScanner(),
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="scannerfail.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: scanner down"


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
def test_download_dll_use_case_scanner_error_returns_failure() -> None:
    repository = InMemoryRepository()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=StubHTTPClient(),
        download_base_url="https://dll.website/download",
        scanner=FailingSecurityScanner(),
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="scannerfail.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: scanner down"
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_unknown_scan_status_returns_failure() -> None:
    repository = InMemoryRepository()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=StubHTTPClient(),
        download_base_url="https://dll.website/download",
        scanner=UnknownSecurityScanner(),
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="unknownscan.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: Security scan did not complete"
    assert repository.list_all() == []


@pytest.mark.unit
def test_download_dll_use_case_not_scanned_status_returns_failure() -> None:
    repository = InMemoryRepository()
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=StubHTTPClient(),
        download_base_url="https://dll.website/download",
        scanner=NotScannedSecurityScanner(),
    )

    response = use_case.execute(
        DownloadDLLRequest(
            dll_name="notscanned.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
    )

    assert response.success is False
    assert response.error_message == "Download failed: Security scan did not complete"
    assert repository.list_all() == []


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


@pytest.mark.unit
def test_download_batch_use_case_validates_all_names_before_download() -> None:
    repository = InMemoryRepository()
    http_client = StubHTTPClient()
    single_use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download",
    )
    batch_use_case = DownloadBatchUseCase(single_use_case)

    with pytest.raises(ValueError, match="DLL name"):
        batch_use_case.execute(
            DownloadBatchRequest(
                dll_names=["good.dll", "../bad", "other.dll"],
                architecture=Architecture.X64,
                scan_before_save=False,
            )
        )

    assert repository.list_all() == []
