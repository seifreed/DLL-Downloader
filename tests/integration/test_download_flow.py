# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Integration tests for the complete download flow.

These tests validate the end-to-end download flow using real implementations
of all components with lightweight alternatives for external dependencies.
No mocks or stubs are used.
"""

import hashlib
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from dll_downloader.application.use_cases.download_dll import (
    DownloadDLLRequest,
    DownloadDLLUseCase,
)
from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.infrastructure.persistence.file_repository import (
    FileSystemDLLRepository,
)


class InMemoryHTTPClient:
    """
    Lightweight HTTP client that serves DLL content from memory.

    This is a real implementation that provides deterministic responses
    for testing without making actual network requests.
    """

    def __init__(self) -> None:
        """Initialize the in-memory HTTP client with a content registry."""
        self._content_registry: dict[str, bytes] = {}
        self._file_info_registry: dict[str, dict] = {}

    def register_url(self, url: str, content: bytes, metadata: dict | None = None) -> None:
        """
        Register URL with content to be returned.

        Args:
            url: The URL to register
            content: Binary content to return when URL is downloaded
            metadata: Optional metadata about the file
        """
        self._content_registry[url] = content
        self._file_info_registry[url] = metadata or {
            "size": len(content),
            "content_type": "application/octet-stream",
        }

    def download(self, url: str) -> bytes:
        """
        Download content from registered URL.

        Args:
            url: URL to download from

        Returns:
            Registered binary content

        Raises:
            ValueError: If URL is not registered
        """
        if url not in self._content_registry:
            raise ValueError(f"URL not found: {url}")
        return self._content_registry[url]

    def get_file_info(self, url: str) -> dict:
        """
        Get file metadata without downloading.

        Args:
            url: URL to get info for

        Returns:
            Metadata dictionary

        Raises:
            ValueError: If URL is not registered
        """
        if url not in self._file_info_registry:
            raise ValueError(f"URL not found: {url}")
        return self._file_info_registry[url]


class StaticSecurityScanner:
    """
    Lightweight security scanner with predefined scan results.

    This is a real implementation that provides deterministic security
    assessments for testing without making actual VirusTotal API calls.
    """

    def __init__(self, is_available: bool = True) -> None:
        """
        Initialize the static security scanner.

        Args:
            is_available: Whether the scanner is available for use
        """
        self._is_available = is_available
        self._scan_results: dict[str, tuple[SecurityStatus, str]] = {}

    @property
    def is_available(self) -> bool:
        """Check if scanner is available."""
        return self._is_available

    def register_scan_result(
        self,
        file_hash: str,
        status: SecurityStatus,
        detection_ratio: str,
    ) -> None:
        """
        Register predefined scan result for a file hash.

        Args:
            file_hash: SHA256 hash of the file
            status: Security status to return
            detection_ratio: Detection ratio string (e.g., "0/72")
        """
        self._scan_results[file_hash] = (status, detection_ratio)

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """
        Perform security scan on DLL file.

        Args:
            dll_file: DLL entity to scan

        Returns:
            Updated DLLFile with security scan results
        """
        if not self._is_available:
            return dll_file

        file_hash = dll_file.file_hash
        if file_hash and file_hash in self._scan_results:
            status, ratio = self._scan_results[file_hash]
            return replace(
                dll_file,
                security_status=status,
                vt_detection_ratio=ratio,
                vt_scan_date=datetime(2026, 1, 31, 12, 0, 0)
            )
        else:
            return replace(
                dll_file,
                security_status=SecurityStatus.CLEAN,
                vt_detection_ratio="0/72",
                vt_scan_date=datetime(2026, 1, 31, 12, 0, 0)
            )


@pytest.fixture
def http_client() -> InMemoryHTTPClient:
    """
    Create an in-memory HTTP client for testing.

    Returns:
        Configured InMemoryHTTPClient instance
    """
    return InMemoryHTTPClient()


@pytest.fixture
def security_scanner() -> StaticSecurityScanner:
    """
    Create a static security scanner for testing.

    Returns:
        Configured StaticSecurityScanner instance
    """
    return StaticSecurityScanner(is_available=True)


@pytest.fixture
def repository(tmp_path: Path) -> FileSystemDLLRepository:
    """
    Create a real FileSystemDLLRepository with temporary directory.

    Args:
        tmp_path: pytest's built-in temporary path fixture

    Returns:
        Configured FileSystemDLLRepository instance
    """
    return FileSystemDLLRepository(tmp_path)


@pytest.fixture
def use_case(
    repository: FileSystemDLLRepository,
    http_client: InMemoryHTTPClient,
    security_scanner: StaticSecurityScanner,
) -> DownloadDLLUseCase:
    """
    Create the download DLL use case with all dependencies.

    Args:
        repository: File system repository
        http_client: In-memory HTTP client
        security_scanner: Static security scanner

    Returns:
        Configured DownloadDLLUseCase instance
    """
    return DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://test.example.com/dlls",
        scanner=security_scanner,
    )


@pytest.fixture
def sample_dll_content() -> bytes:
    """
    Generate realistic DLL binary content.

    Returns:
        Bytes representing a minimal valid DLL structure
    """
    dos_header = b'MZ\x90\x00'  # DOS signature
    dos_stub = b'\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
    dos_padding = b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
    dos_filler = b'\x00' * 32
    pe_signature = b'PE\x00\x00'  # PE signature
    content = b'Test DLL content for integration testing.' * 50

    return dos_header + dos_stub + dos_padding + dos_filler + pe_signature + content


class TestDownloadFlowBasicOperations:
    """Test basic download flow scenarios with real implementations."""

    def test_download_new_dll_successfully(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify successful download of a new DLL file.

        Expected Behavior:
            - HTTP client downloads content
            - DLL is saved to repository
            - File exists on filesystem
            - Response indicates success
        """
        # Register URL in HTTP client
        url = "https://test.example.com/dlls/x64/kernel32.dll"
        http_client.register_url(url, sample_dll_content)

        # Execute download
        request = DownloadDLLRequest(
            dll_name="kernel32.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        # Verify response
        assert response.success is True
        assert response.dll_file is not None
        assert response.dll_file.name == "kernel32.dll"
        assert response.dll_file.architecture == Architecture.X64
        assert response.was_cached is False
        assert response.error_message is None

        # Verify file was saved
        found = repository.find_by_name("kernel32.dll", Architecture.X64)
        assert found is not None
        assert found.file_path is not None
        assert Path(found.file_path).exists()

    def test_download_calculates_file_hash(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that file hash is calculated during download.

        Expected Behavior:
            - Hash is calculated from downloaded content
            - Hash matches SHA256 of actual bytes
            - Hash is stored in entity
        """
        url = "https://test.example.com/dlls/x64/test.dll"
        http_client.register_url(url, sample_dll_content)

        request = DownloadDLLRequest(
            dll_name="test.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        expected_hash = hashlib.sha256(sample_dll_content).hexdigest()
        assert response.dll_file.file_hash == expected_hash

    def test_download_x86_architecture(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify downloading x86 DLL to correct directory.

        Expected Behavior:
            - x86 DLL is downloaded
            - File is saved to x86/ subdirectory
            - Architecture is correctly set
        """
        url = "https://test.example.com/dlls/x86/user32.dll"
        http_client.register_url(url, sample_dll_content)

        request = DownloadDLLRequest(
            dll_name="user32.dll",
            architecture=Architecture.X86,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.architecture == Architecture.X86

        # Verify file is in x86 directory
        expected_path = tmp_path / "x86" / "user32.dll"
        assert expected_path.exists()


class TestDownloadFlowCaching:
    """Test caching behavior when files already exist."""

    def test_returns_cached_file_when_exists(
        self,
        use_case: DownloadDLLUseCase,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that existing files are returned without re-downloading.

        Expected Behavior:
            - Existing file is found in repository
            - No HTTP download is performed
            - was_cached flag is True
            - Original file is returned
        """
        # Pre-save a DLL
        dll = DLLFile(name="cached.dll", architecture=Architecture.X64, version="1.0")
        repository.save(dll, sample_dll_content)

        # Attempt to download (should return cached version)
        request = DownloadDLLRequest(
            dll_name="cached.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.was_cached is True
        assert response.dll_file is not None
        assert response.dll_file.version == "1.0"

    def test_force_download_bypasses_cache(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify that force_download bypasses cache.

        Expected Behavior:
            - Existing file is ignored
            - HTTP download is performed
            - was_cached flag is False
            - File is re-downloaded and saved
        """
        # Pre-save a DLL
        dll = DLLFile(name="force.dll", architecture=Architecture.X64, version="1.0")
        repository.save(dll, sample_dll_content)

        # Register new content
        new_content = b"MZ\x90\x00new version content"
        url = "https://test.example.com/dlls/x64/force.dll"
        http_client.register_url(url, new_content)

        # Force download
        request = DownloadDLLRequest(
            dll_name="force.dll",
            architecture=Architecture.X64,
            force_download=True,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.was_cached is False

        # Verify content was updated
        new_hash = hashlib.sha256(new_content).hexdigest()
        assert response.dll_file.file_hash == new_hash


class TestDownloadFlowSecurityScanning:
    """Test security scanning integration."""

    def test_download_with_security_scan_clean(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        security_scanner: StaticSecurityScanner,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify download with security scan for clean file.

        Expected Behavior:
            - File is downloaded
            - Security scan is performed
            - Security status is CLEAN
            - No security warning is returned
            - File is saved
        """
        url = "https://test.example.com/dlls/x64/clean.dll"
        http_client.register_url(url, sample_dll_content)

        file_hash = hashlib.sha256(sample_dll_content).hexdigest()
        security_scanner.register_scan_result(file_hash, SecurityStatus.CLEAN, "0/72")

        request = DownloadDLLRequest(
            dll_name="clean.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.security_status == SecurityStatus.CLEAN
        assert response.dll_file.vt_detection_ratio == "0/72"
        assert response.security_warning is None

    def test_download_with_security_scan_suspicious(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        security_scanner: StaticSecurityScanner,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify download with security scan for suspicious file.

        Expected Behavior:
            - File is downloaded
            - Security scan is performed
            - Security status is SUSPICIOUS
            - Security warning is returned
            - File is still saved (warning only)
        """
        url = "https://test.example.com/dlls/x64/suspicious.dll"
        http_client.register_url(url, sample_dll_content)

        file_hash = hashlib.sha256(sample_dll_content).hexdigest()
        security_scanner.register_scan_result(file_hash, SecurityStatus.SUSPICIOUS, "3/72")

        request = DownloadDLLRequest(
            dll_name="suspicious.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.security_status == SecurityStatus.SUSPICIOUS
        assert response.dll_file.vt_detection_ratio == "3/72"
        assert response.security_warning is not None
        assert "CAUTION" in response.security_warning
        assert "3/72" in response.security_warning

    def test_download_with_security_scan_malicious(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        security_scanner: StaticSecurityScanner,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify download with security scan for malicious file.

        Expected Behavior:
            - File is downloaded
            - Security scan is performed
            - Security status is MALICIOUS
            - Strong warning is returned
            - File is still saved (with warning)
        """
        url = "https://test.example.com/dlls/x64/malicious.dll"
        http_client.register_url(url, sample_dll_content)

        file_hash = hashlib.sha256(sample_dll_content).hexdigest()
        security_scanner.register_scan_result(file_hash, SecurityStatus.MALICIOUS, "45/72")

        request = DownloadDLLRequest(
            dll_name="malicious.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.security_status == SecurityStatus.MALICIOUS
        assert response.dll_file.vt_detection_ratio == "45/72"
        assert response.security_warning is not None
        assert "WARNING" in response.security_warning
        assert "45/72" in response.security_warning
        assert "malicious" in response.security_warning.lower()

    def test_download_without_scanner_available(
        self,
        repository: FileSystemDLLRepository,
        http_client: InMemoryHTTPClient,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify download works when scanner is not available.

        Expected Behavior:
            - File is downloaded
            - No security scan is performed
            - Security status remains NOT_SCANNED
            - No security warning
            - File is saved successfully
        """
        # Create scanner that is not available
        unavailable_scanner = StaticSecurityScanner(is_available=False)

        use_case = DownloadDLLUseCase(
            repository=repository,
            http_client=http_client,
            download_base_url="https://test.example.com/dlls",
            scanner=unavailable_scanner,
        )

        url = "https://test.example.com/dlls/x64/notscan.dll"
        http_client.register_url(url, sample_dll_content)

        request = DownloadDLLRequest(
            dll_name="notscan.dll",
            architecture=Architecture.X64,
            scan_before_save=True,  # Requested but scanner unavailable
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.security_status == SecurityStatus.NOT_SCANNED
        assert response.security_warning is None

    def test_download_with_scan_disabled(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify download without security scan when disabled.

        Expected Behavior:
            - File is downloaded
            - No security scan is performed
            - Security status remains NOT_SCANNED
            - File is saved successfully
        """
        url = "https://test.example.com/dlls/x64/noscan.dll"
        http_client.register_url(url, sample_dll_content)

        request = DownloadDLLRequest(
            dll_name="noscan.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.security_status == SecurityStatus.NOT_SCANNED
        assert response.dll_file.vt_detection_ratio is None


class TestDownloadFlowErrorHandling:
    """Test error handling in the download flow."""

    def test_download_from_unregistered_url_fails(
        self,
        use_case: DownloadDLLUseCase,
    ) -> None:
        """
        Verify that downloading from non-existent URL fails gracefully.

        Expected Behavior:
            - Download attempt fails
            - Error message is provided
            - success flag is False
            - No file is saved
        """
        request = DownloadDLLRequest(
            dll_name="notfound.dll",
            architecture=Architecture.X64,
            scan_before_save=False,
        )
        response = use_case.execute(request)

        assert response.success is False
        assert response.error_message is not None
        assert "failed" in response.error_message.lower()
        assert response.dll_file is None

    def test_download_with_no_scanner_provided(
        self,
        repository: FileSystemDLLRepository,
        http_client: InMemoryHTTPClient,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify download works when no scanner is provided.

        Expected Behavior:
            - File is downloaded
            - No scanning is performed
            - File is saved successfully
            - No security warnings
        """
        use_case = DownloadDLLUseCase(
            repository=repository,
            http_client=http_client,
            download_base_url="https://test.example.com/dlls",
            scanner=None,  # No scanner provided
        )

        url = "https://test.example.com/dlls/x64/noscanner.dll"
        http_client.register_url(url, sample_dll_content)

        request = DownloadDLLRequest(
            dll_name="noscanner.dll",
            architecture=Architecture.X64,
            scan_before_save=True,  # Requested but no scanner
        )
        response = use_case.execute(request)

        assert response.success is True
        assert response.dll_file.security_status == SecurityStatus.NOT_SCANNED
        assert response.security_warning is None


@pytest.mark.integration
class TestDownloadFlowEndToEnd:
    """End-to-end integration tests for complete download scenarios."""

    def test_complete_download_flow_with_all_features(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        security_scanner: StaticSecurityScanner,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
        tmp_path: Path,
    ) -> None:
        """
        Verify complete download flow with all features enabled.

        Expected Behavior:
            - HTTP client downloads content
            - Hash is calculated
            - Security scan is performed
            - File is saved to repository
            - Index is updated
            - All metadata is preserved
        """
        url = "https://test.example.com/dlls/x64/complete.dll"
        http_client.register_url(url, sample_dll_content)

        file_hash = hashlib.sha256(sample_dll_content).hexdigest()
        security_scanner.register_scan_result(file_hash, SecurityStatus.CLEAN, "0/72")

        request = DownloadDLLRequest(
            dll_name="complete.dll",
            architecture=Architecture.X64,
            scan_before_save=True,
            force_download=False,
        )
        response = use_case.execute(request)

        # Verify response
        assert response.success is True
        assert response.was_cached is False
        assert response.dll_file is not None

        # Verify DLL entity
        dll = response.dll_file
        assert dll.name == "complete.dll"
        assert dll.architecture == Architecture.X64
        assert dll.file_hash == file_hash
        assert dll.security_status == SecurityStatus.CLEAN
        assert dll.vt_detection_ratio == "0/72"
        assert dll.file_size == len(sample_dll_content)

        # Verify filesystem
        file_path = Path(dll.file_path)
        assert file_path.exists()
        assert file_path.read_bytes() == sample_dll_content

        # Verify repository
        found = repository.find_by_name("complete.dll", Architecture.X64)
        assert found is not None
        assert found.file_hash == file_hash

        # Verify index persistence
        index_path = tmp_path / ".dll_index.json"
        assert index_path.exists()

    def test_download_multiple_dlls_in_sequence(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify downloading multiple DLLs in sequence.

        Expected Behavior:
            - All DLLs are downloaded successfully
            - Each has unique hash
            - All are saved to repository
            - list_all returns all files
        """
        dlls = [
            ("kernel32.dll", Architecture.X64),
            ("user32.dll", Architecture.X64),
            ("gdi32.dll", Architecture.X86),
        ]

        for dll_name, arch in dlls:
            url = f"https://test.example.com/dlls/{arch.value}/{dll_name}"
            content = dll_name.encode() + sample_dll_content
            http_client.register_url(url, content)

            request = DownloadDLLRequest(
                dll_name=dll_name,
                architecture=arch,
                scan_before_save=False,
            )
            response = use_case.execute(request)

            assert response.success is True

        # Verify all are in repository
        all_dlls = repository.list_all()
        assert len(all_dlls) == 3

        names = {dll.name for dll in all_dlls}
        assert names == {"kernel32.dll", "user32.dll", "gdi32.dll"}

    def test_download_with_cache_then_force_redownload(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify cache behavior followed by forced re-download.

        Expected Behavior:
            - First download saves file
            - Second download returns cached version
            - Third download with force_download re-downloads
            - File is updated with new content
        """
        dll_name = "versioned.dll"
        url = f"https://test.example.com/dlls/x64/{dll_name}"

        # Version 1
        v1_content = b"MZ\x90\x00version 1 content"
        http_client.register_url(url, v1_content)

        request = DownloadDLLRequest(
            dll_name=dll_name,
            architecture=Architecture.X64,
            scan_before_save=False,
        )

        # First download
        response1 = use_case.execute(request)
        assert response1.success is True
        assert response1.was_cached is False
        v1_hash = response1.dll_file.file_hash

        # Second download (cached)
        response2 = use_case.execute(request)
        assert response2.success is True
        assert response2.was_cached is True
        assert response2.dll_file.file_hash == v1_hash

        # Update content
        v2_content = b"MZ\x90\x00version 2 content"
        http_client.register_url(url, v2_content)

        # Force re-download
        request.force_download = True
        response3 = use_case.execute(request)
        assert response3.success is True
        assert response3.was_cached is False
        v2_hash = response3.dll_file.file_hash
        assert v2_hash != v1_hash

        # Verify updated content
        found = repository.find_by_name(dll_name, Architecture.X64)
        assert found.file_hash == v2_hash

    def test_download_with_different_architectures_same_name(
        self,
        use_case: DownloadDLLUseCase,
        http_client: InMemoryHTTPClient,
        repository: FileSystemDLLRepository,
        sample_dll_content: bytes,
    ) -> None:
        """
        Verify downloading same DLL name with different architectures.

        Expected Behavior:
            - Both x86 and x64 versions are saved
            - Each has separate file path
            - Both can be retrieved independently
            - Each has unique hash
        """
        dll_name = "multiarch.dll"

        # x64 version
        x64_url = "https://test.example.com/dlls/x64/multiarch.dll"
        x64_content = b"MZ\x90\x00x64 specific content" + sample_dll_content
        http_client.register_url(x64_url, x64_content)

        # x86 version
        x86_url = "https://test.example.com/dlls/x86/multiarch.dll"
        x86_content = b"MZ\x90\x00x86 specific content" + sample_dll_content
        http_client.register_url(x86_url, x86_content)

        # Download x64
        request_x64 = DownloadDLLRequest(
            dll_name=dll_name,
            architecture=Architecture.X64,
            scan_before_save=False,
        )
        response_x64 = use_case.execute(request_x64)

        # Download x86
        request_x86 = DownloadDLLRequest(
            dll_name=dll_name,
            architecture=Architecture.X86,
            scan_before_save=False,
        )
        response_x86 = use_case.execute(request_x86)

        # Verify both succeeded
        assert response_x64.success is True
        assert response_x86.success is True

        # Verify different hashes
        assert response_x64.dll_file.file_hash != response_x86.dll_file.file_hash

        # Verify both are in repository
        found_x64 = repository.find_by_name(dll_name, Architecture.X64)
        found_x86 = repository.find_by_name(dll_name, Architecture.X86)

        assert found_x64 is not None
        assert found_x86 is not None
        assert found_x64.file_path != found_x86.file_path

        # Verify file paths are in correct directories
        assert "x64" in found_x64.file_path
        assert "x86" in found_x86.file_path
