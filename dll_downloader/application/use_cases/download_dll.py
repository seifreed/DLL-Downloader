"""
Download DLL Use Case

Orchestrates the process of downloading a DLL file, optionally scanning it
for security threats, and storing it in the repository.
"""

import zipfile
from dataclasses import dataclass
from io import BytesIO

from ...domain.entities.dll_file import Architecture, DLLFile, SecurityStatus
from ...domain.errors import (
    DownloadResolutionError,
    HTTPServiceError,
    RepositoryOperationError,
)
from ...domain.repositories.dll_repository import IDLLRepository
from ...domain.services import IHTTPClient, calculate_sha256
from ...domain.services.download_resolver import IDownloadURLResolver
from ...domain.services.security_scanner import ISecurityScanner
from ..errors import ArchiveExtractionError, DownloadExecutionError


@dataclass
class DownloadDLLRequest:
    """
    Request object for the Download DLL use case.

    Attributes:
        dll_name: Name of the DLL to download
        architecture: Target CPU architecture
        scan_before_save: Whether to scan the file before saving
        force_download: Download even if file already exists locally
        extract_archive: Extract the DLL when the server returns a ZIP archive
    """

    dll_name: str
    architecture: Architecture = Architecture.X64
    scan_before_save: bool = True
    force_download: bool = False
    extract_archive: bool = False


@dataclass
class DownloadDLLResponse:
    """
    Response object for the Download DLL use case.

    Attributes:
        success: Whether the operation completed successfully
        dll_file: The downloaded DLL entity (if successful)
        error_message: Error description (if failed)
        was_cached: True if file was already in repository
        security_warning: Warning message if security scan found issues
    """

    success: bool
    dll_file: DLLFile | None = None
    error_message: str | None = None
    was_cached: bool = False
    security_warning: str | None = None


class DownloadDLLUseCase:
    """
    Use case for downloading DLL files.

    This use case orchestrates the complete flow of:
    1. Checking if the DLL already exists locally
    2. Downloading the DLL from a remote source
    3. Optionally scanning for security threats
    4. Saving to the repository

    Example:
        >>> use_case = DownloadDLLUseCase(
        ...     repository=file_repository,
        ...     http_client=requests_client,
        ...     scanner=vt_scanner
        ... )
        >>> request = DownloadDLLRequest(
        ...     dll_name="kernel32.dll",
        ...     architecture=Architecture.X64
        ... )
        >>> response = use_case.execute(request)
        >>> if response.success:
        ...     print(f"Downloaded: {response.dll_file.file_path}")
    """

    def __init__(
        self,
        repository: IDLLRepository,
        http_client: IHTTPClient,
        download_base_url: str,
        scanner: ISecurityScanner | None = None,
        resolver: IDownloadURLResolver | None = None,
    ) -> None:
        """
        Initialize the use case with required dependencies.

        Args:
            repository: Repository for storing DLL files
            http_client: HTTP client for downloading files
            download_base_url: Base URL for DLL downloads
            scanner: Optional security scanner for threat detection
        """
        self._repository = repository
        self._http_client = http_client
        self._scanner = scanner
        self._download_base_url = download_base_url
        self._resolver = resolver

    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        """
        Execute the download DLL use case.

        Orchestrates the download process by delegating to specialized sub-functions.

        Args:
            request: The download request parameters

        Returns:
            DownloadDLLResponse with the result of the operation
        """
        try:
            return self._execute_download(request)
        except DownloadExecutionError as e:
            return DownloadDLLResponse(
                success=False,
                error_message=f"Download failed: {str(e)}"
            )

    def _execute_download(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        """Execute the happy-path download flow and raise typed failures."""
        cached_response = self._validate_request(request)
        if cached_response:
            return cached_response

        download_url = self._resolve_download_url(request)
        content = self._download_content(download_url)
        if not content:
            raise DownloadExecutionError("Failed to download DLL: empty response")
        content = self._prepare_content(content, request)

        dll_file = DLLFile(
            name=request.dll_name,
            architecture=request.architecture,
            download_url=download_url,
            file_size=len(content),
            file_hash=self._calculate_hash(content)
        )

        dll_file, security_warning = self._scan_for_malware(dll_file, request.scan_before_save)
        dll_file = self._save_dll(dll_file, content)

        return DownloadDLLResponse(
            success=True,
            dll_file=dll_file,
            was_cached=False,
            security_warning=security_warning
        )

    def _validate_request(
        self, request: DownloadDLLRequest
    ) -> DownloadDLLResponse | None:
        """
        Validate the download request and check for cached files.

        Args:
            request: The download request to validate

        Returns:
            DownloadDLLResponse if file is cached, None to proceed with download
        """
        if not request.force_download:
            existing = self._repository.find_by_name(
                request.dll_name,
                request.architecture
            )
            if existing:
                return DownloadDLLResponse(
                    success=True,
                    dll_file=existing,
                    was_cached=True
                )
        return None

    def _scan_for_malware(
        self, dll_file: DLLFile, should_scan: bool
    ) -> tuple[DLLFile, str | None]:
        """
        Perform optional security scanning on the DLL file.

        Args:
            dll_file: The DLL entity to scan
            should_scan: Whether scanning was requested

        Returns:
            Tuple of (updated DLLFile, security warning message or None)
        """
        if not should_scan or not self._scanner or not self._scanner.is_available:
            return dll_file, None

        scanned_dll = self._scanner.scan_dll(dll_file)

        if scanned_dll.security_status == SecurityStatus.MALICIOUS:
            return scanned_dll, (
                f"WARNING: VirusTotal detection ratio: {scanned_dll.vt_detection_ratio}. "
                "This file may be malicious!"
            )
        elif scanned_dll.security_status == SecurityStatus.SUSPICIOUS:
            return scanned_dll, (
                f"CAUTION: VirusTotal detection ratio: {scanned_dll.vt_detection_ratio}. "
                "Some engines flagged this file."
            )
        return scanned_dll, None

    def _build_download_url(self, dll_name: str, architecture: Architecture) -> str:
        """
        Build the download URL for a DLL.

        Args:
            dll_name: Name of the DLL
            architecture: Target architecture

        Returns:
            Complete download URL
        """
        arch_path = architecture.value if architecture != Architecture.UNKNOWN else "x64"
        return f"{self._download_base_url}/{arch_path}/{dll_name}"

    def _calculate_hash(self, content: bytes) -> str:
        """
        Calculate SHA256 hash of file content.

        Args:
            content: Raw file bytes

        Returns:
            Hexadecimal SHA256 hash string
        """
        return calculate_sha256(content)

    def _resolve_download_url(self, request: DownloadDLLRequest) -> str:
        """Resolve download URL using resolver if available, else build from base."""
        if self._resolver:
            try:
                return self._resolver.resolve_download_url(
                    request.dll_name,
                    request.architecture
                )
            except DownloadResolutionError as exc:
                raise DownloadExecutionError(str(exc)) from exc
        return self._build_download_url(request.dll_name, request.architecture)

    def _download_content(self, download_url: str) -> bytes:
        """Download bytes and normalize transport-layer failures."""
        try:
            return self._http_client.download(download_url)
        except (HTTPServiceError, ValueError) as exc:
            raise DownloadExecutionError(str(exc)) from exc

    def _save_dll(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        """Persist the DLL while keeping adapter failures out of the interface layer."""
        try:
            return self._repository.save(dll_file, content)
        except RepositoryOperationError as exc:
            raise DownloadExecutionError(str(exc)) from exc

    def _prepare_content(
        self,
        content: bytes,
        request: DownloadDLLRequest,
    ) -> bytes:
        """Validate downloaded content and optionally extract a DLL from a ZIP payload."""
        if not zipfile.is_zipfile(BytesIO(content)):
            raise ArchiveExtractionError("Downloaded archive is not a valid ZIP file")

        if not request.extract_archive:
            self._validate_zip_contains_valid_dll(content, request)
            return content

        try:
            return self._extract_valid_dll_from_zip(content, request)
        except zipfile.BadZipFile as exc:
            raise ArchiveExtractionError("Downloaded archive is not a valid ZIP file") from exc

    def _validate_zip_contains_valid_dll(
        self,
        content: bytes,
        request: DownloadDLLRequest,
    ) -> None:
        """Validate that a ZIP payload contains a real PE DLL before saving it as-is."""
        extracted_content = self._extract_valid_dll_from_zip(content, request)
        self._validate_dll_signature(extracted_content)

    def _extract_valid_dll_from_zip(
        self,
        content: bytes,
        request: DownloadDLLRequest,
    ) -> bytes:
        """Extract and validate the preferred DLL member from a ZIP payload."""
        with zipfile.ZipFile(BytesIO(content)) as archive:
            matching_members = [
                member for member in archive.infolist()
                if not member.is_dir() and member.filename.lower().endswith(".dll")
            ]

            if not matching_members:
                raise ArchiveExtractionError(
                    "ZIP archive does not contain any DLL files"
                )

            expected_name = request.dll_name.lower()
            preferred_member = next(
                (
                    member for member in matching_members
                    if member.filename.rsplit("/", 1)[-1].lower() == expected_name
                ),
                matching_members[0]
            )

            extracted_content = archive.read(preferred_member)
            if not extracted_content:
                raise ArchiveExtractionError("Extracted DLL from ZIP archive is empty")

            self._validate_dll_signature(extracted_content)
            return extracted_content

    @staticmethod
    def _validate_dll_signature(content: bytes) -> None:
        """Reject content that is neither a PE DLL nor a supported archive."""
        if content.startswith(b"MZ"):
            return
        raise DownloadExecutionError("Downloaded content is not a valid DLL (missing PE signature)")
