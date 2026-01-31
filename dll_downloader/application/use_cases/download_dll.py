"""
Download DLL Use Case

Orchestrates the process of downloading a DLL file, optionally scanning it
for security threats, and storing it in the repository.
"""

from dataclasses import dataclass

from ...domain.entities.dll_file import Architecture, DLLFile, SecurityStatus
from ...domain.repositories.dll_repository import IDLLRepository
from ...domain.services import IHTTPClient, calculate_sha256
from ...domain.services.download_resolver import IDownloadURLResolver
from ...domain.services.security_scanner import ISecurityScanner


@dataclass
class DownloadDLLRequest:
    """
    Request object for the Download DLL use case.

    Attributes:
        dll_name: Name of the DLL to download
        architecture: Target CPU architecture
        scan_before_save: Whether to scan the file before saving
        force_download: Download even if file already exists locally
    """

    dll_name: str
    architecture: Architecture = Architecture.X64
    scan_before_save: bool = True
    force_download: bool = False


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
            # Check cache first
            cached_response = self._validate_request(request)
            if cached_response:
                return cached_response

            # Download the file
            download_url = self._resolve_download_url(request)
            content = self._http_client.download(download_url)
            if not content:
                return DownloadDLLResponse(
                    success=False,
                    error_message="Failed to download DLL: empty response"
                )

            # Create DLL entity with hash
            dll_file = DLLFile(
                name=request.dll_name,
                architecture=request.architecture,
                download_url=download_url,
                file_size=len(content),
                file_hash=self._calculate_hash(content)
            )

            # Optional security scan
            dll_file, security_warning = self._scan_for_malware(dll_file, request.scan_before_save)

            # Save to repository
            dll_file = self._repository.save(dll_file, content)

            return DownloadDLLResponse(
                success=True,
                dll_file=dll_file,
                was_cached=False,
                security_warning=security_warning
            )

        except Exception as e:
            return DownloadDLLResponse(
                success=False,
                error_message=f"Download failed: {str(e)}"
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
            return self._resolver.resolve_download_url(
                request.dll_name,
                request.architecture
            )
        return self._build_download_url(request.dll_name, request.architecture)
