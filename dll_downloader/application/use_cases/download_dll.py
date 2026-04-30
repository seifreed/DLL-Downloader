"""
Download DLL Use Case

Orchestrates the process of downloading a DLL file, optionally scanning it
for security threats, and storing it in the repository.
"""

import zipfile
from dataclasses import dataclass, replace
from io import BytesIO
from pathlib import Path

from ...domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
    normalize_dll_name,
)
from ...domain.errors import (
    DownloadResolutionError,
    HTTPServiceError,
    RepositoryOperationError,
    SecurityServiceError,
)
from ...domain.repositories.dll_repository import IDLLRepository
from ...domain.services import IHTTPClient, calculate_sha256
from ...domain.services.download_resolver import IDownloadURLResolver
from ...domain.services.security_scanner import ISecurityScanner
from ..errors import ArchiveExtractionError, DownloadExecutionError

_PE_POINTER_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"
_PE_COFF_HEADER_SIZE = 20
_PE_NUMBER_OF_SECTIONS_OFFSET_FROM_MACHINE = 2
_PE_SIZE_OF_OPTIONAL_HEADER_OFFSET_FROM_MACHINE = 16
_PE_CHARACTERISTICS_OFFSET_FROM_MACHINE = 18
_PE_DLL_CHARACTERISTIC = 0x2000
_PE_OPTIONAL_HEADER_MAGIC_PE32 = 0x10B
_PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS = 0x20B
_PE_SECTION_HEADER_SIZE = 40
_PE_SECTION_NAME_SIZE = 8
_PE_SECTION_VIRTUAL_SIZE_OFFSET = 8
_PE_SECTION_VIRTUAL_ADDRESS_OFFSET = 12
_PE_SECTION_RAW_SIZE_OFFSET = 16
_PE_SECTION_RAW_POINTER_OFFSET = 20
_PE_MAX_SECTIONS = 96
_PE_MACHINE_ARCHITECTURES = {
    0x014C: Architecture.X86,
    0x8664: Architecture.X64,
}
_INVALID_PE_MESSAGE = "Downloaded content is not a valid DLL (missing PE signature)"
_ZIP_MEMBER_READ_ERRORS = (
    RuntimeError,
    NotImplementedError,
    zipfile.BadZipFile,
)


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
        request = self._normalize_request(request)
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
            try:
                existing = self._repository.find_by_name(
                    request.dll_name,
                    request.architecture
                )
            except RepositoryOperationError as exc:
                raise DownloadExecutionError(str(exc)) from exc
            if existing:
                if not self._cached_payload_satisfies_request(existing, request):
                    return None
                return self._build_cached_response(existing, request)
        return None

    def _build_cached_response(
        self,
        dll_file: DLLFile,
        request: DownloadDLLRequest,
    ) -> DownloadDLLResponse:
        """Build a cache-hit response without bypassing security state."""
        scanned_dll, security_warning = self._scan_cached_dll(
            dll_file,
            request.scan_before_save,
        )
        return DownloadDLLResponse(
            success=True,
            dll_file=scanned_dll,
            was_cached=True,
            security_warning=security_warning,
        )

    def _scan_cached_dll(
        self,
        dll_file: DLLFile,
        should_scan: bool,
    ) -> tuple[DLLFile, str | None]:
        """Scan a cache hit when requested, otherwise preserve known warnings."""
        if should_scan and self._scanner and self._scanner.is_available:
            return self._scan_for_malware(dll_file, should_scan)
        return dll_file, self._security_warning_for_status(dll_file)

    @classmethod
    def _cached_payload_satisfies_extract(
        cls,
        dll_file: DLLFile,
        architecture: Architecture,
    ) -> bool:
        """Return True when a cached payload is already an extracted PE DLL."""
        if not dll_file.file_path:
            return False
        cache_path = Path(dll_file.file_path)
        if not cache_path.is_file():
            return False
        try:
            content = cache_path.read_bytes()
        except OSError:
            return False
        if zipfile.is_zipfile(BytesIO(content)):
            return False
        try:
            cls._validate_dll_architecture(content, architecture)
        except DownloadExecutionError:
            return False
        return True

    def _cached_payload_satisfies_request(
        self,
        dll_file: DLLFile,
        request: DownloadDLLRequest,
    ) -> bool:
        """Return True when a file-backed cache entry matches the active request."""
        if request.extract_archive:
            return self._cached_payload_satisfies_extract(
                dll_file,
                request.architecture,
            )
        if not dll_file.file_path:
            return False

        cache_path = Path(dll_file.file_path)
        if not cache_path.is_file():
            return False

        try:
            content = cache_path.read_bytes()
        except OSError:
            return False

        if zipfile.is_zipfile(BytesIO(content)):
            try:
                self._validate_zip_contains_valid_dll(content, request)
            except (
                ArchiveExtractionError,
                DownloadExecutionError,
                RuntimeError,
                NotImplementedError,
                zipfile.BadZipFile,
            ):
                return False
            return True

        return False

    def _normalize_request(self, request: DownloadDLLRequest) -> DownloadDLLRequest:
        """Normalize user-provided request values before touching dependencies."""
        try:
            normalized_name = normalize_dll_name(request.dll_name)
        except ValueError as exc:
            raise DownloadExecutionError(str(exc)) from exc
        if normalized_name == request.dll_name:
            return request
        return replace(request, dll_name=normalized_name)

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

        try:
            scanned_dll = self._scanner.scan_dll(dll_file)
        except SecurityServiceError as exc:
            raise DownloadExecutionError(str(exc)) from exc

        if scanned_dll.security_status in {
            SecurityStatus.UNKNOWN,
            SecurityStatus.NOT_SCANNED,
        }:
            raise DownloadExecutionError("Security scan did not complete")

        return scanned_dll, self._security_warning_for_status(scanned_dll)

    @staticmethod
    def _security_warning_for_status(dll_file: DLLFile) -> str | None:
        """Return the user-facing warning for known risky scan statuses."""
        if dll_file.security_status == SecurityStatus.MALICIOUS:
            return (
                f"WARNING: VirusTotal detection ratio: {dll_file.vt_detection_ratio}. "
                "This file may be malicious!"
            )
        if dll_file.security_status == SecurityStatus.SUSPICIOUS:
            return (
                f"CAUTION: VirusTotal detection ratio: {dll_file.vt_detection_ratio}. "
                "Some engines flagged this file."
            )
        return None

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
            except (DownloadResolutionError, HTTPServiceError, ValueError) as exc:
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
        is_zip_archive = zipfile.is_zipfile(BytesIO(content))
        if not is_zip_archive:
            raise ArchiveExtractionError("Downloaded archive is not a valid ZIP file")

        try:
            if not request.extract_archive:
                self._validate_zip_contains_valid_dll(content, request)
                return content
            return self._extract_valid_dll_from_zip(content, request)
        except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
            raise ArchiveExtractionError("Downloaded archive is not a valid ZIP file") from exc

    def _validate_zip_contains_valid_dll(
        self,
        content: bytes,
        request: DownloadDLLRequest,
    ) -> None:
        """Validate that a ZIP payload contains a real PE DLL before saving it as-is."""
        self._extract_valid_dll_from_zip(content, request)

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
            requested_members = [
                member for member in matching_members
                if member.filename.rsplit("/", 1)[-1].lower() == expected_name
            ]
            if not requested_members:
                raise ArchiveExtractionError(
                    f"ZIP archive does not contain requested DLL {request.dll_name}"
                )

            validation_error: DownloadExecutionError | None = None
            read_error: Exception | None = None
            empty_member_found = False
            for member in requested_members:
                try:
                    extracted_content = archive.read(member)
                except _ZIP_MEMBER_READ_ERRORS as exc:
                    read_error = exc
                    continue
                if not extracted_content:
                    empty_member_found = True
                    continue
                try:
                    self._validate_dll_architecture(
                        extracted_content,
                        request.architecture,
                    )
                except DownloadExecutionError as exc:
                    validation_error = exc
                    continue
                return extracted_content

            if validation_error is not None:
                raise validation_error
            if read_error is not None:
                raise ArchiveExtractionError(
                    "Downloaded archive is not a valid ZIP file"
                ) from read_error
            if empty_member_found:
                raise ArchiveExtractionError("Extracted DLL from ZIP archive is empty")
            raise ArchiveExtractionError(
                f"ZIP archive does not contain a valid requested DLL {request.dll_name}"
            )

    @staticmethod
    def _detect_pe_architecture(content: bytes) -> Architecture:
        """Return the PE machine architecture or reject invalid DLL content."""
        if not content.startswith(b"MZ"):
            raise DownloadExecutionError(_INVALID_PE_MESSAGE)

        if len(content) < _PE_POINTER_OFFSET + 4:
            raise DownloadExecutionError(_INVALID_PE_MESSAGE)

        pe_offset = int.from_bytes(
            content[_PE_POINTER_OFFSET:_PE_POINTER_OFFSET + 4],
            "little",
        )
        machine_offset = pe_offset + len(_PE_SIGNATURE)
        if (
            pe_offset < 0
            or len(content) < machine_offset + _PE_COFF_HEADER_SIZE
            or content[pe_offset:machine_offset] != _PE_SIGNATURE
        ):
            raise DownloadExecutionError(_INVALID_PE_MESSAGE)

        machine = int.from_bytes(content[machine_offset:machine_offset + 2], "little")
        architecture = _PE_MACHINE_ARCHITECTURES.get(machine)
        if architecture is None:
            raise DownloadExecutionError(
                f"Downloaded DLL uses unsupported PE machine type 0x{machine:04x}"
            )
        if not DownloadDLLUseCase._pe_image_layout_is_valid(
            content,
            machine_offset,
            architecture,
        ):
            raise DownloadExecutionError(_INVALID_PE_MESSAGE)

        characteristics_offset = machine_offset + _PE_CHARACTERISTICS_OFFSET_FROM_MACHINE
        if len(content) < characteristics_offset + 2:
            raise DownloadExecutionError(_INVALID_PE_MESSAGE)
        characteristics = int.from_bytes(
            content[characteristics_offset:characteristics_offset + 2],
            "little",
        )
        if characteristics & _PE_DLL_CHARACTERISTIC == 0:
            raise DownloadExecutionError("Downloaded PE file is not a DLL")
        return architecture

    @staticmethod
    def _pe_image_layout_is_valid(
        content: bytes,
        machine_offset: int,
        architecture: Architecture,
    ) -> bool:
        """Return True when the PE header has an image optional header and sections."""
        section_count = int.from_bytes(
            content[
                machine_offset + _PE_NUMBER_OF_SECTIONS_OFFSET_FROM_MACHINE:
                machine_offset + _PE_NUMBER_OF_SECTIONS_OFFSET_FROM_MACHINE + 2
            ],
            "little",
        )
        if section_count < 1 or section_count > _PE_MAX_SECTIONS:
            return False

        optional_header_size = int.from_bytes(
            content[
                machine_offset + _PE_SIZE_OF_OPTIONAL_HEADER_OFFSET_FROM_MACHINE:
                machine_offset + _PE_SIZE_OF_OPTIONAL_HEADER_OFFSET_FROM_MACHINE + 2
            ],
            "little",
        )
        optional_header_offset = machine_offset + _PE_COFF_HEADER_SIZE
        if optional_header_size < 2:
            return False

        section_table_offset = optional_header_offset + optional_header_size
        if len(content) < section_table_offset:
            return False

        optional_magic = int.from_bytes(
            content[optional_header_offset:optional_header_offset + 2],
            "little",
        )
        if optional_magic != DownloadDLLUseCase._expected_optional_magic(architecture):
            return False

        section_table_size = section_count * _PE_SECTION_HEADER_SIZE
        if len(content) < section_table_offset + section_table_size:
            return False

        return DownloadDLLUseCase._has_loadable_section(
            content,
            section_table_offset,
            section_count,
        )

    @staticmethod
    def _has_loadable_section(
        content: bytes,
        section_table_offset: int,
        section_count: int,
    ) -> bool:
        minimum_raw_pointer = section_table_offset + (
            section_count * _PE_SECTION_HEADER_SIZE
        )
        for index in range(section_count):
            section_offset = section_table_offset + (index * _PE_SECTION_HEADER_SIZE)
            section_header = content[
                section_offset:section_offset + _PE_SECTION_HEADER_SIZE
            ]
            section_name = section_header[:_PE_SECTION_NAME_SIZE].rstrip(b"\x00")
            if not section_name:
                continue

            virtual_size = int.from_bytes(
                section_header[
                    _PE_SECTION_VIRTUAL_SIZE_OFFSET:
                    _PE_SECTION_VIRTUAL_SIZE_OFFSET + 4
                ],
                "little",
            )
            virtual_address = int.from_bytes(
                section_header[
                    _PE_SECTION_VIRTUAL_ADDRESS_OFFSET:
                    _PE_SECTION_VIRTUAL_ADDRESS_OFFSET + 4
                ],
                "little",
            )
            raw_size = int.from_bytes(
                section_header[
                    _PE_SECTION_RAW_SIZE_OFFSET:_PE_SECTION_RAW_SIZE_OFFSET + 4
                ],
                "little",
            )
            raw_pointer = int.from_bytes(
                section_header[
                    _PE_SECTION_RAW_POINTER_OFFSET:_PE_SECTION_RAW_POINTER_OFFSET + 4
                ],
                "little",
            )
            if virtual_address == 0 or (virtual_size == 0 and raw_size == 0):
                continue
            if raw_size == 0:
                return True
            if (
                raw_pointer < minimum_raw_pointer
                or raw_pointer + raw_size > len(content)
            ):
                continue
            return True
        return False

    @staticmethod
    def _expected_optional_magic(architecture: Architecture) -> int:
        if architecture == Architecture.X64:
            return _PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS
        return _PE_OPTIONAL_HEADER_MAGIC_PE32

    @classmethod
    def _validate_dll_architecture(
        cls,
        content: bytes,
        requested_architecture: Architecture,
    ) -> None:
        """Reject PE DLL content that does not match the requested architecture."""
        actual_architecture = cls._detect_pe_architecture(content)
        if requested_architecture == Architecture.UNKNOWN:
            return
        if actual_architecture == requested_architecture:
            return
        raise DownloadExecutionError(
            "Downloaded DLL architecture "
            f"{actual_architecture.value} does not match requested architecture "
            f"{requested_architecture.value}"
        )
