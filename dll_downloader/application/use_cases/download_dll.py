"""
Download DLL Use Case

Orchestrates the process of downloading a DLL file, optionally scanning it
for security threats, and storing it in the repository.
"""

import logging
import zipfile
import zlib
from dataclasses import dataclass, replace
from io import BytesIO
from pathlib import Path
from urllib.parse import quote

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
from ...domain.services.pe_validation import (
    inspect_pe_dll_architecture,
)
from ...domain.services.security_scanner import ISecurityScanner
from ..errors import ArchiveExtractionError, DownloadExecutionError

logger = logging.getLogger(__name__)
_INVALID_PE_MESSAGE = "Downloaded content is not a valid DLL (invalid PE image layout)"
_NOT_DLL_MESSAGE = "Downloaded PE file is not a DLL"
_ZIP_MEMBER_READ_ERRORS = (
    RuntimeError,
    NotImplementedError,
    zipfile.BadZipFile,
    zlib.error,
    ValueError,
)
_ZIP_COMPRESSION_RATIO_LIMIT = 100
_ZIP_MEMBER_SIZE_LIMIT = 512 * 1024 * 1024  # 512 MiB
_ZIP_COMPRESSED_SIZE_LIMIT = 100 * 1024 * 1024  # 100 MiB


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
                    logger.warning(
                        "Cached payload for %s (%s) does not match request mode, "
                        "re-downloading",
                        request.dll_name,
                        request.architecture.value,
                    )
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
            scanned_dll, security_warning = self._scan_for_malware(
                dll_file,
                should_scan,
            )
            persisted_dll = self._persist_cached_scan_result(dll_file, scanned_dll)
            return persisted_dll, security_warning
        return dll_file, self._security_warning_for_status(dll_file)

    def _persist_cached_scan_result(
        self,
        cached_dll: DLLFile,
        scanned_dll: DLLFile,
    ) -> DLLFile:
        """Persist refreshed scanner metadata for a cache hit."""
        if not cached_dll.file_path:
            return scanned_dll
        try:
            return self._repository.update_metadata(scanned_dll)
        except RepositoryOperationError:
            return scanned_dll

    @classmethod
    def _cached_payload_satisfies_extract(
        cls,
        dll_file: DLLFile,
        architecture: Architecture,
    ) -> bool:
        """Return True when a cached payload is an extracted PE DLL or a
        valid ZIP containing the requested DLL."""
        if not dll_file.file_path:
            return False
        cache_path = Path(dll_file.file_path)
        if cache_path.is_symlink():
            return False
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
            if self._cached_payload_satisfies_extract(
                dll_file,
                request.architecture,
            ):
                return True
            # A cached ZIP cannot satisfy an extract request because the cached
            # DLLFile entity still references the ZIP path, not the extracted DLL.
            # Re-download to get a fresh extraction.
            return False
        if not dll_file.file_path:
            return False

        cache_path = Path(dll_file.file_path)
        if cache_path.is_symlink():
            return False
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

        try:
            self._validate_dll_architecture(content, request.architecture)
        except DownloadExecutionError:
            return False
        return True

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
        except Exception as exc:
            raise DownloadExecutionError(
                "Security scan failed unexpectedly"
            ) from exc

        if scanned_dll.security_status in {
            SecurityStatus.UNKNOWN,
            SecurityStatus.NOT_SCANNED,
        }:
            raise DownloadExecutionError("Security scan did not complete")

        return scanned_dll, self._security_warning_for_status(scanned_dll)

    @staticmethod
    def _security_warning_for_status(dll_file: DLLFile) -> str | None:
        """Return the user-facing warning for known risky scan statuses."""
        ratio = dll_file.vt_detection_ratio or "unknown"
        if dll_file.security_status == SecurityStatus.MALICIOUS:
            return (
                f"WARNING: VirusTotal detection ratio: {ratio}. "
                "This file may be malicious!"
            )
        if dll_file.security_status == SecurityStatus.SUSPICIOUS:
            return (
                f"CAUTION: VirusTotal detection ratio: {ratio}. "
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
        base = self._download_base_url.rstrip("/")
        return f"{base}/{arch_path}/{quote(dll_name, safe='')}"

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
        except (HTTPServiceError, ValueError, OSError) as exc:
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
        try:
            is_zip_archive = zipfile.is_zipfile(BytesIO(content))
        except (ValueError, OSError):
            is_zip_archive = False
        if not is_zip_archive:
            self._validate_dll_architecture(content, request.architecture)
            return content

        try:
            if not request.extract_archive:
                self._validate_zip_contains_valid_dll(content, request)
                return content
            return self._extract_valid_dll_from_zip(content, request)
        except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, ValueError, OverflowError) as exc:
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
            total_decompressed_size = 0
            for member in archive.infolist():
                if member.is_dir():
                    continue
                if member.file_size > _ZIP_MEMBER_SIZE_LIMIT:
                    raise ArchiveExtractionError(
                        "ZIP member exceeds size limit"
                    )
                # Check compression ratio for potential ZIP bombs
                if member.compress_size > 0:
                    ratio = member.file_size / member.compress_size
                    if ratio > _ZIP_COMPRESSION_RATIO_LIMIT:
                        raise ArchiveExtractionError(
                            "ZIP member has suspicious compression ratio, possible ZIP bomb"
                        )
                elif member.file_size > 0:
                    # compress_size == 0 with file_size > 0 is suspicious:
                    # either forged metadata or stored with zero-reported size
                    raise ArchiveExtractionError(
                        "ZIP member has suspicious compression ratio, possible ZIP bomb"
                    )
                total_decompressed_size += member.file_size
            if total_decompressed_size > _ZIP_MEMBER_SIZE_LIMIT:
                raise ArchiveExtractionError(
                    "ZIP total decompressed size exceeds limit"
                )
            matching_members = [
                member for member in archive.infolist()
                if not member.is_dir() and member.filename.lower().endswith(".dll")
            ]

            if not matching_members:
                raise ArchiveExtractionError(
                    "ZIP archive does not contain any DLL files"
                )

            expected_name = request.dll_name.lower()
            # Prefer root-level members over nested ones to avoid path confusion.
            # Sort so that members with fewer path segments come first.
            requested_members = sorted(
                [
                    member for member in matching_members
                    if member.filename.replace("\\", "/").rsplit("/", 1)[-1].lower() == expected_name
                ],
                key=lambda m: m.filename.replace("\\", "/").count("/"),
            )
            if not requested_members:
                raise ArchiveExtractionError(
                    f"ZIP archive does not contain requested DLL {request.dll_name}"
                )

            validation_errors: list[DownloadExecutionError] = []
            read_error: Exception | None = None
            empty_member_found = False
            for member in requested_members:
                if member.compress_size > _ZIP_COMPRESSED_SIZE_LIMIT:
                    raise ArchiveExtractionError(
                        "ZIP member compressed size exceeds safe limit, possible ZIP bomb"
                    )
                try:
                    extracted_content = archive.read(member)
                except _ZIP_MEMBER_READ_ERRORS as exc:
                    read_error = exc
                    continue
                if not extracted_content:
                    empty_member_found = True
                    continue
                if len(extracted_content) > _ZIP_MEMBER_SIZE_LIMIT:
                    raise ArchiveExtractionError(
                        "Extracted DLL exceeds size limit"
                    )
                if member.file_size > 0 and len(extracted_content) != member.file_size:
                    raise ArchiveExtractionError(
                        "Extracted size does not match ZIP metadata, possible ZIP bomb"
                    )
                try:
                    self._validate_dll_architecture(
                        extracted_content,
                        request.architecture,
                    )
                except DownloadExecutionError as exc:
                    validation_errors.append(exc)
                    continue
                return extracted_content

            if validation_errors:
                error_messages = "; ".join(str(e) for e in validation_errors)
                raise ArchiveExtractionError(
                    f"Could not extract valid DLL from ZIP: {error_messages}"
                )
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
        inspection = inspect_pe_dll_architecture(content)
        if inspection.is_pe_not_dll:
            raise DownloadExecutionError(_NOT_DLL_MESSAGE)
        if inspection.is_unsupported_machine:
            raise DownloadExecutionError(
                f"Downloaded DLL uses unsupported PE machine type 0x{inspection.unsupported_machine:04x}"
            )
        if not inspection.is_valid_dll:
            raise DownloadExecutionError(_INVALID_PE_MESSAGE)
        assert inspection.architecture is not None
        return inspection.architecture

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
