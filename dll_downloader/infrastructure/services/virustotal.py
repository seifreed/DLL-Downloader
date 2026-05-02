"""
VirusTotal Scanner Implementation

Implements the ISecurityScanner interface using the VirusTotal API
for malware analysis and threat detection.
"""

import contextlib
import json
import logging
import os
import stat
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import requests

from ...domain.entities.dll_file import DLLFile, SecurityStatus
from ...domain.errors import SecurityServiceError
from ...domain.services import calculate_sha256
from ...domain.services.security_scanner import ISecurityScanner, ScanResult
from ..http_session import (
    HTTPResponseProtocol,
    HTTPSessionProtocol,
    HTTPSessionResource,
)

logger = logging.getLogger(__name__)
_API_KEY_MISSING = "VirusTotal API key not configured"
_VT_UPLOAD_MAX_BYTES = 32 * 1024 * 1024  # 32 MiB
_VT_RESPONSE_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB


def _is_valid_hash(value: str) -> bool:
    """Return True when value is a hex hash with valid length for VirusTotal lookups."""
    if not value:
        return False
    if len(value) not in (32, 40, 64):  # MD5, SHA-1, SHA-256
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


class VirusTotalError(SecurityServiceError):
    """Exception raised for VirusTotal API errors."""
    pass


class HashNotFoundError(VirusTotalError):
    """Exception raised when a hash has no VirusTotal results."""
    pass


def _safe_int(value: object) -> int:
    """Safely coerce API values to int, handling float-like strings."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except (ValueError, OverflowError):
            logger.warning("VT API returned unparseable integer value: %r, defaulting to 0", value)
            return 0
    logger.warning("VT API returned unexpected type for integer field: %r, defaulting to 0", value)
    return 0


def _safe_json(response: HTTPResponseProtocol) -> dict[str, object]:
    """Normalize loosely typed HTTP JSON payloads into mappings."""

    content_length = None
    cl_header = response.headers.get("content-length") if hasattr(response, "headers") else None
    if cl_header:
        try:
            content_length = int(cl_header)
        except (ValueError, TypeError):
            pass
    if content_length is not None and content_length > _VT_RESPONSE_MAX_BYTES:
        raise VirusTotalError(
            f"VirusTotal response exceeds size limit ({content_length} bytes)"
        )

    # Stream-read the response body with a size limit to protect against
    # responses that omit Content-Length or use chunked transfer encoding.
    chunks: list[bytes] = []
    total_bytes = 0
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                total_bytes += len(chunk)
                if total_bytes > _VT_RESPONSE_MAX_BYTES:
                    raise VirusTotalError(
                        f"VirusTotal response exceeds size limit ({_VT_RESPONSE_MAX_BYTES} bytes)"
                    )
                chunks.append(chunk)
    except AttributeError:
        pass  # iter_content not available; fall through to response.json()

    if chunks:
        body = b"".join(chunks)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise VirusTotalError(f"Invalid JSON in VirusTotal response: {exc}") from exc
    else:
        try:
            payload = response.json()
        except (ValueError, UnicodeDecodeError) as exc:
            raise VirusTotalError(f"Invalid JSON in VirusTotal response: {exc}") from exc

    if not isinstance(payload, Mapping):
        raise VirusTotalError("VirusTotal response body must be a JSON object")
    normalized: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise VirusTotalError("VirusTotal response keys must be strings")
        normalized[key] = value
    return normalized


def _data_section(payload: Mapping[str, object]) -> dict[str, object]:
    data = payload.get("data", {})
    if not isinstance(data, Mapping):
        return {}

    normalized: dict[str, object] = {}
    for key, value in data.items():
        if isinstance(key, str):
            normalized[key] = value
    return normalized


class VirusTotalScanner(ISecurityScanner):
    """
    Security scanner implementation using VirusTotal API.

    This implementation connects to the VirusTotal API to:
    - Look up files by hash to check existing scan results
    - Submit new files for scanning
    - Retrieve detailed analysis reports

    The scanner supports both API v2 and v3, with v3 being preferred.

    Architecture Notes:
        Uses a composed HTTPSessionResource for API communication and cleanup.
        That keeps the technical session lifecycle reusable without coupling
        scanner behavior to a shared infrastructure base class.

    Example:
        >>> scanner = VirusTotalScanner(api_key="your-api-key")
        >>> if scanner.is_available:
        ...     result = scanner.scan_hash("abc123...")
        ...     print(f"Detection ratio: {result.detection_ratio}")

    Attributes:
        MALICIOUS_THRESHOLD: Number of detections to consider malicious (default: 5)
        SUSPICIOUS_THRESHOLD: Number of detections to consider suspicious (default: 1)
    """

    VT_API_URL = "https://www.virustotal.com/api/v3"
    MALICIOUS_THRESHOLD = 5
    SUSPICIOUS_THRESHOLD = 1

    def __init__(
        self,
        api_key: str | None = None,
        malicious_threshold: int = 5,
        suspicious_threshold: int = 1,
        timeout: float = 60.0,
        session_resource: HTTPSessionResource | None = None,
    ) -> None:
        """
        Initialize the VirusTotal scanner.

        Args:
            api_key: VirusTotal API key. If not provided, scanner will be unavailable.
            malicious_threshold: Number of positive detections to mark as malicious
            suspicious_threshold: Number of positive detections to mark as suspicious
            timeout: Timeout in seconds for VirusTotal API requests
        """
        self._api_key = api_key
        self._malicious_threshold = malicious_threshold
        self._suspicious_threshold = suspicious_threshold
        self._timeout = timeout
        session_headers: dict[str, str] = {}
        if self._api_key:
            session_headers = {
                'x-apikey': self._api_key,
                'Accept': 'application/json'
            }
        self._session_resource = session_resource or HTTPSessionResource(
            headers=session_headers
        )

    @property
    def session(self) -> HTTPSessionProtocol:
        return self._session_resource.session

    @property
    def has_active_session(self) -> bool:
        """Report whether this scanner currently owns a live session instance."""
        return self._session_resource.has_session

    def close(self) -> None:
        self._session_resource.close()

    def __enter__(self) -> "VirusTotalScanner":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        self.close()

    @property
    def is_available(self) -> bool:
        """
        Check if the scanner is available and properly configured.

        Returns:
            True if API key is set and valid
        """
        return bool(self._api_key)

    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file by uploading it to VirusTotal.

        Args:
            file_path: Path to the file to scan

        Returns:
            ScanResult with analysis results

        Raises:
            VirusTotalError: If the scan fails
        """
        if not self.is_available:
            try:
                content = Path(file_path).read_bytes()
                computed_hash = calculate_sha256(content)
            except OSError:
                computed_hash = None
            return ScanResult(
                file_hash=computed_hash,
                status=SecurityStatus.UNKNOWN,
                error_message=_API_KEY_MISSING
            )

        path = Path(file_path)
        try:
            # Use O_NONBLOCK to prevent blocking on FIFOs and other special files,
            # then clear it before wrapping with fdopen so regular file reads work.
            open_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(str(path), open_flags)
        except FileNotFoundError:
            raise VirusTotalError(
                "File upload failed: path does not exist"
            ) from None
        except OSError as e:
            if e.errno == 40:  # ELOOP - symlink
                raise VirusTotalError(
                    "File upload failed: path is a symlink"
                ) from e
            raise VirusTotalError(f"File upload failed: {e}") from e

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                fd = -1
                raise VirusTotalError(
                    "File upload failed: path is not a regular file"
                )
            file_size = st.st_size
            if file_size > _VT_UPLOAD_MAX_BYTES:
                raise VirusTotalError(
                    f"File exceeds {_VT_UPLOAD_MAX_BYTES // (1024 * 1024)} MiB upload limit"
                )
            # Clear O_NONBLOCK for regular files so read() works normally.
            with contextlib.suppress(OSError):
                os.set_blocking(fd, True)
            with os.fdopen(fd, "rb") as f:
                fd = -1
                content = f.read()
        except VirusTotalError:
            raise
        except OSError as e:
            raise VirusTotalError(f"File upload failed: {e}") from e
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)

        if len(content) > _VT_UPLOAD_MAX_BYTES:
            raise VirusTotalError(
                f"File exceeds {_VT_UPLOAD_MAX_BYTES // (1024 * 1024)} MiB upload limit"
            )

        file_hash = calculate_sha256(content)
        upload_content = content[:_VT_UPLOAD_MAX_BYTES]

        try:
            return self.scan_hash(file_hash)
        except HashNotFoundError:
            pass
        except VirusTotalError as exc:
            # Re-raise non-retryable errors (auth failures, forbidden, etc.)
            # rather than silently falling through to a second doomed request.
            error_message = str(exc).lower()
            if any(
                indicator in error_message
                for indicator in ("401", "403", "unauthorized", "forbidden")
            ):
                raise
            logger.info(
                "Hash lookup failed for %s, proceeding with upload: %s", file_hash, exc
            )

        response: HTTPResponseProtocol | None = None
        try:
            filename = Path(file_path).name
            files = {'file': (filename, upload_content)}
            response = self.session.post(
                f"{self.VT_API_URL}/files",
                files=files,
                timeout=self._timeout,
            )

            if response.status_code != 200:
                raise VirusTotalError(f"Upload failed: {response.status_code}")

            logger.info(
                "File submitted for analysis: %s",
                _data_section(_safe_json(response)).get("id"),
            )
            return ScanResult(
                file_hash=file_hash,
                status=SecurityStatus.UNKNOWN,
                error_message="File submitted for analysis. Results pending."
            )

        except (
            OSError,
            requests.RequestException,
            RuntimeError,
        ) as e:
            logger.error("Failed to upload file to VirusTotal: %s", e)
            raise VirusTotalError(f"File upload failed: {e}") from e
        finally:
            if response is not None:
                self._close_response(response)

    def scan_hash(self, file_hash: str) -> ScanResult:
        """
        Look up scan results by file hash.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            ScanResult with cached analysis results

        Raises:
            HashNotFoundError: If no results exist for this hash
            VirusTotalError: If the lookup fails
        """
        if not self.is_available:
            return ScanResult(
                file_hash=file_hash,
                status=SecurityStatus.UNKNOWN,
                error_message=_API_KEY_MISSING
            )

        if not _is_valid_hash(file_hash):
            raise VirusTotalError(f"Invalid file hash: {file_hash!r}")

        response: HTTPResponseProtocol | None = None
        try:
            response = self.session.get(
                f"{self.VT_API_URL}/files/{file_hash}",
                timeout=self._timeout,
            )
            if response.status_code == 404:
                raise HashNotFoundError(f"No results found for hash: {file_hash}")
            if response.status_code != 200:
                raise VirusTotalError(
                    f"API request failed with status {response.status_code}"
                )
            return self._parse_response(file_hash, _safe_json(response))
        except HashNotFoundError:
            raise
        except (requests.RequestException, RuntimeError) as e:
            logger.error("Failed to query VirusTotal: %s", e)
            raise VirusTotalError(f"Hash lookup failed: {e}") from e
        finally:
            if response is not None:
                self._close_response(response)

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """
        Scan a DLL entity and update its security status.

        Args:
            dll_file: The DLL entity to scan

        Returns:
            Updated DLLFile with security information
        """
        if not dll_file.file_hash:
            raise VirusTotalError(f"Cannot scan DLL without file hash: {dll_file.name}")

        try:
            result = self.scan_hash(dll_file.file_hash)

            # Create updated DLL with scan results
            return replace(
                dll_file,
                security_status=result.status,
                vt_detection_ratio=result.detection_ratio,
                vt_scan_date=result.scan_date,
            )

        except HashNotFoundError:
            logger.info("No VT results for %s, file not previously scanned", dll_file.name)
            return replace(
                dll_file,
                security_status=SecurityStatus.UNKNOWN,
                vt_detection_ratio=None,
            )

        except VirusTotalError as e:
            logger.error("VT scan failed for %s: %s", dll_file.name, e)
            raise

    def get_detailed_report(self, file_hash: str) -> dict[str, object]:
        """
        Get a detailed scan report for a file.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Full API response as dictionary

        Raises:
            VirusTotalError: If the report retrieval fails
        """
        if not self.is_available:
            raise VirusTotalError(_API_KEY_MISSING)

        response: HTTPResponseProtocol | None = None
        try:
            url = f"{self.VT_API_URL}/files/{file_hash}"
            response = self.session.get(url, timeout=self._timeout)

            if response.status_code != 200:
                raise VirusTotalError(
                    f"Failed to get report: {response.status_code}"
                )

            return dict(_safe_json(response))

        except (requests.RequestException, RuntimeError) as e:
            logger.error("Failed to get detailed report: %s", e)
            raise VirusTotalError(f"Report retrieval failed: {e}") from e
        finally:
            if response is not None:
                self._close_response(response)

    @staticmethod
    def _close_response(response: HTTPResponseProtocol) -> None:
        close_response = getattr(response, "close", None)
        if not callable(close_response):
            return
        try:
            close_response()
        except (OSError, requests.RequestException) as exc:
            logger.warning("Failed to close VirusTotal response: %s", exc)

    def _determine_security_status(
        self, total_positives: int, total: int
    ) -> SecurityStatus:
        """
        Determine the security status based on detection thresholds.

        Args:
            total_positives: Combined count of malicious and suspicious detections
            total: Total number of engines that analyzed the file

        Returns:
            SecurityStatus based on threshold comparison
        """
        if total_positives >= self._malicious_threshold:
            return SecurityStatus.MALICIOUS
        if total_positives >= self._suspicious_threshold:
            return SecurityStatus.SUSPICIOUS
        return SecurityStatus.CLEAN if total > 0 else SecurityStatus.UNKNOWN

    def _extract_engine_detections(
        self,
        data: Mapping[str, object],
    ) -> dict[str, str]:
        """
        Extract individual engine detection results from API response.

        Args:
            data: Raw API response data

        Returns:
            Dictionary mapping engine names to their detection verdicts
        """
        attributes = self._extract_attributes(data)
        results = attributes.get("last_analysis_results", {})
        if not isinstance(results, dict):
            return {}
        detections: dict[str, str] = {}
        for engine, result in results.items():
            if not isinstance(result, dict):
                continue
            verdict = result.get("result")
            if isinstance(verdict, str) and verdict:
                detections[engine] = verdict
        return detections

    def _parse_response(
        self,
        file_hash: str,
        data: Mapping[str, object],
    ) -> ScanResult:
        """
        Parse VirusTotal API response into ScanResult.

        Orchestrates the extraction of scan statistics, security status
        determination, and detection details from the API response.

        Args:
            file_hash: The file hash that was queried
            data: Raw API response data

        Returns:
            Parsed ScanResult
        """
        attributes = self._extract_attributes(data)
        stats = attributes.get("last_analysis_stats", {})
        if not isinstance(stats, dict):
            stats = {}

        malicious = _safe_int(stats.get('malicious', 0))
        suspicious = _safe_int(stats.get('suspicious', 0))
        total = sum(_safe_int(v) for v in stats.values())
        total_positives = malicious + suspicious

        status = self._determine_security_status(total_positives, total)

        detection_ratio = f"{total_positives}/{total}" if total > 0 else None

        scan_timestamp = attributes.get("last_analysis_date")
        scan_date: datetime | None = None
        if isinstance(scan_timestamp, (int, float)):
            scan_date = datetime.fromtimestamp(float(scan_timestamp), tz=UTC)

        detections = self._extract_engine_detections(data)

        return ScanResult(
            file_hash=file_hash,
            status=status,
            detection_ratio=detection_ratio,
            detections=detections,
            scan_date=scan_date,
            permalink=f"https://www.virustotal.com/gui/file/{file_hash}"
        )

    @staticmethod
    def _extract_attributes(data: Mapping[str, object]) -> Mapping[str, object]:
        data_section = data.get("data")
        if isinstance(data_section, dict):
            attributes = data_section.get("attributes")
            if isinstance(attributes, dict):
                return attributes
        return {}
