"""
VirusTotal Scanner Implementation

Implements the ISecurityScanner interface using the VirusTotal API
for malware analysis and threat detection.
"""

import logging
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime

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


class VirusTotalError(SecurityServiceError):
    """Exception raised for VirusTotal API errors."""
    pass


def _safe_json(response: HTTPResponseProtocol) -> dict[str, object]:
    """Normalize loosely typed HTTP JSON payloads into mappings."""
    payload = response.json()
    if not isinstance(payload, Mapping):
        raise TypeError("VirusTotal response body must be a JSON object")
    normalized: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise TypeError("VirusTotal response keys must be strings")
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
        session_resource: HTTPSessionResource | None = None,
    ) -> None:
        """
        Initialize the VirusTotal scanner.

        Args:
            api_key: VirusTotal API key. If not provided, scanner will be unavailable.
            malicious_threshold: Number of positive detections to mark as malicious
            suspicious_threshold: Number of positive detections to mark as suspicious
        """
        self._api_key = api_key
        self._malicious_threshold = malicious_threshold
        self._suspicious_threshold = suspicious_threshold
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
            return ScanResult(
                file_hash="",
                status=SecurityStatus.UNKNOWN,
                error_message=_API_KEY_MISSING
            )

        with open(file_path, 'rb') as f:
            content = f.read()
        file_hash = calculate_sha256(content)

        try:
            return self.scan_hash(file_hash)
        except FileNotFoundError:
            pass

        try:
            files = {'file': (file_path.split('/')[-1], content)}
            response = self.session.post(f"{self.VT_API_URL}/files", files=files)

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

        except (OSError, requests.RequestException, ValueError, TypeError) as e:
            logger.error(f"Failed to upload file to VirusTotal: {e}")
            raise VirusTotalError(f"File upload failed: {e}") from e

    def scan_hash(self, file_hash: str) -> ScanResult:
        """
        Look up scan results by file hash.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            ScanResult with cached analysis results

        Raises:
            FileNotFoundError: If no results exist for this hash
            VirusTotalError: If the lookup fails
        """
        if not self.is_available:
            return ScanResult(
                file_hash=file_hash,
                status=SecurityStatus.UNKNOWN,
                error_message=_API_KEY_MISSING
            )

        try:
            response = self.session.get(f"{self.VT_API_URL}/files/{file_hash}")
            if response.status_code == 404:
                raise FileNotFoundError(f"No results found for hash: {file_hash}")
            if response.status_code != 200:
                raise VirusTotalError(
                    f"API request failed with status {response.status_code}"
                )
            return self._parse_response(file_hash, _safe_json(response))
        except FileNotFoundError:
            raise
        except (requests.RequestException, RuntimeError, TypeError, ValueError) as e:
            logger.error(f"Failed to query VirusTotal: {e}")
            raise VirusTotalError(f"Hash lookup failed: {e}") from e

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """
        Scan a DLL entity and update its security status.

        Args:
            dll_file: The DLL entity to scan

        Returns:
            Updated DLLFile with security information
        """
        if not dll_file.file_hash:
            logger.warning("Cannot scan DLL without file hash")
            return dll_file

        try:
            result = self.scan_hash(dll_file.file_hash)

            # Create updated DLL with scan results
            return replace(
                dll_file,
                security_status=result.status,
                vt_detection_ratio=result.detection_ratio,
                vt_scan_date=result.scan_date,
            )

        except FileNotFoundError:
            logger.info(f"No VT results for {dll_file.name}, file not previously scanned")
            return replace(dll_file, security_status=SecurityStatus.UNKNOWN)

        except VirusTotalError as e:
            logger.error(f"VT scan failed for {dll_file.name}: {e}")
            return dll_file

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

        try:
            url = f"{self.VT_API_URL}/files/{file_hash}"
            response = self.session.get(url)

            if response.status_code != 200:
                raise VirusTotalError(
                    f"Failed to get report: {response.status_code}"
                )

            return dict(_safe_json(response))

        except (requests.RequestException, RuntimeError, TypeError, ValueError) as e:
            logger.error(f"Failed to get detailed report: {e}")
            raise VirusTotalError(f"Report retrieval failed: {e}") from e

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

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        total_positives = malicious + suspicious

        status = self._determine_security_status(total_positives, total)

        detection_ratio = f"{total_positives}/{total}" if total > 0 else None

        scan_timestamp = attributes.get("last_analysis_date")
        scan_date = (
            datetime.fromtimestamp(float(scan_timestamp))
            if isinstance(scan_timestamp, (int, float))
            else datetime.now()
        )

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
