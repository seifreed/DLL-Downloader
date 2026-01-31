"""
VirusTotal Scanner Implementation

Implements the ISecurityScanner interface using the VirusTotal API
for malware analysis and threat detection.
"""

import logging
from dataclasses import replace
from datetime import datetime
from typing import cast

from ...domain.entities.dll_file import DLLFile, SecurityStatus
from ...domain.services import calculate_sha256
from ...domain.services.security_scanner import ISecurityScanner, ScanResult
from ..base import SessionMixin

logger = logging.getLogger(__name__)
_API_KEY_MISSING = "VirusTotal API key not configured"


class VirusTotalError(Exception):
    """Exception raised for VirusTotal API errors."""
    pass


class VirusTotalScanner(SessionMixin, ISecurityScanner):
    """
    Security scanner implementation using VirusTotal API.

    This implementation connects to the VirusTotal API to:
    - Look up files by hash to check existing scan results
    - Submit new files for scanning
    - Retrieve detailed analysis reports

    The scanner supports both API v2 and v3, with v3 being preferred.

    Architecture Notes:
        Inherits from SessionMixin to reuse HTTP session management logic
        for API communication. This is an intentional infrastructure-layer
        coupling for shared technical concerns (HTTP connections, cleanup).
        See base.py for design rationale.

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
        suspicious_threshold: int = 1
    ) -> None:
        """
        Initialize the VirusTotal scanner.

        Args:
            api_key: VirusTotal API key. If not provided, scanner will be unavailable.
            malicious_threshold: Number of positive detections to mark as malicious
            suspicious_threshold: Number of positive detections to mark as suspicious
        """
        super().__init__()
        self._api_key = api_key
        self._malicious_threshold = malicious_threshold
        self._suspicious_threshold = suspicious_threshold
        if self._api_key:
            self._session_headers = {
                'x-apikey': self._api_key,
                'Accept': 'application/json'
            }

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
                response.json().get('data', {}).get('id')
            )
            return ScanResult(
                file_hash=file_hash,
                status=SecurityStatus.UNKNOWN,
                error_message="File submitted for analysis. Results pending."
            )

        except Exception as e:
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
            return self._parse_response(file_hash, response.json())
        except FileNotFoundError:
            raise
        except Exception as e:
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

            return cast(dict[str, object], response.json())

        except Exception as e:
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

    def _extract_engine_detections(self, data: dict[str, object]) -> dict[str, str]:
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

    def _parse_response(self, file_hash: str, data: dict[str, object]) -> ScanResult:
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
    def _extract_attributes(data: dict[str, object]) -> dict[str, object]:
        data_section = data.get("data")
        if isinstance(data_section, dict):
            attributes = data_section.get("attributes")
            if isinstance(attributes, dict):
                return attributes
        return {}
