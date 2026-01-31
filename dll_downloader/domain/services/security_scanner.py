"""
Security Scanner Interface

Defines the contract for security scanning services that analyze DLL files
for malware and other threats.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from ..entities.dll_file import DLLFile, SecurityStatus


@dataclass(frozen=True)
class ScanResult:
    """
    Result of a security scan operation.

    Attributes:
        file_hash: SHA256 hash of the scanned file
        status: Overall security status determination
        detection_ratio: Ratio string (e.g., '5/72' meaning 5 of 72 engines detected)
        detections: Dictionary mapping engine names to their detection results
        scan_date: Timestamp of when the scan was performed
        permalink: Optional URL to the full scan report
        error_message: Optional error message if scan failed
    """

    file_hash: str
    status: SecurityStatus
    detection_ratio: str | None = None
    detections: dict[str, str] = field(default_factory=dict)
    scan_date: datetime = field(default_factory=datetime.now)
    permalink: str | None = None
    error_message: str | None = None

    @property
    def is_clean(self) -> bool:
        """Check if the scan result indicates a clean file."""
        return self.status == SecurityStatus.CLEAN

    @property
    def detection_count(self) -> int:
        """Get the number of positive detections."""
        if self.detection_ratio:
            try:
                return int(self.detection_ratio.split('/')[0])
            except (ValueError, IndexError):
                return 0
        return len([d for d in self.detections.values() if d])


class ISecurityScanner(ABC):
    """
    Abstract interface for security scanning services.

    Implementations of this interface connect to various malware scanning
    services (e.g., VirusTotal, Hybrid Analysis) to analyze files.
    """

    @abstractmethod
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file by its local path.

        Args:
            file_path: Path to the file to scan

        Returns:
            ScanResult with the analysis results

        Raises:
            ScannerError: If the scan operation fails
        """
        pass

    @abstractmethod
    def scan_hash(self, file_hash: str) -> ScanResult:
        """
        Look up scan results by file hash.

        This is typically faster than uploading the full file,
        as it checks if the file has been previously analyzed.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            ScanResult with the analysis results

        Raises:
            ScannerError: If the lookup fails
            FileNotFoundError: If no results exist for this hash
        """
        pass

    @abstractmethod
    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """
        Scan a DLL entity and update its security status.

        This is a convenience method that scans the DLL and returns
        an updated entity with security information populated.

        Args:
            dll_file: The DLL entity to scan

        Returns:
            Updated DLLFile with security_status and VT fields populated
        """
        pass

    @abstractmethod
    def get_detailed_report(self, file_hash: str) -> dict[str, object]:
        """
        Get a detailed scan report for a file.

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary containing the full scan report

        Raises:
            ScannerError: If the report retrieval fails
        """
        pass

    @property
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the scanner service is available and configured.

        Returns:
            True if the service can be used, False otherwise
        """
        pass
