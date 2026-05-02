"""
DLL File Entity

Represents a DLL file with its metadata and security information.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

_SAFE_DLL_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.dll", re.IGNORECASE)
_WINDOWS_RESERVED_NAMES = frozenset({
    "con", "nul", "aux", "prn",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
})


def normalize_dll_name(name: str) -> str:
    """Normalize DLL name by ensuring .dll extension.

    Args:
        name: The DLL name to normalize

    Returns:
        Name with .dll extension appended if not present
    """
    stripped_name = name.strip()
    if not stripped_name:
        raise ValueError("DLL name cannot be empty")

    normalized_name = stripped_name.lower()
    if not normalized_name.endswith('.dll'):
        normalized_name = f"{normalized_name}.dll"

    base_name = normalized_name[:-4]
    if (
        "/" in normalized_name
        or "\\" in normalized_name
        or not _SAFE_DLL_NAME_PATTERN.fullmatch(normalized_name)
        or base_name in _WINDOWS_RESERVED_NAMES
    ):
        raise ValueError("DLL name must be a simple filename")

    return normalized_name


class Architecture(Enum):
    """CPU architecture types for DLL files."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class SecurityStatus(Enum):
    """Security scan status for a DLL file."""
    NOT_SCANNED = "not_scanned"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DLLFile:
    """
    Entity representing a DLL file.

    This is the core domain entity that encapsulates all information
    about a DLL file including its metadata, location, and security status.

    Attributes:
        name: The filename of the DLL (e.g., 'kernel32.dll')
        version: Optional version string of the DLL
        architecture: CPU architecture the DLL is compiled for
        file_hash: SHA256 hash of the file contents
        file_path: Local filesystem path where the DLL is stored
        download_url: URL from which the DLL was downloaded
        file_size: Size of the file in bytes
        security_status: Result of security scanning
        vt_detection_ratio: VirusTotal detection ratio (e.g., '0/72')
        vt_scan_date: Date of the last VirusTotal scan
        created_at: Timestamp when this entity was created
    """

    name: str
    version: str | None = None
    architecture: Architecture = Architecture.UNKNOWN
    file_hash: str | None = None
    file_path: str | None = None
    download_url: str | None = None
    file_size: int | None = None
    security_status: SecurityStatus = SecurityStatus.NOT_SCANNED
    vt_detection_ratio: str | None = None
    vt_scan_date: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))

    def __post_init__(self) -> None:
        """Validate and normalize entity after initialization."""
        object.__setattr__(self, 'name', normalize_dll_name(self.name))

    @property
    def is_scanned(self) -> bool:
        """Check if the DLL has been security scanned."""
        return self.security_status != SecurityStatus.NOT_SCANNED

    @property
    def is_safe(self) -> bool:
        """Check if the DLL is considered safe based on security scan."""
        return self.security_status == SecurityStatus.CLEAN

    @property
    def display_name(self) -> str:
        """Get a formatted display name including version if available."""
        if self.version:
            return f"{self.name} (v{self.version})"
        return self.name
