"""
Composition root for the DLL downloader application.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .application.use_cases.download_dll import DownloadDLLUseCase
from .domain.entities.dll_file import DLLFile
from .domain.repositories.dll_repository import IDLLRepository
from .domain.services import (
    IDownloadURLResolver,
    IHTTPClient,
    ScanResult,
)
from .infrastructure.config.settings import Settings


class SupportsClose(Protocol):
    """Minimal closeable contract for runtime resources."""

    def close(self) -> None:
        """Release underlying resources."""


class CloseableHTTPClient(IHTTPClient, SupportsClose, Protocol):
    """HTTP client protocol used by the composition root."""


class CloseableSecurityScanner(SupportsClose, Protocol):
    """Security scanner protocol used by the composition root."""

    @property
    def is_available(self) -> bool:
        """Check if the scanner can be used."""

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a file path."""

    def scan_hash(self, file_hash: str) -> ScanResult:
        """Scan a file by hash."""

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        """Scan a DLL entity."""

    def get_detailed_report(self, file_hash: str) -> dict[str, object]:
        """Get a detailed report for a scanned file."""


class DownloadComponentFactory(Protocol):
    """Factory protocol for creating concrete runtime adapters."""

    def create_repository(self, output_path: Path) -> IDLLRepository:
        """Create the DLL repository adapter."""

    def create_http_client(self, settings: Settings) -> CloseableHTTPClient:
        """Create the HTTP client adapter."""

    def create_scanner(
        self,
        settings: Settings,
    ) -> CloseableSecurityScanner | None:
        """Create the security scanner adapter if configured."""

    def create_resolver(
        self,
        settings: Settings,
        http_client: IHTTPClient,
    ) -> IDownloadURLResolver:
        """Create the download URL resolver."""


class DownloadApplicationAssembler(Protocol):
    """Higher-level composition contract for building a runtime session."""

    def build(
        self,
        settings: Settings,
        output_dir: str | None = None,
    ) -> "DownloadApplication":
        """Build a runtime application graph."""


@dataclass(frozen=True)
class DownloadApplication:
    """Concrete runtime dependencies for executing downloads."""

    use_case: DownloadDLLUseCase
    http_client: CloseableHTTPClient
    scanner: CloseableSecurityScanner | None


def build_download_application(
    settings: Settings,
    assembler: DownloadApplicationAssembler,
    output_dir: str | None = None,
) -> DownloadApplication:
    """Create the application runtime from an explicit assembler contract."""
    return assembler.build(settings, output_dir=output_dir)


__all__ = [
    "SupportsClose",
    "CloseableHTTPClient",
    "CloseableSecurityScanner",
    "DownloadComponentFactory",
    "DownloadApplicationAssembler",
    "DownloadApplication",
    "build_download_application",
]
