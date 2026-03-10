"""
Batch download use case.
"""

from dataclasses import dataclass, field
from typing import Protocol

from ...domain.entities.dll_file import Architecture, normalize_dll_name
from .download_dll import DownloadDLLRequest, DownloadDLLResponse


class SupportsDownloadExecution(Protocol):
    """Minimal contract required to execute a single DLL download."""

    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        """Execute a single DLL download request."""


@dataclass(frozen=True)
class DownloadBatchItem:
    """A single DLL result inside a batch download response."""

    dll_name: str
    response: DownloadDLLResponse


@dataclass(frozen=True)
class DownloadBatchRequest:
    """Input parameters for batch download orchestration."""

    dll_names: list[str]
    architecture: Architecture = Architecture.X64
    scan_before_save: bool = True
    force_download: bool = False
    extract_archive: bool = False


@dataclass(frozen=True)
class DownloadBatchResponse:
    """Structured batch response for interface adapters."""

    items: list[DownloadBatchItem] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for item in self.items if item.response.success)

    @property
    def failure_count(self) -> int:
        return len(self.items) - self.success_count


class DownloadBatchUseCase:
    """Run multiple DLL downloads through the single-download use case."""

    def __init__(self, download_use_case: SupportsDownloadExecution) -> None:
        self._download_use_case = download_use_case

    def execute(self, request: DownloadBatchRequest) -> DownloadBatchResponse:
        items: list[DownloadBatchItem] = []
        for dll_name in request.dll_names:
            normalized_name = normalize_dll_name(dll_name)
            response = self._download_use_case.execute(
                DownloadDLLRequest(
                    dll_name=normalized_name,
                    architecture=request.architecture,
                    scan_before_save=request.scan_before_save,
                    force_download=request.force_download,
                    extract_archive=request.extract_archive,
                )
            )
            items.append(DownloadBatchItem(dll_name=normalized_name, response=response))

        return DownloadBatchResponse(items=items)
