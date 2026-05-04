"""
Batch download use case.
"""

import logging
from dataclasses import dataclass, field
from typing import Protocol

from ...domain.entities.dll_file import Architecture, normalize_dll_name
from ...domain.errors import DomainPortError
from ..errors import ApplicationError
from .download_dll import DownloadDLLRequest, DownloadDLLResponse

logger = logging.getLogger(__name__)


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

    dll_names: tuple[str, ...]
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
        seen_names: set[str] = set()
        for dll_name in request.dll_names:
            try:
                normalized_name = normalize_dll_name(dll_name)
            except ValueError as exc:
                logger.warning("Skipping invalid DLL name in batch: %s", exc)
                items.append(
                    DownloadBatchItem(
                        dll_name=dll_name,
                        response=DownloadDLLResponse(
                            success=False,
                            error_message=str(exc),
                        ),
                    )
                )
                continue
            if normalized_name in seen_names:
                logger.info("Skipping duplicate DLL name in batch: %s", normalized_name)
                continue
            seen_names.add(normalized_name)
            try:
                response = self._download_use_case.execute(
                    DownloadDLLRequest(
                        dll_name=normalized_name,
                        architecture=request.architecture,
                        scan_before_save=request.scan_before_save,
                        force_download=request.force_download,
                        extract_archive=request.extract_archive,
                    )
                )
            except (MemoryError, DomainPortError, ApplicationError):
                raise
            except Exception as exc:
                logger.error("Unexpected error downloading %s: %s", normalized_name, exc, exc_info=True)
                response = DownloadDLLResponse(
                    success=False,
                    error_message="Unexpected download error",
                )
            items.append(DownloadBatchItem(dll_name=normalized_name, response=response))

        return DownloadBatchResponse(items=items)
