"""
Unit tests for the composition root.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

from dll_downloader.bootstrap import (
    CloseableHTTPClient,
    CloseableSecurityScanner,
    DownloadApplication,
    DownloadApplicationAssembler,
    build_download_application,
)
from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.domain.repositories.dll_repository import IDLLRepository
from dll_downloader.domain.services import (
    HTTPFileInfo,
    IDownloadURLResolver,
    ISecurityScanner,
    ScanResult,
)
from dll_downloader.infrastructure.composition import build_default_download_application
from dll_downloader.infrastructure.config.settings import Settings
from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient


@dataclass
class StubRepository(IDLLRepository):
    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        return dll_file

    def find_by_name(
        self,
        name: str,
        architecture: Architecture | None = None,
    ) -> DLLFile | None:
        return None

    def find_by_hash(self, file_hash: str) -> DLLFile | None:
        return None

    def list_all(self) -> list[DLLFile]:
        return []

    def delete(self, dll_file: DLLFile) -> bool:
        return True

    def exists(self, name: str, architecture: Architecture | None = None) -> bool:
        return False


class StubHTTPClient(CloseableHTTPClient):
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def download(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        return b"data"

    def get_text(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        return "text"

    def get_file_info(self, url: str) -> HTTPFileInfo:
        return {
            "content_type": "application/octet-stream",
            "content_length": 4,
            "last_modified": None,
            "etag": None,
            "accept_ranges": False,
        }


class StubScanner(CloseableSecurityScanner, ISecurityScanner):
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True

    @property
    def is_available(self) -> bool:
        return True

    def scan_file(self, file_path: str) -> ScanResult:
        return ScanResult(file_hash=file_path, status=SecurityStatus.UNKNOWN)

    def scan_hash(self, file_hash: str) -> ScanResult:
        return ScanResult(file_hash=file_hash, status=SecurityStatus.CLEAN)

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        return dll_file

    def get_detailed_report(self, file_hash: str) -> dict[str, object]:
        return {"hash": file_hash}


class StubResolver(IDownloadURLResolver):
    def resolve_download_url(
        self,
        dll_name: str,
        architecture: Architecture,
    ) -> str:
        return f"https://example.com/{architecture.value}/{dll_name}"


class StubAssembler(DownloadApplicationAssembler):
    def __init__(self) -> None:
        self.http_client = StubHTTPClient()
        self.scanner = StubScanner()

    def build(
        self,
        settings: Settings,
        output_dir: str | None = None,
    ) -> DownloadApplication:
        repository = StubRepository()
        resolver = StubResolver()
        from dll_downloader.application.use_cases.download_dll import DownloadDLLUseCase

        return DownloadApplication(
            use_case=DownloadDLLUseCase(
                repository=repository,
                http_client=self.http_client,
                download_base_url=settings.download_base_url,
                scanner=self.scanner,
                resolver=resolver,
            ),
            http_client=self.http_client,
            scanner=self.scanner,
        )


@pytest.mark.unit
def test_build_download_application_accepts_injected_factory(tmp_path: Path) -> None:
    settings = Settings(download_directory=str(tmp_path))
    assembler = StubAssembler()

    application = build_download_application(
        settings,
        assembler=assembler,
        output_dir=str(tmp_path),
    )

    assert application.http_client is assembler.http_client
    assert application.scanner is assembler.scanner
    assert application.use_case is not None


@pytest.mark.unit
def test_build_default_download_application_uses_default_runtime(tmp_path: Path) -> None:
    settings = Settings(download_directory=str(tmp_path), virustotal_api_key=None)

    application = build_default_download_application(settings, output_dir=str(tmp_path))

    assert isinstance(application.http_client, RequestsHTTPClient)
    assert application.scanner is None
    assert application.use_case is not None
