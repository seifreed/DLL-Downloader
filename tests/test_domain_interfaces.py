import pytest

from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.domain.repositories.dll_repository import IDLLRepository
from dll_downloader.domain.services.download_resolver import IDownloadURLResolver
from dll_downloader.domain.services.security_scanner import ISecurityScanner, ScanResult


class DummyRepository(IDLLRepository):
    def save(self, dll_file: DLLFile, content: bytes) -> DLLFile:
        return IDLLRepository.save(self, dll_file, content)

    def find_by_name(self, name: str, architecture=None):
        return IDLLRepository.find_by_name(self, name, architecture)

    def find_by_hash(self, file_hash: str):
        return IDLLRepository.find_by_hash(self, file_hash)

    def list_all(self):
        return IDLLRepository.list_all(self)

    def delete(self, dll_file: DLLFile) -> bool:
        return IDLLRepository.delete(self, dll_file)

    def exists(self, name: str, architecture=None) -> bool:
        return IDLLRepository.exists(self, name, architecture)


class DummyScanner(ISecurityScanner):
    def scan_file(self, file_path: str) -> ScanResult:
        return ISecurityScanner.scan_file(self, file_path)

    def scan_hash(self, file_hash: str) -> ScanResult:
        return ISecurityScanner.scan_hash(self, file_hash)

    def scan_dll(self, dll_file: DLLFile) -> DLLFile:
        return ISecurityScanner.scan_dll(self, dll_file)

    def get_detailed_report(self, file_hash: str) -> dict:
        return ISecurityScanner.get_detailed_report(self, file_hash)

    @property
    def is_available(self) -> bool:
        return ISecurityScanner.is_available.fget(self)


@pytest.mark.unit
def test_idllrepository_pass_throughs() -> None:
    repo = DummyRepository()
    dll = DLLFile(name="a.dll")

    assert repo.save(dll, b"data") is None
    assert repo.find_by_name("a") is None
    assert repo.find_by_hash("hash") is None
    assert repo.list_all() is None
    assert repo.delete(dll) is None
    assert repo.exists("a") is None


@pytest.mark.unit
def test_scan_result_detection_count_variants() -> None:
    result = ScanResult(file_hash="x", status=SecurityStatus.CLEAN, detection_ratio="5/70")
    assert result.detection_count == 5

    bad_ratio = ScanResult(file_hash="x", status=SecurityStatus.CLEAN, detection_ratio="bad")
    assert bad_ratio.detection_count == 0

    from_detections = ScanResult(file_hash="x", status=SecurityStatus.CLEAN, detections={"a": "X", "b": ""})
    assert from_detections.detection_count == 1


@pytest.mark.unit
def test_scan_result_is_clean_property() -> None:
    clean = ScanResult(file_hash="x", status=SecurityStatus.CLEAN)
    dirty = ScanResult(file_hash="x", status=SecurityStatus.MALICIOUS)
    assert clean.is_clean is True
    assert dirty.is_clean is False


@pytest.mark.unit
def test_isecurityscanner_pass_throughs() -> None:
    scanner = DummyScanner()
    dll = DLLFile(name="a.dll")

    assert scanner.scan_file("path") is None
    assert scanner.scan_hash("hash") is None
    assert scanner.scan_dll(dll) is None
    assert scanner.get_detailed_report("hash") is None
    assert scanner.is_available is None


@pytest.mark.unit
def test_download_resolver_protocol_body() -> None:
    assert IDownloadURLResolver.resolve_download_url(None, "a.dll", Architecture.X64) is None
