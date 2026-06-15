"""Tests for the structured (JSON/SARIF) presenter helpers."""

from datetime import UTC, datetime

import pytest

from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.interfaces.presenters.structured_presenter import (
    _path_to_uri,
    _serialize_datetime,
    _serialize_dll_file,
    _windows_path_to_uri,
)


@pytest.mark.unit
def test_path_to_uri_returns_none_for_empty_or_none() -> None:
    assert _path_to_uri(None) is None
    assert _path_to_uri("") is None


@pytest.mark.unit
def test_path_to_uri_relative_path_yields_relative_reference() -> None:
    assert _path_to_uri("rel/dir/file.dll") == "rel/dir/file.dll"


@pytest.mark.unit
def test_path_to_uri_absolute_posix_path() -> None:
    assert _path_to_uri("/tmp/x.dll") == "file:///tmp/x.dll"


@pytest.mark.unit
def test_windows_unc_path_with_too_few_parts_returns_none() -> None:
    assert _windows_path_to_uri("\\\\host") is None


@pytest.mark.unit
def test_windows_paths_convert_to_file_uris() -> None:
    assert _path_to_uri("\\\\host\\share\\x.dll") == "file://host/share/x.dll"
    assert _path_to_uri("C:\\Windows\\x.dll") == "file:///C:/Windows/x.dll"


@pytest.mark.unit
def test_serialize_datetime_none_and_naive() -> None:
    assert _serialize_datetime(None) is None
    naive = datetime(2026, 1, 2, 3, 4, 5)  # noqa: DTZ001 - testing naive handling
    assert _serialize_datetime(naive) == "2026-01-02T03:04:05+00:00"


@pytest.mark.unit
def test_serialize_dll_file_includes_all_optional_fields() -> None:
    dll = DLLFile(
        name="x.dll",
        version="1.2.3",
        architecture=Architecture.X64,
        file_hash="a" * 64,
        file_path="/tmp/x.dll",
        download_url="https://example/x.zip",
        file_size=10,
        security_status=SecurityStatus.CLEAN,
        vt_detection_ratio="0/70",
        vt_scan_date=datetime(2026, 1, 1, tzinfo=UTC),
    )

    result = _serialize_dll_file(dll)

    assert result is not None
    assert result["version"] == "1.2.3"
    assert result["download_url"] == "https://example/x.zip"
    assert result["vt_detection_ratio"] == "0/70"
    assert result["vt_scan_date"] == "2026-01-01T00:00:00+00:00"
    assert "created_at" in result


@pytest.mark.unit
def test_serialize_dll_file_omits_created_at_when_absent() -> None:
    dll = DLLFile(name="x.dll", architecture=Architecture.X64)
    object.__setattr__(dll, "created_at", None)

    result = _serialize_dll_file(dll)

    assert result is not None
    assert "created_at" not in result


@pytest.mark.unit
def test_serialize_dll_file_none_returns_none() -> None:
    assert _serialize_dll_file(None) is None
