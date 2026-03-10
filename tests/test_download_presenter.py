import json

import pytest

from dll_downloader.application.use_cases.download_batch import (
    DownloadBatchItem,
    DownloadBatchResponse,
)
from dll_downloader.application.use_cases.download_dll import DownloadDLLResponse
from dll_downloader.domain.entities.dll_file import Architecture, DLLFile
from dll_downloader.interfaces.presenters.download_presenter import (
    DownloadBatchConsolePresenter,
    DownloadConsolePresenter,
)
from dll_downloader.interfaces.presenters.structured_presenter import (
    STRUCTURED_OUTPUT_VERSION,
    DownloadBatchJSONPresenter,
    DownloadBatchSARIFPresenter,
)


@pytest.mark.unit
def test_download_console_presenter_handles_cached_without_file() -> None:
    presenter = DownloadConsolePresenter()

    output = presenter.format(
        DownloadDLLResponse(success=True, was_cached=True, dll_file=None),
        "ghost.dll",
    )

    assert output == "[FAILED] ghost.dll: cached file info missing"


@pytest.mark.unit
def test_download_batch_presenter_summary_and_boundary_error() -> None:
    presenter = DownloadBatchConsolePresenter()

    summary = presenter.summary(
        DownloadBatchResponse(
            items=[
                DownloadBatchItem(
                    dll_name="a.dll",
                    response=DownloadDLLResponse(success=True),
                ),
                DownloadBatchItem(
                    dll_name="b.dll",
                    response=DownloadDLLResponse(success=False, error_message="x"),
                ),
            ]
        )
    )

    assert summary == "\nSummary: 1 succeeded, 1 failed"
    assert presenter.boundary_error("boom") == "[ERROR] Batch download failed: boom"


@pytest.mark.unit
def test_download_batch_presenter_renders_item_list() -> None:
    presenter = DownloadBatchConsolePresenter()
    dll_file = DLLFile(
        name="a.dll",
        architecture=Architecture.X64,
        file_path="/tmp/a.dll",
    )

    lines = presenter.render_batch(
        DownloadBatchResponse(
            items=[
                DownloadBatchItem(
                    dll_name="a.dll",
                    response=DownloadDLLResponse(success=True, dll_file=dll_file),
                )
            ]
        ),
        "x64",
    )

    assert lines[0] == "\nSearching and downloading: a.dll (x64)"
    assert "[OK] Downloaded: a.dll" in lines[1]


@pytest.mark.unit
def test_download_batch_json_presenter_renders_machine_readable_payload() -> None:
    presenter = DownloadBatchJSONPresenter()
    dll_file = DLLFile(
        name="a.dll",
        architecture=Architecture.X64,
        file_path="/tmp/a.dll",
    )

    payload_text = presenter.render_batch(
        DownloadBatchResponse(
            items=[
                DownloadBatchItem(
                    dll_name="a.dll",
                    response=DownloadDLLResponse(success=True, dll_file=dll_file),
                )
            ]
        ),
        "x64",
    )[0]
    payload = json.loads(payload_text)

    assert payload["format"] == "json"
    assert payload["schema_version"] == STRUCTURED_OUTPUT_VERSION
    assert payload["architecture"] == "x64"
    assert payload["success_count"] == 1
    assert payload["items"][0]["dll_file"]["file_path"] == "/tmp/a.dll"
    assert presenter.summary_counts(1, 0) is None


@pytest.mark.unit
def test_download_batch_json_presenter_boundary_error_is_machine_readable() -> None:
    presenter = DownloadBatchJSONPresenter()

    payload = json.loads(presenter.boundary_error("boom"))

    assert payload["format"] == "json"
    assert payload["schema_version"] == STRUCTURED_OUTPUT_VERSION
    assert payload["error"]["message"] == "boom"


@pytest.mark.unit
def test_download_batch_sarif_presenter_renders_valid_log() -> None:
    presenter = DownloadBatchSARIFPresenter()

    payload_text = presenter.render_batch(
        DownloadBatchResponse(
            items=[
                DownloadBatchItem(
                    dll_name="bad.dll",
                    response=DownloadDLLResponse(
                        success=False,
                        error_message="boom",
                    ),
                )
            ]
        ),
        "x64",
    )[0]
    payload = json.loads(payload_text)
    run = payload["runs"][0]

    assert payload["version"] == "2.1.0"
    assert run["properties"]["structuredOutputVersion"] == STRUCTURED_OUTPUT_VERSION
    assert run["tool"]["driver"]["name"] == "dll_downloader"
    assert run["results"][0]["ruleId"] == "dll-downloader/download-failed"
    assert run["results"][0]["message"]["text"] == "boom"
    assert presenter.summary_counts(0, 1) is None


@pytest.mark.unit
def test_download_batch_sarif_presenter_renders_boundary_error_log() -> None:
    presenter = DownloadBatchSARIFPresenter()

    payload = json.loads(presenter.boundary_error("bad input"))

    assert payload["runs"][0]["results"][0]["ruleId"] == (
        "dll-downloader/boundary-failure"
    )
    assert payload["runs"][0]["properties"]["structuredOutputVersion"] == (
        STRUCTURED_OUTPUT_VERSION
    )
    assert payload["runs"][0]["results"][0]["message"]["text"] == "bad input"


@pytest.mark.unit
def test_download_batch_sarif_presenter_emits_warning_and_locations() -> None:
    presenter = DownloadBatchSARIFPresenter()
    dll_file = DLLFile(
        name="warn.dll",
        architecture=Architecture.X64,
        file_path="/tmp/warn.dll",
    )

    payload = json.loads(
        presenter.render_batch(
            DownloadBatchResponse(
                items=[
                    DownloadBatchItem(
                        dll_name="warn.dll",
                        response=DownloadDLLResponse(
                            success=True,
                            dll_file=dll_file,
                            security_warning="careful",
                        ),
                    )
                ]
            ),
            "x64",
        )[0]
    )
    results = payload["runs"][0]["results"]

    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "/tmp/warn.dll"
    )
    assert results[1]["ruleId"] == "dll-downloader/security-warning"
    assert results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "/tmp/warn.dll"
    )


@pytest.mark.unit
def test_download_batch_sarif_presenter_supports_missing_file_metadata() -> None:
    presenter = DownloadBatchSARIFPresenter()

    payload = json.loads(
        presenter.render_batch(
            DownloadBatchResponse(
                items=[
                    DownloadBatchItem(
                        dll_name="ok.dll",
                        response=DownloadDLLResponse(success=True),
                    )
                ]
            ),
            "x64",
        )[0]
    )

    result = payload["runs"][0]["results"][0]
    assert result["ruleId"] == "dll-downloader/download-succeeded"
    assert "locations" not in result


@pytest.mark.unit
def test_download_batch_sarif_presenter_warning_without_file_path() -> None:
    presenter = DownloadBatchSARIFPresenter()
    dll_file = DLLFile(
        name="warn.dll",
        architecture=Architecture.X64,
        file_path=None,
    )

    payload = json.loads(
        presenter.render_batch(
            DownloadBatchResponse(
                items=[
                    DownloadBatchItem(
                        dll_name="warn.dll",
                        response=DownloadDLLResponse(
                            success=True,
                            dll_file=dll_file,
                            security_warning="careful",
                        ),
                    )
                ]
            ),
            "x64",
        )[0]
    )

    warning_result = payload["runs"][0]["results"][1]
    assert warning_result["ruleId"] == "dll-downloader/security-warning"
    assert "locations" not in warning_result
