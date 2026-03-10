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
