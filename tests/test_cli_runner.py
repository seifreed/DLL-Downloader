from typing import cast

import pytest

from dll_downloader.application.use_cases.download_dll import (
    DownloadDLLRequest,
    DownloadDLLResponse,
    DownloadDLLUseCase,
)
from dll_downloader.bootstrap import (
    CloseableHTTPClient,
    CloseableSecurityScanner,
    DownloadApplication,
)
from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.domain.services import HTTPFileInfo, ScanResult
from dll_downloader.infrastructure.config.settings import Settings
from dll_downloader.interfaces.cli_output import (
    CLIBoundaryFailure,
    CLICommandResult,
    CLISessionResult,
)
from dll_downloader.interfaces.cli_runner import (
    CLIApplicationService,
    CLIBatchDownloadCommand,
    CLIInvocation,
    CLIRunResult,
    DownloadCLIService,
    cleanup_runtime_resources,
)
from dll_downloader.interfaces.presenters.structured_presenter import (
    DownloadBatchSARIFPresenter,
)


class RecordingWriter:
    def __init__(self) -> None:
        self.stdout: list[str] = []
        self.stderr: list[str] = []

    def write(self, text: str, *, error: bool = False) -> None:
        if error:
            self.stderr.append(text)
        else:
            self.stdout.append(text)


class StubPresenter:
    def render_batch(self, response: object, architecture_label: str) -> list[str]:
        return [f"batch:{architecture_label}"]

    def summary_counts(self, success_count: int, failure_count: int) -> str:
        return f"summary:{success_count}:{failure_count}"

    def boundary_error(self, error_message: str, failure_count: int = 1) -> str:
        return f"error:{error_message}"


class SuccessfulUseCase:
    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        return DownloadDLLResponse(success=True)


class FailingUseCase:
    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        raise RuntimeError("boom")


class HTTPClientStub:
    def __init__(self) -> None:
        self.closed = False

    def download(self, url: str, headers: dict[str, str] | None = None) -> bytes:
        return b"data"

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> str:
        return "text"

    def get_file_info(self, url: str) -> HTTPFileInfo:
        return {
            "content_type": "application/octet-stream",
            "content_length": 4,
            "last_modified": None,
            "etag": None,
            "accept_ranges": False,
        }

    def close(self) -> None:
        self.closed = True


class ScannerStub:
    def __init__(self) -> None:
        self.closed = False

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

    def close(self) -> None:
        self.closed = True


def _application_with_use_case(use_case: SuccessfulUseCase) -> DownloadApplication:
    http_client = HTTPClientStub()
    scanner = ScannerStub()
    return DownloadApplication(
        use_case=cast(DownloadDLLUseCase, use_case),
        http_client=cast(CloseableHTTPClient, http_client),
        scanner=cast(CloseableSecurityScanner, scanner),
    )


@pytest.mark.unit
def test_download_cli_service_returns_rendered_lines() -> None:
    service = DownloadCLIService(SuccessfulUseCase(), StubPresenter())

    result = service.run(
        CLIBatchDownloadCommand(
            dll_names=["test.dll"],
            architecture=Architecture.X64,
            scan_enabled=False,
            force_download=False,
            extract_archive=False,
        )
    )

    assert result.lines == ["batch:x64"]
    assert result.success_count == 1
    assert result.failure_count == 0


@pytest.mark.unit
def test_download_cli_service_handles_unexpected_exception_as_failure() -> None:
    service = DownloadCLIService(FailingUseCase(), StubPresenter())

    result = service.run_with_error_handling(
        CLIBatchDownloadCommand(
            dll_names=["bad.dll"],
            architecture=Architecture.X64,
            scan_enabled=False,
            force_download=False,
            extract_archive=False,
            debug=True,
        )
    )

    assert result.session.exit_code == 1
    assert result.session.failure_count == 1


@pytest.mark.unit
def test_download_cli_service_handles_unexpected_exception_in_sarif_batch() -> None:
    service = DownloadCLIService(FailingUseCase(), DownloadBatchSARIFPresenter())

    result = service.run_with_error_handling(
        CLIBatchDownloadCommand(
            dll_names=["good.dll", "bad.dll", "other.dll"],
            architecture=Architecture.X64,
            scan_enabled=False,
            force_download=False,
            extract_archive=False,
        )
    )

    assert result.session.failure_count == 3
    assert result.boundary_failure is None


@pytest.mark.unit
def test_cli_application_service_emits_stdout_and_stderr() -> None:
    writer = RecordingWriter()
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=writer,
    )

    service.emit(
        CLICommandResult(
            stdout_lines=["one", "two"],
            session=CLISessionResult(success_count=1, failure_count=0, exit_code=0),
            boundary_failure=CLIBoundaryFailure(
                message="problem",
                traceback_text="traceback",
            ),
        )
    )

    assert writer.stdout == ["one", "two"]
    assert writer.stderr == ["problem", "traceback"]


@pytest.mark.unit
def test_cli_application_service_run_closes_runtime_resources() -> None:
    writer = RecordingWriter()
    http_client = HTTPClientStub()
    scanner = ScannerStub()

    def build_application(
        settings: Settings,
        output_dir: str | None = None,
    ) -> DownloadApplication:
        return DownloadApplication(
            use_case=cast(DownloadDLLUseCase, SuccessfulUseCase()),
            http_client=cast(CloseableHTTPClient, http_client),
            scanner=cast(CloseableSecurityScanner, scanner),
        )

    service = CLIApplicationService(StubPresenter(), build_application, writer=writer)

    result = service.run(
        Settings(),
        CLIInvocation(
            dll_names=["a.dll"],
            architecture=Architecture.X64,
            scan_enabled=False,
            force_download=False,
            extract_archive=False,
            debug=False,
        ),
    )

    assert result.exit_code == 0
    assert http_client.closed is True
    assert scanner.closed is True
    assert writer.stdout == ["batch:x64"]


@pytest.mark.unit
def test_cli_application_service_render_summary_batch_only() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )

    batch_summary = service.render_summary(
        CLIRunResult(
            invocation=CLIInvocation(
                dll_names=["a.dll", "b.dll"],
                architecture=Architecture.X64,
                scan_enabled=False,
                force_download=False,
                extract_archive=False,
                debug=False,
            ),
            session=CLISessionResult(success_count=2, failure_count=0, exit_code=0),
        )
    )
    single_summary = service.render_summary(
        CLIRunResult(
            invocation=CLIInvocation(
                dll_names=["a.dll"],
                architecture=Architecture.X64,
                scan_enabled=False,
                force_download=False,
                extract_archive=False,
                debug=False,
            ),
            session=CLISessionResult(success_count=1, failure_count=0, exit_code=0),
        )
    )

    assert batch_summary == "summary:2:0"
    assert single_summary is None


@pytest.mark.unit
def test_cleanup_runtime_resources_accepts_missing_scanner() -> None:
    http_client = HTTPClientStub()

    cleanup_runtime_resources(http_client, None)

    assert http_client.closed is True


@pytest.mark.unit
def test_cleanup_runtime_resources_closes_scanner_after_http_close_failure() -> None:
    class FailingHTTPClient(HTTPClientStub):
        def close(self) -> None:
            self.closed = True
            raise OSError("http close failed")

    http_client = FailingHTTPClient()
    scanner = ScannerStub()

    cleanup_runtime_resources(http_client, scanner)

    assert http_client.closed is True
    assert scanner.closed is True


@pytest.mark.unit
def test_cleanup_runtime_resources_closes_scanner_after_value_error() -> None:
    class FailingHTTPClient(HTTPClientStub):
        def close(self) -> None:
            self.closed = True
            raise ValueError("http close failed")

    http_client = FailingHTTPClient()
    scanner = ScannerStub()

    cleanup_runtime_resources(http_client, scanner)

    assert http_client.closed is True
    assert scanner.closed is True


@pytest.mark.unit
def test_cleanup_runtime_resources_closes_scanner_after_generic_exception() -> None:
    class FailingHTTPClient(HTTPClientStub):
        def close(self) -> None:
            self.closed = True
            raise Exception("http close failed")

    http_client = FailingHTTPClient()
    scanner = ScannerStub()

    cleanup_runtime_resources(http_client, scanner)

    assert http_client.closed is True
    assert scanner.closed is True


@pytest.mark.unit
def test_cleanup_runtime_resources_suppresses_scanner_close_failure() -> None:
    class FailingScanner(ScannerStub):
        def close(self) -> None:
            self.closed = True
            raise RuntimeError("scanner close failed")

    http_client = HTTPClientStub()
    scanner = FailingScanner()

    cleanup_runtime_resources(http_client, scanner)

    assert http_client.closed is True
    assert scanner.closed is True


@pytest.mark.unit
def test_cli_application_service_create_invocation_uses_settings_and_args() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )
    args = type(
        "Args",
        (),
        {
            "dll_name": "kernel32",
            "file": None,
            "arch": "x86",
            "no_scan": True,
            "force": True,
            "extract": True,
            "debug": True,
            "output_dir": "/tmp/out",
        },
    )()

    invocation = service.create_invocation(
        args,
        __import__("argparse").ArgumentParser(),
        Settings(virustotal_api_key="key"),
        lambda path: ["ignored.dll"],
    )

    assert invocation is not None
    assert invocation.dll_names == ["kernel32.dll"]
    assert invocation.architecture == Architecture.X86
    assert invocation.scan_enabled is False
    assert invocation.force_download is True
    assert invocation.extract_archive is True
    assert invocation.debug is True
    assert invocation.output_dir == "/tmp/out"


@pytest.mark.unit
def test_cli_application_service_create_invocation_honors_scan_setting() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )
    args = type(
        "Args",
        (),
        {
            "dll_name": "kernel32",
            "file": None,
            "arch": "x64",
            "no_scan": False,
            "force": False,
            "extract": False,
            "debug": False,
            "output_dir": None,
        },
    )()

    invocation = service.create_invocation(
        args,
        __import__("argparse").ArgumentParser(),
        Settings(virustotal_api_key="key", scan_before_save=False),
        lambda path: ["ignored.dll"],
    )

    assert invocation.scan_enabled is False


@pytest.mark.unit
def test_cli_application_service_create_invocation_ignores_blank_api_key() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )
    args = type(
        "Args",
        (),
        {
            "dll_name": "kernel32",
            "file": None,
            "arch": "x64",
            "no_scan": False,
            "force": False,
            "extract": False,
            "debug": False,
            "output_dir": None,
        },
    )()

    invocation = service.create_invocation(
        args,
        __import__("argparse").ArgumentParser(),
        Settings(virustotal_api_key=""),
        lambda path: ["ignored.dll"],
    )

    assert invocation.scan_enabled is False


@pytest.mark.unit
def test_cli_application_service_run_from_args_raises_on_invalid_input() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )
    parser = __import__("argparse").ArgumentParser()
    args = type("Args", (), {"dll_name": None, "file": None})()

    with pytest.raises(ValueError, match="Please provide a DLL name or use --file"):
        service.run_from_args(args, parser, Settings(), lambda path: [])


@pytest.mark.unit
def test_cli_application_service_create_invocation_rejects_unsafe_name() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )
    args = type(
        "Args",
        (),
        {
            "dll_name": "../evil",
            "file": None,
            "arch": "x64",
            "no_scan": False,
            "force": False,
            "extract": False,
            "debug": False,
            "output_dir": None,
        },
    )()

    with pytest.raises(ValueError, match="DLL name"):
        service.create_invocation(args, __import__("argparse").ArgumentParser(), Settings(), lambda path: [])


@pytest.mark.unit
def test_cli_application_service_run_from_args_returns_result_on_success() -> None:
    service = CLIApplicationService(
        StubPresenter(),
        lambda settings, output_dir=None: _application_with_use_case(SuccessfulUseCase()),
        writer=RecordingWriter(),
    )
    parser = __import__("argparse").ArgumentParser()
    args = type(
        "Args",
        (),
        {
            "dll_name": "a.dll",
            "file": None,
            "arch": "x64",
            "no_scan": False,
            "force": False,
            "extract": False,
            "debug": False,
            "output_dir": None,
        },
    )()

    result = service.run_from_args(args, parser, Settings(), lambda path: [])

    assert result is not None
    assert result.invocation.dll_names == ["a.dll"]
    assert result.session.exit_code == 0
