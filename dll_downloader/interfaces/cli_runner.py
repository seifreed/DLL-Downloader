"""
CLI-focused orchestration helpers.
"""

import argparse
import traceback
from dataclasses import dataclass
from typing import Protocol

from ..application.use_cases.download_batch import (
    DownloadBatchRequest,
    DownloadBatchUseCase,
)
from ..application.use_cases.download_dll import (
    DownloadDLLRequest,
    DownloadDLLResponse,
)
from ..bootstrap import DownloadApplication
from ..domain.entities.dll_file import Architecture
from ..infrastructure.config.settings import Settings
from .cli_contracts import (
    BatchPresenter,
    DLLListReader,
    parse_architecture,
    resolve_dll_names,
)
from .cli_output import (
    CLIBoundaryFailure,
    CLICommandResult,
    CLISessionResult,
    ConsoleOutputWriter,
    OutputWriter,
    emit_command_result,
)


class SupportsClose(Protocol):
    """Minimal closeable contract for runtime resources."""

    def close(self) -> None:
        """Release underlying resources."""


class SupportsDownloadExecution(Protocol):
    """Minimal single-item download use case contract for CLI orchestration."""

    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        """Execute a single download request."""


@dataclass(frozen=True)
class CLIBatchDownloadCommand:
    """Input data required to process a CLI batch download."""

    dll_names: list[str]
    architecture: Architecture
    scan_enabled: bool
    force_download: bool
    extract_archive: bool
    debug: bool = False


@dataclass(frozen=True)
class CLIBatchDownloadResult:
    """Summary values returned to the CLI entrypoint."""

    lines: list[str]
    success_count: int
    failure_count: int


@dataclass(frozen=True)
class CLIRunResult:
    """CLI session result plus normalized invocation metadata."""

    invocation: "CLIInvocation"
    session: CLISessionResult


@dataclass(frozen=True)
class CLIInvocation:
    """Fully normalized CLI invocation after argument parsing."""

    dll_names: list[str]
    architecture: Architecture
    scan_enabled: bool
    force_download: bool
    extract_archive: bool
    debug: bool
    output_dir: str | None = None


class DownloadCLIService:
    """Translate CLI batch commands into application use case execution."""

    def __init__(
        self,
        item_use_case: SupportsDownloadExecution,
        presenter: BatchPresenter,
    ) -> None:
        self._batch_use_case = DownloadBatchUseCase(item_use_case)
        self._presenter = presenter

    def run(self, command: CLIBatchDownloadCommand) -> CLIBatchDownloadResult:
        architecture_label = (
            "x86" if command.architecture == Architecture.X86 else "x64"
        )
        batch_response = self._batch_use_case.execute(
            DownloadBatchRequest(
                dll_names=command.dll_names,
                architecture=command.architecture,
                scan_before_save=command.scan_enabled,
                force_download=command.force_download,
                extract_archive=command.extract_archive,
            )
        )

        return CLIBatchDownloadResult(
            lines=self._presenter.render_batch(batch_response, architecture_label),
            success_count=batch_response.success_count,
            failure_count=batch_response.failure_count,
        )

    def _boundary_failure(
        self,
        command: CLIBatchDownloadCommand,
        exc: Exception,
    ) -> CLICommandResult:
        return CLICommandResult(
            stdout_lines=[],
            session=CLISessionResult(
                success_count=0,
                failure_count=len(command.dll_names),
                exit_code=1,
            ),
            boundary_failure=CLIBoundaryFailure(
                message=self._presenter.boundary_error(str(exc)),
                traceback_text=traceback.format_exc() if command.debug else None,
            ),
        )

    def run_with_error_handling(
        self,
        command: CLIBatchDownloadCommand,
    ) -> CLICommandResult:
        """Execute a CLI batch command and normalize boundary failures."""
        return execute_boundary_command(
            command=command,
            run_command=self.run,
            boundary_failure_factory=self._boundary_failure,
        )


def execute_boundary_command(
    command: CLIBatchDownloadCommand,
    run_command: "BatchCommandRunner",
    boundary_failure_factory: "BoundaryFailureFactory",
) -> CLICommandResult:
    """
    Execute one outermost CLI boundary command.

    The broad catch lives here intentionally: this is the final translation
    point between runtime failures and user-facing CLI output.
    """
    try:
        result = run_command(command)
    except Exception as exc:
        return boundary_failure_factory(command, exc)

    return CLICommandResult(
        stdout_lines=result.lines,
        session=CLISessionResult(
            success_count=result.success_count,
            failure_count=result.failure_count,
            exit_code=0 if result.failure_count == 0 else 1,
        ),
    )


def cleanup_runtime_resources(
    http_client: SupportsClose,
    scanner: SupportsClose | None,
) -> None:
    """Close runtime adapters created by the composition root."""
    http_client.close()
    if scanner:
        scanner.close()


class CLIApplicationService:
    """Own the lifecycle of a CLI download session."""

    def __init__(
        self,
        presenter: BatchPresenter,
        application_builder: "ApplicationBuilder",
        writer: OutputWriter | None = None,
    ) -> None:
        self._presenter = presenter
        self._application_builder = application_builder
        self._writer = writer or ConsoleOutputWriter()

    def create_invocation(
        self,
        args: argparse.Namespace,
        parser: argparse.ArgumentParser,
        settings: Settings,
        read_dll_list: "DLLListReader",
    ) -> CLIInvocation:
        """Normalize raw CLI arguments into a validated invocation."""
        dll_names = resolve_dll_names(args, parser, read_dll_list)

        return CLIInvocation(
            dll_names=dll_names,
            architecture=parse_architecture(getattr(args, "arch", "x64")),
            scan_enabled=(
                not getattr(args, "no_scan", False)
                and settings.virustotal_api_key is not None
            ),
            force_download=getattr(args, "force", False),
            extract_archive=getattr(args, "extract", False),
            debug=getattr(args, "debug", False),
            output_dir=getattr(args, "output_dir", None),
        )

    def run(
        self,
        settings: Settings,
        invocation: CLIInvocation,
    ) -> CLISessionResult:
        application = self._application_builder(
            settings,
            output_dir=invocation.output_dir,
        )
        return self._run_application(application, invocation)

    def run_from_args(
        self,
        args: argparse.Namespace,
        parser: argparse.ArgumentParser,
        settings: Settings,
        read_dll_list: "DLLListReader",
    ) -> CLIRunResult:
        """Normalize args and execute one CLI session."""
        invocation = self.create_invocation(args, parser, settings, read_dll_list)
        return CLIRunResult(
            invocation=invocation,
            session=self.run(settings, invocation),
        )

    def render_summary(self, result: CLIRunResult) -> str | None:
        """Render summary text only for batch sessions."""
        if len(result.invocation.dll_names) <= 1:
            return None
        return self._presenter.summary_counts(
            result.session.success_count,
            result.session.failure_count,
        )

    def emit(self, result: CLICommandResult) -> None:
        """Write rendered command output to the configured writer."""
        emit_command_result(self._writer, result)

    def _run_application(
        self,
        application: DownloadApplication,
        invocation: CLIInvocation,
    ) -> CLISessionResult:
        service = DownloadCLIService(application.use_case, self._presenter)
        try:
            result = service.run_with_error_handling(
                CLIBatchDownloadCommand(
                    dll_names=invocation.dll_names,
                    architecture=invocation.architecture,
                    scan_enabled=invocation.scan_enabled,
                    force_download=invocation.force_download,
                    extract_archive=invocation.extract_archive,
                    debug=invocation.debug,
                )
            )
            self.emit(result)
            return result.session
        finally:
            cleanup_runtime_resources(application.http_client, application.scanner)


class ApplicationBuilder(Protocol):
    """Build a runtime application graph for one CLI session."""

    def __call__(
        self,
        settings: Settings,
        output_dir: str | None = None,
    ) -> DownloadApplication:
        """Return the assembled runtime application."""


class BatchCommandRunner(Protocol):
    """Run one normalized batch command."""

    def __call__(
        self,
        command: CLIBatchDownloadCommand,
    ) -> CLIBatchDownloadResult:
        """Return the rendered batch result."""


class BoundaryFailureFactory(Protocol):
    """Build a normalized CLI failure result from an unexpected exception."""

    def __call__(
        self,
        command: CLIBatchDownloadCommand,
        exc: Exception,
    ) -> CLICommandResult:
        """Translate an unexpected boundary exception."""
