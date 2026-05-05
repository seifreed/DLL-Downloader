"""CLI-focused orchestration helpers."""

import argparse
import logging
import traceback
from dataclasses import dataclass
from typing import Protocol

from ..application.use_cases.download_batch import (
    DownloadBatchRequest,
    DownloadBatchUseCase,
    snapshot_dll_names,
)
from ..application.use_cases.download_dll import DownloadDLLRequest, DownloadDLLResponse
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

logger = logging.getLogger(__name__)
_RUNTIME_CLOSE_ERROR_TYPES: tuple[type[Exception], ...] = (Exception,)


class SupportsClose(Protocol):
    def close(self) -> None:
        pass


class SupportsDownloadExecution(Protocol):
    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        pass


def _validate_cli_architecture(value: object) -> None:
    if not isinstance(value, Architecture):
        raise ValueError("architecture must be an Architecture")


def _validate_cli_bool(value: object, field_name: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")


def _validate_cli_output_dir(value: object) -> None:
    if value is not None and not isinstance(value, str):
        raise ValueError("output_dir must be a string or None")


@dataclass(frozen=True)
class CLIBatchDownloadCommand:
    dll_names: tuple[str, ...]
    architecture: Architecture
    scan_enabled: bool
    force_download: bool
    extract_archive: bool
    debug: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "dll_names", snapshot_dll_names(self.dll_names))
        _validate_cli_architecture(self.architecture)
        _validate_cli_bool(self.scan_enabled, "scan_enabled")
        _validate_cli_bool(self.force_download, "force_download")
        _validate_cli_bool(self.extract_archive, "extract_archive")
        _validate_cli_bool(self.debug, "debug")


@dataclass(frozen=True)
class CLIBatchDownloadResult:
    lines: tuple[str, ...]
    success_count: int
    failure_count: int


@dataclass(frozen=True)
class CLIRunResult:
    invocation: "CLIInvocation"
    session: CLISessionResult


@dataclass(frozen=True)
class CLIInvocation:
    dll_names: tuple[str, ...]
    architecture: Architecture
    scan_enabled: bool
    force_download: bool
    extract_archive: bool
    debug: bool
    output_dir: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "dll_names", snapshot_dll_names(self.dll_names))
        _validate_cli_architecture(self.architecture)
        _validate_cli_bool(self.scan_enabled, "scan_enabled")
        _validate_cli_bool(self.force_download, "force_download")
        _validate_cli_bool(self.extract_archive, "extract_archive")
        _validate_cli_bool(self.debug, "debug")
        _validate_cli_output_dir(self.output_dir)


class DownloadCLIService:
    """Translate CLI batch commands into application use case execution."""

    def __init__(
        self,
        item_use_case: SupportsDownloadExecution,
        presenter: BatchPresenter,
        is_structured: bool = False,
    ) -> None:
        self._batch_use_case = DownloadBatchUseCase(item_use_case)
        self._presenter = presenter
        self._is_structured = is_structured

    def run(self, command: CLIBatchDownloadCommand) -> CLIBatchDownloadResult:
        architecture_label = command.architecture.value
        batch_response = self._batch_use_case.execute(
            DownloadBatchRequest(
                dll_names=tuple(command.dll_names),
                architecture=command.architecture,
                scan_before_save=command.scan_enabled,
                force_download=command.force_download,
                extract_archive=command.extract_archive,
            )
        )

        rendered_lines = self._presenter.render_batch(
            batch_response, architecture_label
        )
        return CLIBatchDownloadResult(
            lines=tuple(rendered_lines),
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
                message=self._presenter.boundary_error(
                    str(exc),
                    failure_count=len(command.dll_names),
                ),
                traceback_text=traceback.format_exc() if command.debug else None,
                is_structured=self._is_structured,
            ),
        )

    def run_with_error_handling(
        self,
        command: CLIBatchDownloadCommand,
    ) -> CLICommandResult:
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
    try:
        result = run_command(command)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        return boundary_failure_factory(command, exc)

    return CLICommandResult(
        stdout_lines=list(result.lines),
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
    _close_runtime_resource(http_client, "HTTP client")
    if scanner is not None:
        _close_runtime_resource(scanner, "security scanner")


def _close_runtime_resource(resource: SupportsClose, label: str) -> None:
    try:
        resource.close()
    except _RUNTIME_CLOSE_ERROR_TYPES as exc:
        logger.warning("Failed to close %s: %s", label, exc)


class CLIApplicationService:
    """Own the lifecycle of a CLI download session."""

    def __init__(
        self,
        presenter: BatchPresenter,
        application_builder: "ApplicationBuilder",
        writer: OutputWriter | None = None,
        is_structured: bool = False,
    ) -> None:
        self._presenter = presenter
        self._application_builder = application_builder
        self._writer = writer or ConsoleOutputWriter()
        self._is_structured = is_structured

    @property
    def is_structured(self) -> bool:
        return self._is_structured

    def create_invocation(
        self,
        args: argparse.Namespace,
        parser: argparse.ArgumentParser,
        settings: Settings,
        read_dll_list: "DLLListReader",
    ) -> CLIInvocation:
        dll_names = resolve_dll_names(args, parser, read_dll_list)

        return CLIInvocation(
            dll_names=tuple(dll_names),
            architecture=parse_architecture(getattr(args, "arch", "x64")),
            scan_enabled=(
                not getattr(args, "no_scan", False)
                and settings.scan_before_save
                and bool(
                    settings.virustotal_api_key and settings.virustotal_api_key.strip()
                )
            ),
            force_download=getattr(args, "force", False),
            extract_archive=getattr(args, "extract", False),
            debug=getattr(args, "debug", False),
            output_dir=getattr(args, "output_dir", None),
        )

    def run(self, settings: Settings, invocation: CLIInvocation) -> CLISessionResult:
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
        invocation = self.create_invocation(args, parser, settings, read_dll_list)
        return CLIRunResult(
            invocation=invocation,
            session=self.run(settings, invocation),
        )

    def render_summary(self, result: CLIRunResult) -> str | None:
        if len(result.invocation.dll_names) <= 1:
            return None
        return self._presenter.summary_counts(
            result.session.success_count,
            result.session.failure_count,
        )

    def emit(self, result: CLICommandResult) -> None:
        emit_command_result(self._writer, result)

    def _run_application(
        self,
        application: DownloadApplication,
        invocation: CLIInvocation,
    ) -> CLISessionResult:
        service = DownloadCLIService(
            application.use_case,
            self._presenter,
            is_structured=self._is_structured,
        )
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
    def __call__(
        self,
        settings: Settings,
        output_dir: str | None = None,
    ) -> DownloadApplication:
        pass


class BatchCommandRunner(Protocol):
    def __call__(self, command: CLIBatchDownloadCommand) -> CLIBatchDownloadResult:
        pass


class BoundaryFailureFactory(Protocol):
    def __call__(
        self, command: CLIBatchDownloadCommand, exc: Exception
    ) -> CLICommandResult:
        pass
