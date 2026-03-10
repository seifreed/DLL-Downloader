"""
CLI format selection and boundary-output helpers.
"""

import argparse
from typing import cast

from .cli_contracts import BatchPresenter, OutputFormat
from .cli_output import CLIBoundaryFailure, CLICommandResult, CLISessionResult
from .cli_runner import CLIApplicationService
from .presenters.download_presenter import (
    DownloadBatchConsolePresenter,
    DownloadConsolePresenter,
)
from .presenters.structured_presenter import (
    DownloadBatchJSONPresenter,
    DownloadBatchSARIFPresenter,
)


def get_output_format(args: argparse.Namespace) -> OutputFormat:
    """Translate CLI flags into a stable output format enum."""
    if getattr(args, "json", False):
        return OutputFormat.JSON
    if getattr(args, "sarif", False):
        return OutputFormat.SARIF
    return OutputFormat.CONSOLE


def create_batch_presenter(output_format: OutputFormat) -> BatchPresenter:
    """Construct the presenter matching the selected output format."""
    if output_format == OutputFormat.JSON:
        return cast(BatchPresenter, DownloadBatchJSONPresenter())
    if output_format == OutputFormat.SARIF:
        return cast(BatchPresenter, DownloadBatchSARIFPresenter())
    return cast(
        BatchPresenter,
        DownloadBatchConsolePresenter(DownloadConsolePresenter()),
    )


def create_cli_service(output_format: OutputFormat) -> CLIApplicationService:
    """Create a CLI application service configured for one output format."""
    from ..runtime import create_application

    return CLIApplicationService(create_batch_presenter(output_format), create_application)


def emit_cli_input_error(
    service: CLIApplicationService,
    message: str,
) -> None:
    """Emit a normalized CLI boundary error for invalid input."""
    service.emit(
        CLICommandResult(
            stdout_lines=[],
            session=CLISessionResult(success_count=0, failure_count=1, exit_code=1),
            boundary_failure=CLIBoundaryFailure(message=message),
        )
    )
