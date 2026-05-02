"""
Explicit default-runtime helpers for programmatic use.
"""

import contextlib
from typing import TYPE_CHECKING

from .api import Settings
from .bootstrap import (
    CloseableHTTPClient,
    CloseableSecurityScanner,
    DownloadApplication,
)
from .domain.entities import Architecture

if TYPE_CHECKING:
    from .interfaces.cli_output import ConsoleOutputWriter
    from .interfaces.cli_runner import DownloadCLIService, SupportsDownloadExecution


def _create_batch_cli_service(
    use_case: "SupportsDownloadExecution",
) -> "DownloadCLIService":
    from .interfaces.cli_runner import DownloadCLIService
    from .interfaces.presenters.download_presenter import (
        DownloadBatchConsolePresenter,
        DownloadConsolePresenter,
    )

    return DownloadCLIService(
        use_case,
        DownloadBatchConsolePresenter(DownloadConsolePresenter()),
    )


def _create_output_writer() -> "ConsoleOutputWriter":
    from .interfaces.cli_output import ConsoleOutputWriter

    return ConsoleOutputWriter()


def load_settings() -> Settings:
    """Load the default runtime settings from external configuration sources."""
    from .infrastructure.config.loader import SettingsLoader

    return SettingsLoader.load()


def create_application(
    settings: Settings,
    output_dir: str | None = None,
) -> DownloadApplication:
    """Create the default assembled runtime application graph."""
    from .infrastructure.composition import build_default_download_application

    return build_default_download_application(settings, output_dir=output_dir)


def create_dependencies(
    settings: Settings,
    output_dir: str | None = None,
) -> tuple[
    "SupportsDownloadExecution",
    CloseableHTTPClient,
    CloseableSecurityScanner | None,
]:
    """Return the wired dependencies for programmatic integration."""
    application = create_application(settings, output_dir=output_dir)
    return application.use_case, application.http_client, application.scanner


def process_downloads(
    use_case: "SupportsDownloadExecution",
    dll_names: list[str],
    architecture: Architecture,
    scan_enabled: bool,
    force_download: bool,
    extract_archive: bool,
    debug: bool = False,
    *,
    http_client: "CloseableHTTPClient | None" = None,
    scanner: "CloseableSecurityScanner | None" = None,
) -> tuple[int, int]:
    """Execute a batch download outside the CLI entrypoint."""
    from .interfaces.cli_output import (
        emit_command_result,
    )
    from .interfaces.cli_runner import CLIBatchDownloadCommand

    runner = _create_batch_cli_service(use_case)
    result = runner.run_with_error_handling(
        CLIBatchDownloadCommand(
            dll_names=dll_names,
            architecture=architecture,
            scan_enabled=scan_enabled,
            force_download=force_download,
            extract_archive=extract_archive,
            debug=debug,
        )
    )
    writer = _create_output_writer()
    emit_command_result(writer, result)
    try:
        return result.session.success_count, result.session.failure_count
    finally:
        if http_client is not None:
            with contextlib.suppress(Exception):
                http_client.close()
        if scanner is not None:
            with contextlib.suppress(Exception):
                scanner.close()


__all__ = [
    "Settings",
    "Architecture",
    "load_settings",
    "create_application",
    "create_dependencies",
    "process_downloads",
]
