"""CLI entry point for the DLL Downloader application."""

import argparse
import contextlib
import logging
import os
import re
import stat
import sys
from pathlib import Path

from ..api import Settings
from ..application.use_cases.download_dll import DownloadDLLResponse
from ..domain.entities.dll_file import Architecture, normalize_dll_name
from ..runtime import load_settings
from .cli_arguments import ArgumentParseFailure, parse_arguments, parse_main_arguments
from .cli_contracts import OutputFormat, parse_architecture
from .cli_formatters import (
    create_batch_presenter,
    create_cli_service,
    emit_cli_input_error,
    get_output_format,
)
from .cli_runner import CLIApplicationService
from .presenters.download_presenter import (
    DownloadConsolePresenter,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger(__name__)
_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}


_PATH_PATTERN = re.compile(r"(?:^|\s|['\"])/[^\s'\"]+")


def _sanitize_boundary_message(exc: Exception) -> str:
    """Remove filesystem paths and URL credentials from exception messages."""
    msg = str(exc)
    msg = _PATH_PATTERN.sub(" <path>", msg)
    return msg


def set_debug_mode(enabled: bool) -> None:
    """
    Set debug mode environment variable.

    Args:
        enabled: Whether to enable debug mode.
    """
    os.environ['DEBUG_MODE'] = '1' if enabled else '0'


def apply_logging_settings(settings: Settings, debug_enabled: bool) -> None:
    """Apply configured logging unless debug mode explicitly wins."""
    if debug_enabled:
        logging.getLogger().setLevel(logging.DEBUG)
        return
    level_name = settings.log_level.upper()
    if level_name not in _LOG_LEVELS:
        raise ValueError(f"Unsupported log level: {settings.log_level}")
    logging.getLogger().setLevel(_LOG_LEVELS[level_name])


_MAX_DLL_LIST_LINES = 10_000


def read_dll_list_from_file(file_path: str) -> list[str]:
    """
    Read DLL names from a file, one per line.

    Args:
        file_path: Path to the file containing DLL names.

    Returns:
        A list of DLL names read from the file.

    Raises:
        ValueError: If the file does not exist or is empty.
    """
    raw_path = Path(file_path)
    fd = -1
    try:
        fd = os.open(str(raw_path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        raise ValueError(f"File '{file_path}' not found.") from None
    except OSError as exc:
        if exc.errno == 40:  # ELOOP - symlink
            raise ValueError(f"Refusing to read DLL list from symlink: '{file_path}'") from exc
        raise ValueError(f"Failed to access file '{file_path}': {exc}") from exc

    try:
        st = os.fstat(fd)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Refusing to read non-regular file: '{file_path}'")
        with os.fdopen(fd, encoding="utf-8") as f:
            fd = -1  # ownership transferred to fdopen
            dll_names = []
            for i, line in enumerate(f):
                if i >= _MAX_DLL_LIST_LINES:
                    raise ValueError(f"File '{file_path}' exceeds maximum line count")
                stripped = line.strip()
                if stripped:
                    dll_names.append(normalize_dll_name(stripped))
    except ValueError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"Failed to read file '{file_path}': {exc}") from exc
    finally:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)

    if not dll_names:
        raise ValueError(
            f"File '{file_path}' is empty or contains no valid DLL names."
        )

    return dll_names


def get_architecture(arch_str: str) -> Architecture:
    """
    Convert architecture string to Architecture enum.

    Args:
        arch_str: Architecture string ('x86', 'x64', 'arm', or 'arm64')

    Returns:
        Architecture enum value

    Raises:
        ValueError: If the architecture string is not recognized.
    """
    return parse_architecture(arch_str)


def format_response(response: DownloadDLLResponse, dll_name: str) -> None:
    """
    Format and print the download response to console.

    Args:
        response: The download response from the use case
        dll_name: Name of the DLL that was requested
    """
    print(DownloadConsolePresenter().format(response, dll_name))


def _handle_missing_cli_input(
    parser: argparse.ArgumentParser,
    output_format: OutputFormat,
    service: CLIApplicationService,
) -> int:
    """Emit the correct missing-input response for the selected output format."""
    if output_format == OutputFormat.CONSOLE:
        parser.print_help()
        return 1

    emit_cli_input_error(
        service,
        create_batch_presenter(output_format).boundary_error(
            "Please provide a DLL name or use --file"
        ),
    )
    return 1


def _run_cli_session(
    service: CLIApplicationService,
    output_format: OutputFormat,
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    settings: Settings,
) -> int:
    """Execute one CLI session and normalize input failures."""
    try:
        result = service.run_from_args(
            args,
            parser,
            settings,
            read_dll_list_from_file,
        )
    except Exception as exc:
        emit_cli_input_error(
            service,
            create_batch_presenter(output_format).boundary_error(_sanitize_boundary_message(exc)),
        )
        return 1

    summary = service.render_summary(result)
    if summary:
        print(summary)
    return result.session.exit_code

def main(settings: Settings | None = None) -> int:
    """
    CLI entry point using Clean Architecture.

    Args:
        settings: Optional settings instance for dependency injection.
                  If None, settings are loaded from environment/config files.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        return _main_inner(settings)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


def _main_inner(settings: Settings | None) -> int:
    """Inner entry point that raises on interrupt."""
    parsed = parse_main_arguments()
    if isinstance(parsed, ArgumentParseFailure):
        service = create_cli_service(parsed.output_format)
        emit_cli_input_error(
            service,
            create_batch_presenter(parsed.output_format).boundary_error(parsed.message),
        )
        return 1
    args, parser = parsed
    set_debug_mode(args.debug)
    output_format = get_output_format(args)
    service = create_cli_service(output_format)

    if not args.dll_name and not args.file:
        return _handle_missing_cli_input(parser, output_format, service)

    if settings is None:
        try:
            settings = load_settings()
        except (OSError, ValueError) as exc:
            emit_cli_input_error(
                service,
                create_batch_presenter(output_format).boundary_error(_sanitize_boundary_message(exc)),
            )
            return 1

    try:
        apply_logging_settings(settings, args.debug)
    except ValueError as exc:
        emit_cli_input_error(
            service,
            create_batch_presenter(output_format).boundary_error(_sanitize_boundary_message(exc)),
        )
        return 1

    return _run_cli_session(service, output_format, args, parser, settings)


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "parse_arguments",
    "set_debug_mode",
    "read_dll_list_from_file",
    "get_architecture",
    "format_response",
    "main",
]
