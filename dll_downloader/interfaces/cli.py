"""CLI entry point for the DLL Downloader application."""

import argparse
import contextlib
import errno
import logging
import os
import stat
import sys
from pathlib import Path
from typing import TextIO

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
from .cli_sanitization import sanitize_boundary_message as _sanitize_boundary_message
from .presenters.download_presenter import DownloadConsolePresenter

logging.basicConfig(level=logging.INFO, format="%(message)s")
_LOG_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}


_MAX_DLL_NAME_LENGTH = 260
_READ_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)


def set_debug_mode(enabled: bool) -> None:
    """Set debug mode environment variable."""
    os.environ["DEBUG_MODE"] = "1" if enabled else "0"


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


def _open_regular_dll_list(file_path: str) -> int:
    """Open a DLL list without following symlinks or blocking on special files."""
    try:
        fd = os.open(file_path, _READ_FILE_FLAGS)
    except FileNotFoundError:
        raise ValueError(f"File '{file_path}' not found.") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(
                f"Refusing to read DLL list from symlink: '{file_path}'"
            ) from exc
        raise ValueError(f"Failed to read file '{file_path}': {exc}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Refusing to read non-regular file: '{file_path}'")
        os.set_blocking(fd, True)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise

    return fd


def _parse_dll_list_lines(file_handle: TextIO, file_path: str) -> list[str]:
    dll_names: list[str] = []
    for line_number, line in enumerate(file_handle, start=1):
        if line_number > _MAX_DLL_LIST_LINES:
            raise ValueError(f"File '{file_path}' exceeds maximum line count")
        line_without_newline = line.rstrip("\n\r")
        if len(line_without_newline) > _MAX_DLL_NAME_LENGTH:
            raise ValueError(
                f"Line {line_number} in '{file_path}' exceeds maximum length"
            )
        stripped_name = line_without_newline.strip()
        if stripped_name:
            dll_names.append(normalize_dll_name(stripped_name))
    return dll_names


def read_dll_list_from_file(file_path: str) -> list[str]:
    """Read DLL names from a regular file, one per line."""
    fd = _open_regular_dll_list(str(Path(file_path)))
    try:
        with os.fdopen(fd, encoding="utf-8-sig") as file_handle:
            fd = -1
            dll_names = _parse_dll_list_lines(file_handle, file_path)
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"Failed to read file '{file_path}': {exc}") from exc
    finally:
        if fd >= 0:
            with contextlib.suppress(OSError):
                os.close(fd)

    if not dll_names:
        raise ValueError(f"File '{file_path}' is empty or contains no valid DLL names.")

    return dll_names


def get_architecture(arch_str: str) -> Architecture:
    """Convert architecture string to Architecture enum."""
    return parse_architecture(arch_str)


def format_response(response: DownloadDLLResponse, dll_name: str) -> None:
    """Format and print the download response to console."""
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
            create_batch_presenter(output_format).boundary_error(
                _sanitize_boundary_message(exc)
            ),
        )
        return 1

    summary = service.render_summary(result)
    if summary:
        print(summary)
    return result.session.exit_code


def _load_cli_settings(
    provided_settings: Settings | None,
    service: CLIApplicationService,
    output_format: OutputFormat,
) -> Settings | None:
    if provided_settings is not None:
        return provided_settings
    try:
        return load_settings()
    except (OSError, ValueError) as exc:
        emit_cli_input_error(
            service,
            create_batch_presenter(output_format).boundary_error(
                _sanitize_boundary_message(exc)
            ),
        )
        return None


def _apply_cli_logging(
    settings: Settings,
    debug_enabled: bool,
    service: CLIApplicationService,
    output_format: OutputFormat,
) -> bool:
    try:
        apply_logging_settings(settings, debug_enabled)
    except ValueError as exc:
        emit_cli_input_error(
            service,
            create_batch_presenter(output_format).boundary_error(
                _sanitize_boundary_message(exc)
            ),
        )
        return False
    return True


def main(settings: Settings | None = None) -> int:
    """CLI entry point. Returns exit code (0 for success, 1 for failure)."""
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

    settings = _load_cli_settings(settings, service, output_format)
    if settings is None:
        return 1
    if not _apply_cli_logging(settings, args.debug, service, output_format):
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
