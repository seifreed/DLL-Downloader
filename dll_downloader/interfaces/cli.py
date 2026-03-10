"""
Command Line Interface

Provides the CLI entry point for the DLL Downloader application
using Clean Architecture with dependency injection.
"""

import argparse
import logging
import os
import sys

from ..api import Settings
from ..application.use_cases.download_dll import DownloadDLLResponse
from ..domain.entities.dll_file import Architecture
from ..runtime import load_settings
from .cli_contracts import OutputFormat
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


def _build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI parser with its help text."""
    return argparse.ArgumentParser(
        description="Download DLL files from DLL-files.com",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dll-downloader.py msvcp140.dll
  python3 dll-downloader.py msvcp140.dll --arch x86
  python3 dll-downloader.py --file dll_list.txt
  python3 dll-downloader.py msvcp140.dll --debug
  python3 dll-downloader.py msvcp140.dll --no-scan
  python3 dll-downloader.py msvcp140.dll --extract
        """
    )


def _add_standard_arguments(parser: argparse.ArgumentParser) -> None:
    """Register all supported CLI arguments on the parser."""
    parser.add_argument(
        'dll_name',
        nargs='?',
        help='Name of the DLL to download (e.g., msvcp140.dll)'
    )

    parser.add_argument(
        '--file',
        help='File containing a list of DLL names (one per line)'
    )

    parser.add_argument(
        '--arch',
        choices=['x86', 'x64'],
        default='x64',
        help='Target architecture (default: x64)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode for verbose output'
    )

    parser.add_argument(
        '--no-scan',
        action='store_true',
        help='Skip VirusTotal security scanning'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Force download even if file already exists locally'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        help='Custom output directory for downloads'
    )

    parser.add_argument(
        '--extract',
        action='store_true',
        help='Extract the DLL when the downloaded file is a ZIP archive'
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )
    output_group.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF v2.1.0 output",
    )


def parse_arguments() -> tuple[argparse.Namespace, argparse.ArgumentParser]:
    """
    Parse and return command line arguments.

    Creates an argument parser with options for specifying DLL names,
    input files, target architecture, and debug mode.

    Returns:
        A tuple containing the parsed arguments namespace and the parser object.
    """
    parser = _build_argument_parser()
    _add_standard_arguments(parser)

    return parser.parse_args(), parser


def set_debug_mode(enabled: bool) -> None:
    """
    Set debug mode environment variable and logging level.

    Args:
        enabled: Whether to enable debug mode.
    """
    os.environ['DEBUG_MODE'] = '1' if enabled else '0'
    if enabled:
        logging.getLogger().setLevel(logging.DEBUG)


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
    if not os.path.exists(file_path):
        raise ValueError(f"File '{file_path}' not found.")

    with open(file_path) as f:
        dll_names = [line.strip() for line in f if line.strip()]

    if not dll_names:
        raise ValueError(
            f"File '{file_path}' is empty or contains no valid DLL names."
        )

    return dll_names


def get_architecture(arch_str: str) -> Architecture:
    """
    Convert architecture string to Architecture enum.

    Args:
        arch_str: Architecture string ('x86' or 'x64')

    Returns:
        Architecture enum value
    """
    return {
        'x86': Architecture.X86,
        'x64': Architecture.X64,
    }.get(arch_str, Architecture.X64)


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
    except ValueError as exc:
        emit_cli_input_error(
            service,
            create_batch_presenter(output_format).boundary_error(str(exc)),
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
    args, parser = parse_arguments()
    set_debug_mode(args.debug)
    output_format = get_output_format(args)
    service = create_cli_service(output_format)

    if not args.dll_name and not args.file:
        return _handle_missing_cli_input(parser, output_format, service)

    if settings is None:
        settings = load_settings()

    return _run_cli_session(service, output_format, args, parser, settings)
if __name__ == "__main__":
    sys.exit(main())


__all__ = ["parse_arguments", "set_debug_mode", "read_dll_list_from_file", "get_architecture", "format_response", "main"]
