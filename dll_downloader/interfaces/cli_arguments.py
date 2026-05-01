"""
CLI argument parser construction and structured parse handling.
"""

import argparse
import sys
from dataclasses import dataclass
from typing import Never

from .cli_contracts import OutputFormat


@dataclass(frozen=True)
class ArgumentParseFailure:
    """Structured parse failure metadata for CLI boundary handling."""

    output_format: OutputFormat
    message: str


class BoundaryArgumentParser(argparse.ArgumentParser):
    """Argument parser variant that reports errors through exceptions."""

    def error(self, message: str) -> Never:
        raise ValueError(message)


def build_argument_parser(
    parser_class: type[argparse.ArgumentParser] = argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    """Create the CLI parser with its help text."""
    return parser_class(
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
        """,
    )


def add_standard_arguments(parser: argparse.ArgumentParser) -> None:
    """Register all supported CLI arguments on the parser."""
    parser.add_argument(
        "dll_name",
        nargs="?",
        help="Name of the DLL to download (e.g., msvcp140.dll)",
    )

    parser.add_argument(
        "--file",
        help="File containing a list of DLL names (one per line)",
    )

    parser.add_argument(
        "--arch",
        choices=["x86", "x64"],
        default="x64",
        help="Target architecture (default: x64)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode for verbose output",
    )

    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip VirusTotal security scanning",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force download even if file already exists locally",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        help="Custom output directory for downloads",
    )

    parser.add_argument(
        "--extract",
        action="store_true",
        help="Extract the DLL when the downloaded file is a ZIP archive",
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


def parse_arguments(
    argv: list[str] | None = None,
) -> tuple[argparse.Namespace, argparse.ArgumentParser]:
    """Parse and return command-line arguments."""
    parser = build_argument_parser()
    add_standard_arguments(parser)
    return parser.parse_args(argv), parser


def detect_requested_output_format(argv: list[str]) -> OutputFormat:
    """Detect structured output flags before full argument parsing."""
    for argument in argv:
        if argument == "--":
            break
        if _matches_output_flag(argument, "--json"):
            return OutputFormat.JSON
        if _matches_output_flag(argument, "--sarif"):
            return OutputFormat.SARIF
    return OutputFormat.CONSOLE


def _matches_output_flag(argument: str, flag: str) -> bool:
    """Match argparse-style unambiguous abbreviations for structured flags."""
    argument_name = argument.split("=", 1)[0]
    return len(argument_name) >= len(flag) and flag.startswith(argument_name)


def parse_main_arguments(
    argv: list[str] | None = None,
) -> tuple[argparse.Namespace, argparse.ArgumentParser] | ArgumentParseFailure:
    """Parse CLI arguments while preserving structured-output boundary contracts."""
    parse_argv = sys.argv[1:] if argv is None else argv
    requested_output_format = detect_requested_output_format(parse_argv)
    if requested_output_format == OutputFormat.CONSOLE:
        return parse_arguments(parse_argv)

    parser = build_argument_parser(BoundaryArgumentParser)
    add_standard_arguments(parser)
    try:
        return parser.parse_args(parse_argv), parser
    except ValueError as exc:
        return ArgumentParseFailure(requested_output_format, str(exc))
