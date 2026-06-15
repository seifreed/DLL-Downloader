"""Tests for CLI argument output-format detection."""

import pytest

from dll_downloader.interfaces.cli_arguments import detect_requested_output_format
from dll_downloader.interfaces.cli_contracts import OutputFormat


@pytest.mark.unit
def test_detect_output_format_defaults_to_console() -> None:
    assert detect_requested_output_format(["foo.dll"]) == OutputFormat.CONSOLE


@pytest.mark.unit
@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["--json"], OutputFormat.JSON),
        (["--json=anything"], OutputFormat.JSON),
        (["--sarif"], OutputFormat.SARIF),
    ],
)
def test_detect_output_format_recognizes_flags(
    argv: list[str], expected: OutputFormat
) -> None:
    assert detect_requested_output_format(argv) == expected


@pytest.mark.unit
def test_detect_output_format_stops_at_double_dash_separator() -> None:
    # Anything after the "--" separator is positional and must not be read as
    # an output flag, so detection breaks at "--" and falls back to console.
    assert detect_requested_output_format(["--", "--json"]) == OutputFormat.CONSOLE
