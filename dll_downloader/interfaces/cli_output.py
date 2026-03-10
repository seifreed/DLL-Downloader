"""
CLI output contracts and helpers.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CLISessionResult:
    """Aggregate result returned by the CLI session runner."""

    success_count: int
    failure_count: int
    exit_code: int


class OutputWriter(Protocol):
    """Write rendered CLI output to a concrete destination."""

    def write(self, text: str, *, error: bool = False) -> None:
        """Emit one line of output."""


class ConsoleOutputWriter:
    """Default stdout/stderr writer for CLI sessions."""

    def write(self, text: str, *, error: bool = False) -> None:
        import sys

        print(text, file=sys.stderr if error else sys.stdout)


@dataclass(frozen=True)
class CLIBoundaryFailure:
    """Rendered failure information for CLI boundary handling."""

    message: str
    traceback_text: str | None = None


@dataclass(frozen=True)
class CLICommandResult:
    """Rendered command output plus normalized session status."""

    stdout_lines: list[str]
    session: CLISessionResult
    boundary_failure: CLIBoundaryFailure | None = None


def emit_command_result(writer: OutputWriter, result: CLICommandResult) -> None:
    """Write a rendered command result to the configured writer."""
    for line in result.stdout_lines:
        writer.write(line)
    if result.boundary_failure is None:
        return
    writer.write(result.boundary_failure.message)
    if result.boundary_failure.traceback_text:
        writer.write(result.boundary_failure.traceback_text, error=True)
