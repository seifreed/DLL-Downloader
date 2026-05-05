from typing import Any, cast

import pytest

from dll_downloader.interfaces.cli_output import (
    CLIBoundaryFailure,
    CLICommandResult,
    CLISessionResult,
    emit_command_result,
)


class RecordingWriter:
    def __init__(self) -> None:
        self.stdout: list[str] = []
        self.stderr: list[str] = []

    def write(self, text: str, *, error: bool = False) -> None:
        if error:
            self.stderr.append(text)
        else:
            self.stdout.append(text)


@pytest.mark.unit
def test_emit_command_result_without_boundary_failure() -> None:
    writer = RecordingWriter()

    emit_command_result(
        writer,
        CLICommandResult(
            stdout_lines=["one", "two"],
            session=CLISessionResult(success_count=1, failure_count=0, exit_code=0),
        ),
    )

    assert writer.stdout == ["one", "two"]
    assert writer.stderr == []


@pytest.mark.unit
def test_cli_command_result_stdout_lines_are_snapshot_immutable() -> None:
    source_lines = ["one"]
    result = CLICommandResult(
        stdout_lines=source_lines,
        session=CLISessionResult(success_count=1, failure_count=0, exit_code=0),
    )
    source_lines.append("two")
    writer = RecordingWriter()

    emit_command_result(writer, result)

    assert writer.stdout == ["one"]
    with pytest.raises(AttributeError):
        cast(Any, result.stdout_lines).append("three")


@pytest.mark.unit
def test_emit_command_result_without_traceback_text() -> None:
    writer = RecordingWriter()

    emit_command_result(
        writer,
        CLICommandResult(
            stdout_lines=[],
            session=CLISessionResult(success_count=0, failure_count=1, exit_code=1),
            boundary_failure=CLIBoundaryFailure(message="problem"),
        ),
    )

    assert writer.stderr == ["problem"]
    assert writer.stdout == []


@pytest.mark.unit
def test_emit_command_result_structured_failure_goes_to_stdout() -> None:
    writer = RecordingWriter()

    emit_command_result(
        writer,
        CLICommandResult(
            stdout_lines=[],
            session=CLISessionResult(success_count=0, failure_count=1, exit_code=1),
            boundary_failure=CLIBoundaryFailure(
                message='{"error":"bad"}', is_structured=True
            ),
        ),
    )

    assert writer.stdout == ['{"error":"bad"}']
    assert writer.stderr == []


@pytest.mark.unit
def test_emit_command_result_console_failure_goes_to_stderr() -> None:
    writer = RecordingWriter()

    emit_command_result(
        writer,
        CLICommandResult(
            stdout_lines=[],
            session=CLISessionResult(success_count=0, failure_count=1, exit_code=1),
            boundary_failure=CLIBoundaryFailure(
                message="[ERROR] something failed", is_structured=False
            ),
        ),
    )

    assert writer.stderr == ["[ERROR] something failed"]
    assert writer.stdout == []
