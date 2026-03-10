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

    assert writer.stdout == ["problem"]
    assert writer.stderr == []
