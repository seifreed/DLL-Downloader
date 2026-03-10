import argparse

import pytest

from dll_downloader.domain.entities.dll_file import Architecture
from dll_downloader.interfaces.cli_contracts import (
    parse_architecture,
    resolve_dll_names,
)


class RecordingReader:
    def __init__(self, dll_names: list[str]) -> None:
        self._dll_names = dll_names
        self.calls: list[str] = []

    def __call__(self, file_path: str) -> list[str]:
        self.calls.append(file_path)
        return self._dll_names


@pytest.mark.unit
def test_parse_architecture_supports_known_values() -> None:
    assert parse_architecture("x86") == Architecture.X86
    assert parse_architecture("x64") == Architecture.X64


@pytest.mark.unit
def test_parse_architecture_defaults_to_x64() -> None:
    assert parse_architecture("arm64") == Architecture.X64


@pytest.mark.unit
def test_resolve_dll_names_prints_help_when_missing_inputs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = argparse.ArgumentParser()
    args = argparse.Namespace(dll_name=None, file=None)

    assert resolve_dll_names(args, parser, RecordingReader([])) is None
    assert "usage:" in capsys.readouterr().out.lower()


@pytest.mark.unit
def test_resolve_dll_names_reads_batch_file(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = argparse.ArgumentParser()
    args = argparse.Namespace(dll_name=None, file="dlls.txt")
    reader = RecordingReader(["a.dll", "b.dll"])

    dll_names = resolve_dll_names(args, parser, reader)

    assert dll_names == ["a.dll", "b.dll"]
    assert reader.calls == ["dlls.txt"]
    assert "Downloading 2 DLL(s) from 'dlls.txt'" in capsys.readouterr().out


@pytest.mark.unit
def test_resolve_dll_names_normalizes_single_name() -> None:
    parser = argparse.ArgumentParser()
    args = argparse.Namespace(dll_name="kernel32", file=None)

    assert resolve_dll_names(args, parser, RecordingReader([])) == ["kernel32.dll"]
