import argparse
from typing import cast

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
    assert parse_architecture("arm") == Architecture.ARM
    assert parse_architecture("arm64") == Architecture.ARM64


@pytest.mark.unit
def test_parse_architecture_rejects_unknown_values() -> None:
    with pytest.raises(ValueError, match="Unsupported architecture"):
        parse_architecture("unknown")
    with pytest.raises(ValueError, match="Unsupported architecture"):
        parse_architecture("")


@pytest.mark.unit
@pytest.mark.parametrize("arch_str", [cast(str, None), cast(str, 1)])
def test_parse_architecture_rejects_non_string_values(arch_str: str) -> None:
    with pytest.raises(ValueError, match="Unsupported architecture"):
        parse_architecture(arch_str)


@pytest.mark.unit
def test_resolve_dll_names_raises_when_missing_inputs() -> None:
    args = argparse.Namespace(dll_name=None, file=None)

    with pytest.raises(ValueError, match="Please provide a DLL name or use --file"):
        resolve_dll_names(args, RecordingReader([]))


@pytest.mark.unit
def test_resolve_dll_names_rejects_ambiguous_inputs() -> None:
    args = argparse.Namespace(dll_name="ignored.dll", file="dlls.txt")
    reader = RecordingReader(["a.dll"])

    with pytest.raises(ValueError, match="either a DLL name or --file"):
        resolve_dll_names(args, reader)

    assert reader.calls == []


@pytest.mark.unit
def test_resolve_dll_names_reads_batch_file() -> None:
    args = argparse.Namespace(dll_name=None, file="dlls.txt")
    reader = RecordingReader(["a.dll", "b.dll"])

    dll_names = resolve_dll_names(args, reader)

    assert dll_names == ["a.dll", "b.dll"]
    assert reader.calls == ["dlls.txt"]


@pytest.mark.unit
def test_resolve_dll_names_normalizes_single_name() -> None:
    args = argparse.Namespace(dll_name="kernel32", file=None)

    assert resolve_dll_names(args, RecordingReader([])) == ["kernel32.dll"]
