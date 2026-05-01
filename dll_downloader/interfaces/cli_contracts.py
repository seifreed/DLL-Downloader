"""
CLI contracts and argument-normalization helpers.
"""

import argparse
from enum import Enum
from typing import Protocol

from ..application.use_cases.download_batch import DownloadBatchResponse
from ..domain.entities.dll_file import Architecture, normalize_dll_name


class OutputFormat(Enum):
    """Supported CLI output formats."""

    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


class BatchPresenter(Protocol):
    """Minimal presenter contract required by CLI orchestration."""

    def render_batch(
        self,
        response: DownloadBatchResponse,
        architecture_label: str,
    ) -> list[str]:
        """Render the per-item batch output."""

    def summary_counts(self, success_count: int, failure_count: int) -> str | None:
        """Render a final summary line when the format uses a separate summary."""

    def boundary_error(self, error_message: str, failure_count: int = 1) -> str:
        """Render a boundary failure line."""


class DLLListReader(Protocol):
    """Boundary contract for reading batch DLL names from a file."""

    def __call__(self, file_path: str) -> list[str]:
        """Return normalized raw entries read from disk."""


_ARCH_STRING_MAP = {
    "x86": Architecture.X86,
    "x64": Architecture.X64,
    "arm": Architecture.ARM,
    "arm64": Architecture.ARM64,
}


def parse_architecture(arch_str: str) -> Architecture:
    """Normalize CLI architecture strings to the domain enum."""
    result = _ARCH_STRING_MAP.get(arch_str)
    if result is None:
        raise ValueError(f"Unsupported architecture: {arch_str!r}")
    return result


def resolve_dll_names(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,  # noqa: ARG001
    read_dll_list: DLLListReader,
) -> list[str]:
    """Resolve CLI-provided DLL names from direct args or a batch file."""
    if not args.dll_name and not args.file:
        raise ValueError("Please provide a DLL name or use --file")
    if args.dll_name and args.file:
        raise ValueError("Please provide either a DLL name or --file, not both")

    if args.file:
        return read_dll_list(args.file)

    return [normalize_dll_name(args.dll_name)]
