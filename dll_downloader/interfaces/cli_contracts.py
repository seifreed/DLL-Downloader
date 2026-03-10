"""
CLI contracts and argument-normalization helpers.
"""

import argparse
from typing import Protocol

from ..application.use_cases.download_batch import DownloadBatchResponse
from ..domain.entities.dll_file import Architecture, normalize_dll_name


class BatchPresenter(Protocol):
    """Minimal presenter contract required by CLI orchestration."""

    def render_batch(
        self,
        response: DownloadBatchResponse,
        architecture_label: str,
    ) -> list[str]:
        """Render the per-item batch output."""

    def summary_counts(self, success_count: int, failure_count: int) -> str:
        """Render a final summary line."""

    def boundary_error(self, error_message: str) -> str:
        """Render a boundary failure line."""


class DLLListReader(Protocol):
    """Boundary contract for reading batch DLL names from a file."""

    def __call__(self, file_path: str) -> list[str]:
        """Return normalized raw entries read from disk."""


def parse_architecture(arch_str: str) -> Architecture:
    """Normalize CLI architecture strings to the domain enum."""
    return {
        "x86": Architecture.X86,
        "x64": Architecture.X64,
    }.get(arch_str, Architecture.X64)


def resolve_dll_names(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    read_dll_list: DLLListReader,
) -> list[str] | None:
    """Resolve CLI-provided DLL names from direct args or a batch file."""
    if not args.dll_name and not args.file:
        parser.print_help()
        return None

    if args.file:
        dll_names = read_dll_list(args.file)
        print(f"Downloading {len(dll_names)} DLL(s) from '{args.file}'...")
        return dll_names

    return [normalize_dll_name(args.dll_name)]
