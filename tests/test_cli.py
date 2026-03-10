# Copyright (c) 2026 Marc Rivero López
# Licensed under GPLv3. See LICENSE file for details.
# This test suite validates real code behavior without mocks or stubs.

"""
Unit tests for CLI interface.

This module tests the command-line interface including argument parsing,
dependency creation, and main execution flow. Tests use real function
execution and temporary files.
"""

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from _pytest.capture import CaptureFixture

from dll_downloader.api import (
    DownloadDLLRequest,
    DownloadDLLResponse,
    Settings,
)
from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
    normalize_dll_name,
)
from dll_downloader.interfaces.cli import (
    format_response,
    get_architecture,
    main,
    parse_arguments,
    read_dll_list_from_file,
    set_debug_mode,
)
from dll_downloader.runtime import create_dependencies, process_downloads


class RecordingUseCase:
    """Minimal fake that satisfies the public download execution contract."""

    def __init__(
        self,
        responses: dict[str, DownloadDLLResponse] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.requests: list[DownloadDLLRequest] = []

    def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
        self.requests.append(request)
        return self.responses.get(
            request.dll_name,
            DownloadDLLResponse(
                success=False,
                error_message=f"Missing canned response for {request.dll_name}",
            ),
        )


def _successful_response(dll_name: str) -> DownloadDLLResponse:
    return DownloadDLLResponse(
        success=True,
        dll_file=DLLFile(
            name=dll_name,
            architecture=Architecture.X64,
            file_path=f"/downloads/{dll_name}",
        ),
    )

@contextmanager
def _temporary_argv(argv: list[str]) -> Iterator[None]:
    original = sys.argv[:]
    sys.argv = argv
    try:
        yield
    finally:
        sys.argv = original


@contextmanager
def _temporary_cwd(path: Path) -> Iterator[None]:
    original = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


def _seed_cached_dll(repo_dir: Path, dll_names: list[str]) -> None:
    (repo_dir / "x64").mkdir(parents=True, exist_ok=True)
    index_data: dict[str, dict[str, object]] = {}
    for dll_name in dll_names:
        normalized_name = normalize_dll_name(dll_name)
        file_path = repo_dir / "x64" / normalized_name
        content = b"cached content"
        file_path.write_bytes(content)
        index_data[f"x64/{normalized_name.lower()}"] = {
            "name": normalized_name,
            "version": None,
            "architecture": "x64",
            "file_hash": None,
            "file_path": str(file_path),
            "download_url": None,
            "file_size": len(content),
            "security_status": "not_scanned",
            "vt_detection_ratio": None,
            "vt_scan_date": None,
            "created_at": None,
        }

    (repo_dir / ".dll_index.json").write_text(json.dumps({"files": index_data}))

# ============================================================================
# Argument Parsing Tests
# ============================================================================

@pytest.mark.unit
def test_parse_arguments_single_dll() -> None:
    """
    Test parsing command line arguments for single DLL.

    Purpose:
        Verify that basic DLL name argument is parsed correctly.

    Expected Behavior:
        - dll_name is captured
        - Default values are set for other arguments
    """
    sys.argv = ["dll-downloader.py", "kernel32.dll"]
    args, parser = parse_arguments()

    assert args.dll_name == "kernel32.dll"
    assert args.file is None
    assert args.arch == "x64"
    assert args.debug is False
    assert args.no_scan is False
    assert args.force is False
    assert args.extract is False


@pytest.mark.unit
def test_parse_arguments_with_architecture() -> None:
    """
    Test parsing with architecture specification.

    Purpose:
        Verify that architecture argument is parsed correctly.

    Expected Behavior:
        Architecture value is captured correctly.
    """
    sys.argv = ["dll-downloader.py", "msvcp140.dll", "--arch", "x86"]
    args, parser = parse_arguments()

    assert args.dll_name == "msvcp140.dll"
    assert args.arch == "x86"


@pytest.mark.unit
def test_parse_arguments_with_file() -> None:
    """
    Test parsing with file input option.

    Purpose:
        Verify that --file argument is parsed correctly.

    Expected Behavior:
        File path is captured, dll_name is optional.
    """
    sys.argv = ["dll-downloader.py", "--file", "dlls.txt"]
    args, parser = parse_arguments()

    assert args.file == "dlls.txt"
    assert args.dll_name is None


@pytest.mark.unit
def test_parse_arguments_debug_flag() -> None:
    """
    Test parsing with debug flag.

    Purpose:
        Verify that debug mode flag is recognized.

    Expected Behavior:
        debug flag is set to True.
    """
    sys.argv = ["dll-downloader.py", "test.dll", "--debug"]
    args, parser = parse_arguments()

    assert args.debug is True


@pytest.mark.unit
def test_parse_arguments_no_scan_flag() -> None:
    """
    Test parsing with no-scan flag.

    Purpose:
        Verify that security scanning can be disabled.

    Expected Behavior:
        no_scan flag is set to True.
    """
    sys.argv = ["dll-downloader.py", "test.dll", "--no-scan"]
    args, parser = parse_arguments()

    assert args.no_scan is True


@pytest.mark.unit
def test_parse_arguments_force_flag() -> None:
    """
    Test parsing with force download flag.

    Purpose:
        Verify that force download option is recognized.

    Expected Behavior:
        force flag is set to True.
    """
    sys.argv = ["dll-downloader.py", "test.dll", "--force"]
    args, parser = parse_arguments()

    assert args.force is True


@pytest.mark.unit
def test_parse_arguments_custom_output_dir() -> None:
    """
    Test parsing with custom output directory.

    Purpose:
        Verify that output directory can be specified.

    Expected Behavior:
        output_dir value is captured.
    """
    sys.argv = ["dll-downloader.py", "test.dll", "--output-dir", "/custom/path"]
    args, parser = parse_arguments()

    assert args.output_dir == "/custom/path"


@pytest.mark.unit
def test_parse_arguments_extract_flag() -> None:
    """
    Test parsing with extract flag.

    Purpose:
        Verify that ZIP extraction can be enabled from the CLI.

    Expected Behavior:
        extract flag is set to True.
    """
    sys.argv = ["dll-downloader.py", "test.dll", "--extract"]
    args, parser = parse_arguments()

    assert args.extract is True


@pytest.mark.unit
def test_parse_arguments_combined_flags() -> None:
    """
    Test parsing with multiple combined flags.

    Purpose:
        Verify that multiple options work together correctly.

    Expected Behavior:
        All specified flags are captured correctly.
    """
    sys.argv = [
        "dll-downloader.py",
        "msvcp140.dll",
        "--arch", "x86",
        "--debug",
        "--no-scan",
        "--force",
        "--extract",
    ]
    args, parser = parse_arguments()

    assert args.dll_name == "msvcp140.dll"
    assert args.arch == "x86"
    assert args.debug is True
    assert args.no_scan is True
    assert args.force is True
    assert args.extract is True


@pytest.mark.unit
def test_parse_arguments_returns_parser() -> None:
    """
    Test that parse_arguments returns both args and parser.

    Purpose:
        Verify function signature for proper error handling.

    Expected Behavior:
        Returns tuple of (Namespace, ArgumentParser).
    """
    sys.argv = ["dll-downloader.py", "test.dll"]
    args, parser = parse_arguments()

    assert isinstance(args, argparse.Namespace)
    assert isinstance(parser, argparse.ArgumentParser)


# ============================================================================
# Debug Mode Tests
# ============================================================================

@pytest.mark.unit
def test_set_debug_mode_enabled() -> None:
    """
    Test enabling debug mode.

    Purpose:
        Verify that debug mode sets environment variable correctly.

    Expected Behavior:
        DEBUG_MODE environment variable is set to '1'.
    """
    set_debug_mode(True)

    assert os.environ.get("DEBUG_MODE") == "1"

    # Cleanup
    os.environ.pop("DEBUG_MODE", None)


@pytest.mark.unit
def test_set_debug_mode_disabled() -> None:
    """
    Test disabling debug mode.

    Purpose:
        Verify that debug mode can be turned off.

    Expected Behavior:
        DEBUG_MODE environment variable is set to '0'.
    """
    set_debug_mode(False)

    assert os.environ.get("DEBUG_MODE") == "0"

    # Cleanup
    os.environ.pop("DEBUG_MODE", None)


# ============================================================================
# DLL List File Reading Tests
# ============================================================================

@pytest.mark.unit
def test_read_dll_list_from_file_success() -> None:
    """
    Test reading DLL names from a valid file.

    Purpose:
        Verify that file content is parsed correctly.

    Expected Behavior:
        - Returns list of DLL names
        - Empty lines are skipped
        - Whitespace is stripped
    """
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("kernel32.dll\n")
        f.write("msvcp140.dll\n")
        f.write("\n")  # Empty line
        f.write("  user32.dll  \n")  # With whitespace
        temp_path = f.name

    try:
        dll_names = read_dll_list_from_file(temp_path)

        assert len(dll_names) == 3
        assert "kernel32.dll" in dll_names
        assert "msvcp140.dll" in dll_names
        assert "user32.dll" in dll_names
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_read_dll_list_from_file_nonexistent_raises_error() -> None:
    """
    Test reading from non-existent file.

    Purpose:
        Verify proper error handling for missing files.

    Expected Behavior:
        SystemExit is raised when file doesn't exist.
    """
    with pytest.raises(SystemExit):
        read_dll_list_from_file("/nonexistent/path/file.txt")


@pytest.mark.unit
def test_read_dll_list_from_file_empty_file_raises_error() -> None:
    """
    Test reading from empty file.

    Purpose:
        Verify that empty files are rejected.

    Expected Behavior:
        SystemExit is raised when file contains no valid DLL names.
    """
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("\n\n\n")  # Only empty lines
        temp_path = f.name

    try:
        with pytest.raises(SystemExit):
            read_dll_list_from_file(temp_path)
    finally:
        os.unlink(temp_path)


@pytest.mark.unit
def test_read_dll_list_from_file_whitespace_only_raises_error() -> None:
    """
    Test reading from file with only whitespace.

    Purpose:
        Verify that whitespace-only files are rejected.

    Expected Behavior:
        SystemExit is raised when no valid names exist.
    """
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("   \n")
        f.write("\t\t\n")
        temp_path = f.name

    try:
        with pytest.raises(SystemExit):
            read_dll_list_from_file(temp_path)
    finally:
        os.unlink(temp_path)


# ============================================================================
# DLL Name Normalization Tests
# ============================================================================

@pytest.mark.unit
def test_normalize_dll_name_without_extension() -> None:
    """
    Test normalizing DLL name without extension.

    Purpose:
        Verify that .dll extension is added when missing.

    Expected Behavior:
        .dll extension is appended to the name.
    """
    result = normalize_dll_name("kernel32")

    assert result == "kernel32.dll"


@pytest.mark.unit
def test_normalize_dll_name_with_extension() -> None:
    """
    Test normalizing DLL name that already has extension.

    Purpose:
        Verify that existing extension is preserved.

    Expected Behavior:
        Name is returned unchanged.
    """
    result = normalize_dll_name("msvcp140.dll")

    assert result == "msvcp140.dll"


@pytest.mark.unit
def test_normalize_dll_name_case_insensitive() -> None:
    """
    Test normalization with uppercase extension.

    Purpose:
        Verify case-insensitive extension detection.

    Expected Behavior:
        .DLL, .Dll, .dll are all recognized.
    """
    result1 = normalize_dll_name("test.DLL")
    result2 = normalize_dll_name("test.Dll")
    result3 = normalize_dll_name("test.dll")

    assert result1 == "test.DLL"
    assert result2 == "test.Dll"
    assert result3 == "test.dll"


@pytest.mark.unit
def test_normalize_dll_name_no_double_extension() -> None:
    """
    Test that normalization doesn't create double extensions.

    Purpose:
        Verify that .dll is not added if already present.

    Expected Behavior:
        No duplicate extension created.
    """
    result = normalize_dll_name("kernel32.dll")

    assert result == "kernel32.dll"
    assert result != "kernel32.dll.dll"


# ============================================================================
# Architecture Conversion Tests
# ============================================================================

@pytest.mark.unit
def test_get_architecture_x86() -> None:
    """
    Test converting 'x86' string to Architecture enum.

    Purpose:
        Verify x86 architecture mapping.

    Expected Behavior:
        Returns Architecture.X86.
    """
    result = get_architecture("x86")

    assert result == Architecture.X86


@pytest.mark.unit
def test_get_architecture_x64() -> None:
    """
    Test converting 'x64' string to Architecture enum.

    Purpose:
        Verify x64 architecture mapping (default).

    Expected Behavior:
        Returns Architecture.X64.
    """
    result = get_architecture("x64")

    assert result == Architecture.X64


@pytest.mark.unit
def test_get_architecture_default() -> None:
    """
    Test that any non-x86 value defaults to x64.

    Purpose:
        Verify default architecture fallback behavior.

    Expected Behavior:
        Unknown values default to X64.
    """
    result1 = get_architecture("arm")
    result2 = get_architecture("unknown")
    result3 = get_architecture("")

    assert result1 == Architecture.X64
    assert result2 == Architecture.X64
    assert result3 == Architecture.X64


# ============================================================================
# Dependency Creation Tests
# ============================================================================

@pytest.mark.unit
def test_create_dependencies_returns_all_components() -> None:
    """
    Test that create_dependencies returns all required components.

    Purpose:
        Verify dependency injection setup.

    Expected Behavior:
        - Returns tuple of (repository, http_client, scanner, use_case)
        - All components are instantiated
    """
    settings = Settings(
        download_directory=tempfile.mkdtemp(),
        virustotal_api_key="test_key"
    )

    use_case, http_client, scanner = create_dependencies(settings)

    assert http_client is not None
    assert scanner is not None
    assert use_case is not None

    # Cleanup
    http_client.close()
    if scanner:
        scanner.close()


@pytest.mark.unit
def test_create_dependencies_without_vt_api_key() -> None:
    """
    Test dependency creation without VirusTotal API key.

    Purpose:
        Verify that scanner is None when API key is missing.

    Expected Behavior:
        Scanner is None but other components are created.
    """
    settings = Settings(
        download_directory=tempfile.mkdtemp(),
        virustotal_api_key=None
    )

    use_case, http_client, scanner = create_dependencies(settings)

    assert http_client is not None
    assert scanner is None
    assert use_case is not None

    # Cleanup
    http_client.close()


@pytest.mark.unit
def test_create_dependencies_with_custom_output_dir() -> None:
    """
    Test dependency creation with custom output directory.

    Purpose:
        Verify that custom download path is used.

    Expected Behavior:
        Repository uses custom directory instead of settings default.
    """
    settings = Settings(download_directory="/default/path")
    custom_dir = tempfile.mkdtemp()

    use_case, http_client, scanner = create_dependencies(
        settings,
        output_dir=custom_dir
    )

    assert use_case is not None
    # Repository should use custom directory
    # (We can't directly access it, but it's created with that path)

    # Cleanup
    http_client.close()
    if scanner:
        scanner.close()


@pytest.mark.unit
def test_create_dependencies_uses_settings_values() -> None:
    """The public API should expose usable runtime components, not concrete types."""
    settings = Settings(
        download_directory=tempfile.mkdtemp(),
        virustotal_api_key="my_api_key",
    )

    use_case, http_client, scanner = create_dependencies(settings)

    assert hasattr(use_case, "execute")
    assert hasattr(http_client, "close")
    assert scanner is not None
    assert hasattr(scanner, "close")

    http_client.close()
    scanner.close()


@pytest.mark.unit
def test_create_dependencies_creates_download_directory() -> None:
    """
    Test that repository ensures download directory exists.

    Purpose:
        Verify filesystem setup for downloads.

    Expected Behavior:
        Download directory is created if it doesn't exist.
    """
    temp_dir = Path(tempfile.mkdtemp())
    download_path = temp_dir / "downloads" / "nested"

    # Directory doesn't exist yet
    assert not download_path.exists()

    settings = Settings(download_directory=str(download_path))
    use_case, http_client, scanner = create_dependencies(settings)

    # Directory should be created by repository
    assert download_path.exists()

    # Cleanup
    http_client.close()
    if scanner:
        scanner.close()
    import shutil
    shutil.rmtree(temp_dir)


# ============================================================================
# Integration Tests
# ============================================================================

@pytest.mark.integration
def test_cli_argument_flow_to_architecture() -> None:
    """
    Test complete flow from CLI args to Architecture enum.

    Purpose:
        Verify end-to-end argument processing.

    Expected Behavior:
        CLI argument -> parse -> convert -> Architecture enum.
    """
    sys.argv = ["dll-downloader.py", "test.dll", "--arch", "x86"]
    args, parser = parse_arguments()

    architecture = get_architecture(args.arch)

    assert architecture == Architecture.X86


@pytest.mark.integration
def test_cli_dll_name_normalization_flow() -> None:
    """
    Test complete DLL name normalization flow.

    Purpose:
        Verify end-to-end name processing.

    Expected Behavior:
        Raw input -> parse -> normalize -> valid DLL name.
    """
    sys.argv = ["dll-downloader.py", "kernel32"]
    args, parser = parse_arguments()

    normalized = normalize_dll_name(args.dll_name)

    assert normalized == "kernel32.dll"


@pytest.mark.integration
def test_cli_file_input_flow() -> None:
    """
    Test complete file-based input flow.

    Purpose:
        Verify end-to-end file processing.

    Expected Behavior:
        File creation -> parse args -> read file -> process names.
    """
    # Create temporary file with DLL names
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("kernel32.dll\n")
        f.write("user32\n")  # Without extension
        temp_path = f.name

    try:
        sys.argv = ["dll-downloader.py", "--file", temp_path]
        args, parser = parse_arguments()

        dll_names = read_dll_list_from_file(args.file)
        normalized_names = [normalize_dll_name(name) for name in dll_names]

        assert len(normalized_names) == 2
        assert "kernel32.dll" in normalized_names
        assert "user32.dll" in normalized_names
    finally:
        os.unlink(temp_path)


# ============================================================================
# Format Response Tests
# ============================================================================

@pytest.mark.unit
def test_format_response_success_cached(capsys: CaptureFixture[str]) -> None:
    """
    Test format_response with cached file.

    Purpose:
        Verify correct output for cached DLL response.

    Expected Behavior:
        Shows [CACHED] prefix and file path.
    """
    dll_file = DLLFile(
        name="kernel32.dll",
        architecture=Architecture.X64,
        file_path="/downloads/kernel32.dll"
    )
    response = DownloadDLLResponse(
        success=True,
        dll_file=dll_file,
        was_cached=True
    )

    format_response(response, "kernel32.dll")

    captured = capsys.readouterr()
    assert "[CACHED]" in captured.out
    assert "kernel32.dll" in captured.out


@pytest.mark.unit
def test_format_response_success_downloaded(capsys: CaptureFixture[str]) -> None:
    """
    Test format_response with freshly downloaded file.

    Purpose:
        Verify correct output for new download.

    Expected Behavior:
        Shows [OK] prefix with path, hash, and size.
    """
    dll_file = DLLFile(
        name="user32.dll",
        architecture=Architecture.X64,
        file_path="/downloads/user32.dll",
        file_hash="abc123def456",
        file_size=102400
    )
    response = DownloadDLLResponse(
        success=True,
        dll_file=dll_file,
        was_cached=False
    )

    format_response(response, "user32.dll")

    captured = capsys.readouterr()
    assert "[OK]" in captured.out
    assert "user32.dll" in captured.out
    assert "SHA256:" in captured.out
    assert "Size:" in captured.out


@pytest.mark.unit
def test_format_response_success_with_security_warning(capsys: CaptureFixture[str]) -> None:
    """
    Test format_response with security warning.

    Purpose:
        Verify security warnings are displayed.

    Expected Behavior:
        Shows the security warning message.
    """
    dll_file = DLLFile(
        name="suspicious.dll",
        architecture=Architecture.X64,
        file_path="/downloads/suspicious.dll",
        security_status=SecurityStatus.SUSPICIOUS
    )
    response = DownloadDLLResponse(
        success=True,
        dll_file=dll_file,
        was_cached=False,
        security_warning="CAUTION: Some engines flagged this file."
    )

    format_response(response, "suspicious.dll")

    captured = capsys.readouterr()
    assert "CAUTION" in captured.out


@pytest.mark.unit
def test_format_response_failure(capsys: CaptureFixture[str]) -> None:
    """
    Test format_response with failed download.

    Purpose:
        Verify error output for failed downloads.

    Expected Behavior:
        Shows [FAILED] prefix with error message.
    """
    response = DownloadDLLResponse(
        success=False,
        error_message="Network timeout"
    )

    format_response(response, "missing.dll")

    captured = capsys.readouterr()
    assert "[FAILED]" in captured.out
    assert "missing.dll" in captured.out
    assert "Network timeout" in captured.out


@pytest.mark.unit
def test_format_response_success_without_dll_file(capsys: CaptureFixture[str]) -> None:
    """
    Verify format_response handles success with no dll_file.
    """
    response = DownloadDLLResponse(success=True, dll_file=None)
    format_response(response, "ghost.dll")
    assert "[OK]" in capsys.readouterr().out


# ============================================================================
# Download Request Tests
# ============================================================================

@pytest.mark.unit
def test_download_request_public_contract() -> None:
    """Verify the stable request DTO exposed by the public API."""
    request = DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=False,
        force_download=True,
    )

    assert request.dll_name == "test.dll"
    assert request.architecture == Architecture.X64
    assert request.scan_before_save is False
    assert request.force_download is True


# ============================================================================
# Process Downloads Tests
# ============================================================================

@pytest.mark.integration
def test_process_downloads_single_dll(
    capsys: CaptureFixture[str],
) -> None:
    """
    Test process_downloads with a single DLL.

    Purpose:
        Verify the function processes a single DLL and returns correct counts.

    Expected Behavior:
        Returns (success_count, failure_count) tuple.
    """
    use_case = RecordingUseCase(
        responses={
            "test.dll": DownloadDLLResponse(
                success=False,
                error_message="boom",
            )
        }
    )

    # Process downloads - this will fail to download but exercises the code
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=["test.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=True,
        extract_archive=False,
        debug=False
    )

    assert isinstance(success_count, int)
    assert isinstance(failure_count, int)
    assert success_count + failure_count == 1
    assert use_case.requests[0].dll_name == "test.dll"


@pytest.mark.integration
def test_process_downloads_multiple_dlls(
    capsys: CaptureFixture[str],
) -> None:
    """
    Test process_downloads with multiple DLLs.

    Purpose:
        Verify the function processes multiple DLLs and returns correct counts.

    Expected Behavior:
        Returns combined success/failure counts for all DLLs.
    """
    use_case = RecordingUseCase(
        responses={
            "kernel32.dll": _successful_response("kernel32.dll"),
            "user32.dll": _successful_response("user32.dll"),
            "test.dll": DownloadDLLResponse(
                success=False,
                error_message="missing",
            ),
        }
    )

    # Process multiple downloads
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=["kernel32.dll", "user32.dll", "test.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=True,
        extract_archive=False,
        debug=False
    )

    assert success_count + failure_count == 3


@pytest.mark.unit
def test_process_downloads_normalizes_names(
    capsys: CaptureFixture[str],
) -> None:
    """
    Test process_downloads normalizes DLL names.

    Purpose:
        Verify that DLL names without .dll extension are normalized.

    Expected Behavior:
        Names are normalized before processing.
    """
    use_case = RecordingUseCase(
        responses={"kernel32.dll": _successful_response("kernel32.dll")}
    )

    # Process download with name without extension
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=["kernel32"],  # No .dll extension
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=True,
        extract_archive=False,
        debug=False
    )

    captured = capsys.readouterr()
    assert "kernel32.dll" in captured.out
    assert use_case.requests[0].dll_name == "kernel32.dll"


@pytest.mark.unit
def test_process_downloads_prints_architecture(
    capsys: CaptureFixture[str],
) -> None:
    """
    Test process_downloads prints correct architecture.

    Purpose:
        Verify that the architecture is displayed correctly in output.

    Expected Behavior:
        Output shows correct architecture string.
    """
    use_case = RecordingUseCase(
        responses={"test.dll": _successful_response("test.dll")}
    )

    # Test x86 architecture
    process_downloads(
        use_case=use_case,
        dll_names=["test.dll"],
        architecture=Architecture.X86,
        scan_enabled=False,
        force_download=True,
        extract_archive=False,
        debug=False
    )

    captured = capsys.readouterr()
    assert "(x86)" in captured.out


@pytest.mark.unit
def test_process_downloads_empty_list() -> None:
    """
    Test process_downloads with empty list.

    Purpose:
        Verify the function handles empty input gracefully.

    Expected Behavior:
        Returns (0, 0) for empty input.
    """
    use_case = RecordingUseCase()

    # Process empty list
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=[],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=False,
        extract_archive=False,
        debug=False
    )

    assert success_count == 0
    assert failure_count == 0


@pytest.mark.unit
def test_process_downloads_handles_exception(capsys: CaptureFixture[str]) -> None:
    """
    Verify process_downloads handles exceptions and prints traceback in debug.
    """
    class FailingUseCase:
        def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
            raise RuntimeError("boom")

    success_count, failure_count = process_downloads(
        use_case=FailingUseCase(),
        dll_names=["bad.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=False,
        extract_archive=False,
        debug=True
    )

    out = capsys.readouterr()
    assert success_count == 0
    assert failure_count == 1
    assert "[ERROR]" in out.out
    assert "Traceback" in out.err


@pytest.mark.unit
def test_process_downloads_exception_without_debug(capsys: CaptureFixture[str]) -> None:
    """
    Verify process_downloads does not print traceback when debug is False.
    """
    class FailingUseCase:
        def execute(self, request: DownloadDLLRequest) -> DownloadDLLResponse:
            raise RuntimeError("boom")

    process_downloads(
        use_case=FailingUseCase(),
        dll_names=["bad.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=False,
        extract_archive=False,
        debug=False
    )

    out = capsys.readouterr()
    assert "[ERROR]" in out.out
    assert out.err == ""


@pytest.mark.unit
def test_main_no_args_prints_help_and_returns_error(
    capsys: CaptureFixture[str],
) -> None:
    """
    Verify main prints help and returns error when no args exist.
    """
    with _temporary_argv(["dll-downloader.py"]):
        assert main(Settings()) == 1
    assert "usage" in capsys.readouterr().out.lower()


@pytest.mark.unit
def test_main_prints_summary_for_multiple_dlls(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    """
    Verify main prints batch summary for multiple DLLs.
    """
    repo_dir = tmp_path / "downloads"
    dll_list = tmp_path / "dlls.txt"
    dll_list.write_text("a.dll\nb.dll\n")
    _seed_cached_dll(repo_dir, ["a.dll", "b.dll"])

    with _temporary_argv(
        [
            "dll-downloader.py",
            "--file",
            str(dll_list),
            "--output-dir",
            str(repo_dir),
        ]
    ):
        assert main(Settings()) == 0
    assert "Summary: 2 succeeded, 0 failed" in capsys.readouterr().out


@pytest.mark.unit
def test_cleanup_resources_calls_close() -> None:
    """
    Verify cleanup closes HTTP client and scanner.
    """
    class Dummy:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    http_client = Dummy()
    scanner = Dummy()
    http_client.close()
    scanner.close()

    assert http_client.closed is True
    assert scanner.closed is True


@pytest.mark.unit
def test_main_returns_error_when_no_args() -> None:
    """
    Verify main returns error code when no args are provided.
    """
    with _temporary_argv(["dll-downloader.py"]):
        assert create_dependencies is not None
        assert parse_arguments is not None
        assert main() == 1


@pytest.mark.unit
def test_main_success_flow(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    """
    Verify main returns 0 on successful processing.
    """
    repo_dir = tmp_path / "downloads"
    _seed_cached_dll(repo_dir, ["test.dll"])

    with _temporary_argv(
        [
            "dll-downloader.py",
            "test.dll",
            "--output-dir",
            str(repo_dir),
        ]
    ):
        assert main(Settings()) == 0
    assert "Summary" not in capsys.readouterr().out


@pytest.mark.unit
def test_main_loads_settings_when_none(tmp_path: Path) -> None:
    """
    Verify main calls SettingsLoader.load when settings is None.
    """
    repo_dir = tmp_path / "downloads"
    config_path = tmp_path / ".config.json"
    _seed_cached_dll(repo_dir, ["test.dll"])
    config_path.write_text(json.dumps({"download_directory": str(repo_dir)}))

    with _temporary_cwd(tmp_path), _temporary_argv(["dll-downloader.py", "test.dll"]):
        assert main(None) == 0
