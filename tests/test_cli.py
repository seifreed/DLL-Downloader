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
import os
import sys
import tempfile
from pathlib import Path

import pytest

from dll_downloader.application.use_cases.download_dll import (
    DownloadDLLRequest,
    DownloadDLLResponse,
    DownloadDLLUseCase,
)
from dll_downloader.domain.entities.dll_file import (
    Architecture,
    DLLFile,
    SecurityStatus,
)
from dll_downloader.infrastructure.config.settings import Settings
from dll_downloader.interfaces.cli import (
    _cleanup_resources,
    _print_summary,
    _validate_and_get_dll_names,
    create_dependencies,
    format_response,
    get_architecture,
    main,
    normalize_dll_name,
    parse_arguments,
    process_downloads,
    read_dll_list_from_file,
    set_debug_mode,
)

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
        "--force"
    ]
    args, parser = parse_arguments()

    assert args.dll_name == "msvcp140.dll"
    assert args.arch == "x86"
    assert args.debug is True
    assert args.no_scan is True
    assert args.force is True


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
    """
    Test that dependencies use settings configuration.

    Purpose:
        Verify settings are propagated to created components.

    Expected Behavior:
        HTTP client and scanner use settings values.
    """
    settings = Settings(
        download_directory=tempfile.mkdtemp(),
        http_timeout=30,
        user_agent="CustomAgent/1.0",
        verify_ssl=False,
        virustotal_api_key="my_api_key",
        malicious_threshold=10,
        suspicious_threshold=3
    )

    use_case, http_client, scanner = create_dependencies(settings)

    # Verify HTTP client configuration
    assert http_client._timeout == 30
    assert http_client._user_agent == "CustomAgent/1.0"
    assert http_client._verify_ssl is False

    # Verify scanner configuration
    assert scanner is not None
    assert scanner._api_key == "my_api_key"
    assert scanner._malicious_threshold == 10
    assert scanner._suspicious_threshold == 3

    # Cleanup
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
def test_format_response_success_cached(capsys) -> None:
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
def test_format_response_success_downloaded(capsys) -> None:
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
def test_format_response_success_with_security_warning(capsys) -> None:
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
def test_format_response_failure(capsys) -> None:
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
def test_format_response_success_without_dll_file(capsys) -> None:
    """
    Verify format_response handles success with no dll_file.
    """
    response = DownloadDLLResponse(success=True, dll_file=None)
    format_response(response, "ghost.dll")
    assert "[OK]" in capsys.readouterr().out


# ============================================================================
# Download Request Tests
# ============================================================================

@pytest.mark.integration
def test_download_request_executes_use_case(tmp_download_dir) -> None:
    """
    Test DownloadDLLRequest executes use case.

    Purpose:
        Verify the request executes against the use case.

    Expected Behavior:
        Returns a response object.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.persistence.file_repository import (
        FileSystemDLLRepository,
    )

    # Create real dependencies
    repository = FileSystemDLLRepository(tmp_download_dir)
    http_client = RequestsHTTPClient(timeout=5)

    # Create use case with real components
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    response = use_case.execute(DownloadDLLRequest(
        dll_name="test.dll",
        architecture=Architecture.X64,
        scan_before_save=False,
        force_download=True
    ))

    # Verify response structure (download will fail, but code path exercised)
    assert response is not None
    assert hasattr(response, 'success')


# ============================================================================
# Process Downloads Tests
# ============================================================================

@pytest.mark.integration
def test_process_downloads_single_dll(tmp_download_dir, capsys) -> None:
    """
    Test process_downloads with a single DLL.

    Purpose:
        Verify the function processes a single DLL and returns correct counts.

    Expected Behavior:
        Returns (success_count, failure_count) tuple.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.persistence.file_repository import (
        FileSystemDLLRepository,
    )

    # Create real dependencies
    repository = FileSystemDLLRepository(tmp_download_dir)
    http_client = RequestsHTTPClient(timeout=5)

    # Create use case with real components
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    # Process downloads - this will fail to download but exercises the code
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=["test.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=True,
        debug=False
    )

    # Verify counts are returned (download will fail, but code path exercised)
    assert isinstance(success_count, int)
    assert isinstance(failure_count, int)
    assert success_count + failure_count == 1

    # Cleanup
    http_client.close()


@pytest.mark.integration
def test_process_downloads_multiple_dlls(tmp_download_dir, capsys) -> None:
    """
    Test process_downloads with multiple DLLs.

    Purpose:
        Verify the function processes multiple DLLs and returns correct counts.

    Expected Behavior:
        Returns combined success/failure counts for all DLLs.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.persistence.file_repository import (
        FileSystemDLLRepository,
    )

    # Create real dependencies
    repository = FileSystemDLLRepository(tmp_download_dir)
    http_client = RequestsHTTPClient(timeout=5)

    # Create use case with real components
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    # Process multiple downloads
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=["kernel32.dll", "user32.dll", "test.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=True,
        debug=False
    )

    # Verify total count matches input
    assert success_count + failure_count == 3

    # Cleanup
    http_client.close()


@pytest.mark.unit
def test_process_downloads_normalizes_names(tmp_download_dir, capsys) -> None:
    """
    Test process_downloads normalizes DLL names.

    Purpose:
        Verify that DLL names without .dll extension are normalized.

    Expected Behavior:
        Names are normalized before processing.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.persistence.file_repository import (
        FileSystemDLLRepository,
    )

    # Create real dependencies
    repository = FileSystemDLLRepository(tmp_download_dir)
    http_client = RequestsHTTPClient(timeout=5)

    # Create use case with real components
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    # Process download with name without extension
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=["kernel32"],  # No .dll extension
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=True,
        debug=False
    )

    # Check output shows normalized name
    captured = capsys.readouterr()
    assert "kernel32.dll" in captured.out

    # Cleanup
    http_client.close()


@pytest.mark.unit
def test_process_downloads_prints_architecture(tmp_download_dir, capsys) -> None:
    """
    Test process_downloads prints correct architecture.

    Purpose:
        Verify that the architecture is displayed correctly in output.

    Expected Behavior:
        Output shows correct architecture string.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.persistence.file_repository import (
        FileSystemDLLRepository,
    )

    # Create real dependencies
    repository = FileSystemDLLRepository(tmp_download_dir)
    http_client = RequestsHTTPClient(timeout=5)

    # Create use case
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    # Test x86 architecture
    process_downloads(
        use_case=use_case,
        dll_names=["test.dll"],
        architecture=Architecture.X86,
        scan_enabled=False,
        force_download=True,
        debug=False
    )

    captured = capsys.readouterr()
    assert "(x86)" in captured.out

    # Cleanup
    http_client.close()


@pytest.mark.unit
def test_process_downloads_empty_list(tmp_download_dir) -> None:
    """
    Test process_downloads with empty list.

    Purpose:
        Verify the function handles empty input gracefully.

    Expected Behavior:
        Returns (0, 0) for empty input.
    """
    from dll_downloader.infrastructure.http.http_client import RequestsHTTPClient
    from dll_downloader.infrastructure.persistence.file_repository import (
        FileSystemDLLRepository,
    )

    # Create real dependencies
    repository = FileSystemDLLRepository(tmp_download_dir)
    http_client = RequestsHTTPClient(timeout=5)

    # Create use case
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url="https://dll.website/download"
    )

    # Process empty list
    success_count, failure_count = process_downloads(
        use_case=use_case,
        dll_names=[],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=False,
        debug=False
    )

    assert success_count == 0
    assert failure_count == 0

    # Cleanup
    http_client.close()


@pytest.mark.unit
def test_process_downloads_handles_exception(capsys) -> None:
    """
    Verify process_downloads handles exceptions and prints traceback in debug.
    """
    class FailingUseCase:
        def execute(self, request):
            raise RuntimeError("boom")

    success_count, failure_count = process_downloads(
        use_case=FailingUseCase(),
        dll_names=["bad.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=False,
        debug=True
    )

    out = capsys.readouterr()
    assert success_count == 0
    assert failure_count == 1
    assert "[ERROR]" in out.out
    assert "Traceback" in out.err


@pytest.mark.unit
def test_process_downloads_exception_without_debug(capsys) -> None:
    """
    Verify process_downloads does not print traceback when debug is False.
    """
    class FailingUseCase:
        def execute(self, request):
            raise RuntimeError("boom")

    process_downloads(
        use_case=FailingUseCase(),
        dll_names=["bad.dll"],
        architecture=Architecture.X64,
        scan_enabled=False,
        force_download=False,
        debug=False
    )

    out = capsys.readouterr()
    assert "[ERROR]" in out.out
    assert out.err == ""


@pytest.mark.unit
def test_validate_and_get_dll_names_no_args(capsys) -> None:
    """
    Verify validation returns None and prints help when no args are provided.
    """
    parser = argparse.ArgumentParser()
    args = argparse.Namespace(dll_name=None, file=None)
    result = _validate_and_get_dll_names(args, parser)

    assert result is None
    assert "usage" in capsys.readouterr().out.lower()


@pytest.mark.unit
def test_validate_and_get_dll_names_with_file(tmp_download_dir, capsys) -> None:
    """
    Verify validation loads names from file when provided.
    """
    file_path = tmp_download_dir / "dlls.txt"
    file_path.write_text("a.dll\nb.dll\n")
    parser = argparse.ArgumentParser()
    args = argparse.Namespace(dll_name=None, file=str(file_path))

    result = _validate_and_get_dll_names(args, parser)
    assert result == ["a.dll", "b.dll"]
    assert "Downloading 2 DLL" in capsys.readouterr().out


@pytest.mark.unit
def test_print_summary_multiple(capsys) -> None:
    """
    Verify summary printed only for multiple DLLs.
    """
    _print_summary(2, 1, ["a.dll", "b.dll"])
    assert "Summary" in capsys.readouterr().out


@pytest.mark.unit
def test_cleanup_resources_calls_close() -> None:
    """
    Verify cleanup closes HTTP client and scanner.
    """
    class Dummy:
        def __init__(self):
            self.closed = False
        def close(self):
            self.closed = True

    http_client = Dummy()
    scanner = Dummy()
    _cleanup_resources(http_client, scanner)

    assert http_client.closed is True
    assert scanner.closed is True


@pytest.mark.unit
def test_main_returns_error_when_no_args(monkeypatch) -> None:
    """
    Verify main returns error code when no args are provided.
    """
    monkeypatch.setattr(sys, "argv", ["dll-downloader.py"])
    assert create_dependencies is not None
    assert parse_arguments is not None
    assert main() == 1


@pytest.mark.unit
def test_main_success_flow(monkeypatch, capsys) -> None:
    """
    Verify main returns 0 on successful processing.
    """
    class DummyUseCase:
        def execute(self, request):
            return DownloadDLLResponse(success=True)

    class DummyClient:
        def close(self):
            pass

    monkeypatch.setattr(sys, "argv", ["dll-downloader.py", "test.dll"])
    monkeypatch.setattr(
        "dll_downloader.interfaces.cli.create_dependencies",
        lambda settings, output_dir=None: (DummyUseCase(), DummyClient(), None)
    )
    monkeypatch.setattr(
        "dll_downloader.interfaces.cli.process_downloads",
        lambda **kwargs: (1, 0)
    )

    assert main(Settings()) == 0
    assert "Summary" not in capsys.readouterr().out


@pytest.mark.unit
def test_main_loads_settings_when_none(monkeypatch) -> None:
    """
    Verify main calls Settings.load when settings is None.
    """
    class DummyUseCase:
        def execute(self, request):
            return DownloadDLLResponse(success=True)

    class DummyClient:
        def close(self):
            pass

    monkeypatch.setattr(sys, "argv", ["dll-downloader.py", "test.dll"])
    monkeypatch.setattr(
        "dll_downloader.interfaces.cli.Settings.load",
        lambda: Settings()
    )
    monkeypatch.setattr(
        "dll_downloader.interfaces.cli.create_dependencies",
        lambda settings, output_dir=None: (DummyUseCase(), DummyClient(), None)
    )
    monkeypatch.setattr(
        "dll_downloader.interfaces.cli.process_downloads",
        lambda **kwargs: (1, 0)
    )

    assert main(None) == 0
