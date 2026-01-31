"""
Command Line Interface

Provides the CLI entry point for the DLL Downloader application
using Clean Architecture with dependency injection.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from ..application.use_cases.download_dll import (
    DownloadDLLRequest,
    DownloadDLLResponse,
    DownloadDLLUseCase,
)
from ..domain.entities.dll_file import Architecture, normalize_dll_name
from ..infrastructure.config.settings import Settings
from ..infrastructure.http.dll_files_resolver import DllFilesResolver
from ..infrastructure.http.http_client import RequestsHTTPClient
from ..infrastructure.persistence.file_repository import FileSystemDLLRepository
from ..infrastructure.services.virustotal import VirusTotalScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger(__name__)


def parse_arguments() -> tuple[argparse.Namespace, argparse.ArgumentParser]:
    """
    Parse and return command line arguments.

    Creates an argument parser with options for specifying DLL names,
    input files, target architecture, and debug mode.

    Returns:
        A tuple containing the parsed arguments namespace and the parser object.
    """
    parser = argparse.ArgumentParser(
        description="Download DLL files from DLL-files.com",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dll-downloader.py msvcp140.dll
  python3 dll-downloader.py msvcp140.dll --arch x86
  python3 dll-downloader.py --file dll_list.txt
  python3 dll-downloader.py msvcp140.dll --debug
  python3 dll-downloader.py msvcp140.dll --no-scan
        """
    )

    parser.add_argument(
        'dll_name',
        nargs='?',
        help='Name of the DLL to download (e.g., msvcp140.dll)'
    )

    parser.add_argument(
        '--file',
        help='File containing a list of DLL names (one per line)'
    )

    parser.add_argument(
        '--arch',
        choices=['x86', 'x64'],
        default='x64',
        help='Target architecture (default: x64)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode for verbose output'
    )

    parser.add_argument(
        '--no-scan',
        action='store_true',
        help='Skip VirusTotal security scanning'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Force download even if file already exists locally'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        help='Custom output directory for downloads'
    )

    return parser.parse_args(), parser


def set_debug_mode(enabled: bool) -> None:
    """
    Set debug mode environment variable and logging level.

    Args:
        enabled: Whether to enable debug mode.
    """
    os.environ['DEBUG_MODE'] = '1' if enabled else '0'
    if enabled:
        logging.getLogger().setLevel(logging.DEBUG)


def read_dll_list_from_file(file_path: str) -> list[str]:
    """
    Read DLL names from a file, one per line.

    Args:
        file_path: Path to the file containing DLL names.

    Returns:
        A list of DLL names read from the file.

    Raises:
        SystemExit: If the file does not exist or is empty.
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)

    with open(file_path) as f:
        dll_names = [line.strip() for line in f if line.strip()]

    if not dll_names:
        print(f"Error: File '{file_path}' is empty or contains no valid DLL names.")
        sys.exit(1)

    return dll_names


def get_architecture(arch_str: str) -> Architecture:
    """
    Convert architecture string to Architecture enum.

    Args:
        arch_str: Architecture string ('x86' or 'x64')

    Returns:
        Architecture enum value
    """
    return {
        'x86': Architecture.X86,
        'x64': Architecture.X64,
    }.get(arch_str, Architecture.X64)


def format_response(response: DownloadDLLResponse, dll_name: str) -> None:
    """
    Format and print the download response to console.

    Args:
        response: The download response from the use case
        dll_name: Name of the DLL that was requested
    """
    if not response.success:
        print(f"[FAILED] {dll_name}: {response.error_message}")
        return

    dll_file = response.dll_file
    lines = []
    if response.was_cached:
        if not dll_file:
            print(f"[FAILED] {dll_name}: cached file info missing")
            return
        lines.append(f"[CACHED] {dll_name} already exists at: {dll_file.file_path}")
    else:
        lines.append(f"[OK] Downloaded: {dll_name}")
        if dll_file:
            lines.append(f"     Path: {dll_file.file_path}")
            if dll_file.file_hash:
                lines.append(f"     SHA256: {dll_file.file_hash}")
            if dll_file.file_size:
                lines.append(f"     Size: {dll_file.file_size / 1024:.2f} KB")

    if response.security_warning:
        lines.append(f"     {response.security_warning}")

    print("\n".join(lines))


def create_dependencies(
    settings: Settings,
    output_dir: str | None = None,
) -> tuple[DownloadDLLUseCase, RequestsHTTPClient, VirusTotalScanner | None]:
    """
    Create and wire up all dependencies using manual DI.

    Args:
        settings: Application settings
        output_dir: Optional custom output directory

    Returns:
        Tuple of (repository, http_client, scanner, use_case)
    """
    # Determine download directory
    download_path = Path(output_dir) if output_dir else settings.downloads_path

    # Create repository
    repository = FileSystemDLLRepository(download_path)

    # Create HTTP client
    http_client = RequestsHTTPClient(
        timeout=settings.http_timeout,
        user_agent=settings.user_agent,
        verify_ssl=settings.verify_ssl
    )

    # Create scanner (optional, based on API key availability)
    scanner = None
    if settings.virustotal_api_key:
        scanner = VirusTotalScanner(
            api_key=settings.virustotal_api_key,
            malicious_threshold=settings.malicious_threshold,
            suspicious_threshold=settings.suspicious_threshold
        )

    # Create use case
    use_case = DownloadDLLUseCase(
        repository=repository,
        http_client=http_client,
        download_base_url=settings.download_base_url,
        scanner=scanner,
        resolver=DllFilesResolver(
            base_url=settings.download_base_url,
            timeout=settings.http_timeout,
        )
    )

    return use_case, http_client, scanner


def process_downloads(
    use_case: DownloadDLLUseCase,
    dll_names: list[str],
    architecture: Architecture,
    scan_enabled: bool,
    force_download: bool,
    debug: bool = False
) -> tuple[int, int]:
    """
    Process a list of DLL downloads.

    Args:
        use_case: The download use case
        dll_names: List of DLL names to download
        architecture: Target CPU architecture
        scan_enabled: Whether to scan with VirusTotal
        force_download: Force download even if cached
        debug: Enable debug mode for verbose error output

    Returns:
        Tuple of (success_count, failure_count)
    """
    success_count = 0
    failure_count = 0
    arch_str = "x86" if architecture == Architecture.X86 else "x64"

    for dll_name in dll_names:
        normalized_name = normalize_dll_name(dll_name)
        print(f"\nSearching and downloading: {normalized_name} ({arch_str})")

        try:
            response = use_case.execute(DownloadDLLRequest(
                dll_name=normalized_name,
                architecture=architecture,
                scan_before_save=scan_enabled,
                force_download=force_download
            ))
            format_response(response, normalized_name)

            success_count += int(response.success)
            failure_count += int(not response.success)

        except Exception as e:
            print(f"[ERROR] {normalized_name}: {e}")
            failure_count += 1
            if debug:
                import traceback
                traceback.print_exc()

    return success_count, failure_count


def _validate_and_get_dll_names(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser
) -> list[str] | None:
    """
    Validate arguments and return DLL names to download.

    Args:
        args: Parsed command line arguments
        parser: The argument parser for help display

    Returns:
        List of DLL names to download, or None if validation fails
    """
    if not args.dll_name and not args.file:
        parser.print_help()
        return None

    if args.file:
        dll_names = read_dll_list_from_file(args.file)
        print(f"Downloading {len(dll_names)} DLL(s) from '{args.file}'...")
        return dll_names

    return [normalize_dll_name(args.dll_name)]


def _print_summary(
    success_count: int,
    failure_count: int,
    dll_names: list[str]
) -> None:
    """
    Print final download summary for multiple DLLs.

    Args:
        success_count: Number of successful downloads
        failure_count: Number of failed downloads
        dll_names: List of DLL names that were processed
    """
    if len(dll_names) > 1:
        print(f"\nSummary: {success_count} succeeded, {failure_count} failed")


def _cleanup_resources(
    http_client: RequestsHTTPClient,
    scanner: VirusTotalScanner | None
) -> None:
    """
    Close HTTP client and scanner resources properly.

    Args:
        http_client: The HTTP client to close
        scanner: Optional VirusTotal scanner to close
    """
    http_client.close()
    if scanner:
        scanner.close()


def main(settings: Settings | None = None) -> int:
    """
    CLI entry point using Clean Architecture.

    Args:
        settings: Optional settings instance for dependency injection.
                  If None, settings are loaded from environment/config files.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    args, parser = parse_arguments()
    set_debug_mode(args.debug)

    dll_names = _validate_and_get_dll_names(args, parser)
    if dll_names is None:
        return 1

    if settings is None:
        settings = Settings.load()

    use_case, http_client, scanner = create_dependencies(
        settings,
        output_dir=args.output_dir
    )

    architecture = get_architecture(args.arch)
    scan_enabled = not args.no_scan and scanner is not None

    try:
        success_count, failure_count = process_downloads(
            use_case=use_case,
            dll_names=dll_names,
            architecture=architecture,
            scan_enabled=scan_enabled,
            force_download=args.force,
            debug=args.debug
        )
    finally:
        _cleanup_resources(http_client, scanner)

    _print_summary(success_count, failure_count, dll_names)
    return 0 if failure_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
