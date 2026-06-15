"""Allow running the package with ``python -m dll_downloader``."""

from .interfaces.cli import main


def run() -> None:
    """Run the CLI and raise SystemExit with its return code."""
    raise SystemExit(main())


# This module is only ever loaded as the package entry point
# (``python -m dll_downloader``), never imported, so no ``__main__`` guard is
# needed -- adding one would leave a permanently unreachable branch.
run()
