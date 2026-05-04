"""Allow running the package with ``python -m dll_downloader``."""

from .interfaces.cli import main


def run() -> None:
    """Run the CLI and raise SystemExit with its return code."""
    raise SystemExit(main())


if __name__ == "__main__":
    run()
