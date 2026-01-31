#!/usr/bin/env python3
"""DLL Downloader - Professional tool to download DLL files from DLL-files.com.

This module provides a command-line interface for downloading DLL files
from the DLL-files.com website. It supports downloading single DLLs or
multiple DLLs from a file list.

Author: Marc Rivero | @seifreed
License: Attribution License

This is a thin wrapper that delegates to the Clean Architecture implementation.
"""

import sys

from dll_downloader.interfaces.cli import main

if __name__ == "__main__":
    sys.exit(main())
