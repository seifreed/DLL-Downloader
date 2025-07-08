#!/usr/bin/env python3
"""
DLL Downloader - Professional tool to download DLL files from DLL-files.com
Author: Marc Rivero | @seifreed
License: Attribution License
"""

import sys
import os
import argparse
from downloader import download_dlls

def main():
    parser = argparse.ArgumentParser(
        description="Download DLL files from DLL-files.com",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 dll-downloader.py msvcp140.dll
  python3 dll-downloader.py msvcp140.dll --arch x86
  python3 dll-downloader.py --file dll_list.txt
  python3 dll-downloader.py msvcp140.dll --debug
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
    
    args = parser.parse_args()
    
    # Set debug mode globally
    if args.debug:
        os.environ['DEBUG_MODE'] = '1'
    else:
        os.environ['DEBUG_MODE'] = '0'
    
    # Create downloads directory if it doesn't exist
    download_dir = 'downloads'
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)
    
    if args.file:
        # Download DLLs from file
        if not os.path.exists(args.file):
            print(f"Error: File '{args.file}' not found.")
            sys.exit(1)
        
        with open(args.file, 'r') as f:
            dll_names = [line.strip() for line in f if line.strip()]
        
        if not dll_names:
            print(f"Error: File '{args.file}' is empty or contains no valid DLL names.")
            sys.exit(1)
        
        print(f"Downloading {len(dll_names)} DLL(s) from '{args.file}'...")
        download_dlls(dll_names, download_dir, args.arch)
        
    elif args.dll_name:
        # Download single DLL
        if not args.dll_name.lower().endswith('.dll'):
            args.dll_name += '.dll'
        
        download_dlls([args.dll_name], download_dir, args.arch)
        
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main() 