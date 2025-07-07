import argparse
import os
from downloader import download_dlls

def parse_args():
    parser = argparse.ArgumentParser(description='Download DLLs from es.dll-files.com')
    parser.add_argument('dll', nargs='?', help='Name of the DLL file to download')
    parser.add_argument('--file', '-f', help='Text file with list of DLLs (one per line)')
    return parser.parse_args()

def main():
    args = parse_args()
    dlls = []
    if args.file:
        with open(args.file, 'r') as f:
            dlls = [line.strip() for line in f if line.strip()]
    elif args.dll:
        dlls = [args.dll]
    else:
        print('You must specify a DLL name or a file with the --file option')
        return

    os.makedirs('downloads', exist_ok=True)
    download_dlls(dlls, 'downloads')

if __name__ == '__main__':
    main() 