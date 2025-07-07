# DLL Downloader

A professional Python tool to automatically search and download DLL files from [DLL-files.com](https://es.dll-files.com/) by specifying one or multiple DLL names. The script simulates a real browser session to bypass anti-bot protections and always fetches the latest available version of the requested DLLs.

## Features
- Download a single DLL or a list from a file
- Handles anti-bot and compression mechanisms
- Always fetches the latest version available
- Saves DLLs in a dedicated `downloads/` folder
- Professional error handling and session management

## Requirements
- Python 3.13
- requests
- beautifulsoup4

## Installation
```bash
pip install -r requirements.txt
```

## Usage

### Download a single DLL
```bash
python dll-downloader.py msvcp140.dll
```

### Download multiple DLLs from a file
```bash
python dll-downloader.py --file list.txt
```

Downloaded DLL files will be saved in the `downloads/` folder.

## License
This project is licensed under a permissive Attribution License. If you use this project or substantial portions of it, you **must** give appropriate credit, provide a link to the repository, and indicate if changes were made. See [LICENSE](LICENSE) for details.

## Attribution
Author: Marc Rivero | [@seifreed](https://github.com/seifreed)

Project repository: https://github.com/seifreed/DLL-Downloader 