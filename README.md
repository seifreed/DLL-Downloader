# DLL Downloader

A  Python script to automatically search and download DLL files from [DLL-files.com](https://es.dll-files.com/) by specifying one or multiple DLL names. The script simulates a real browser session to bypass anti-bot protections and always fetches the latest available version of the requested DLLs.

## Features
- Download a single DLL or a list from a file
- Handles anti-bot and compression mechanisms
- Always fetches the latest version available
- Saves DLLs in a dedicated `downloads/` folder
- Professional error handling and session management
- **NEW**: Architecture selection (x86/x64)
- **NEW**: VirusTotal malware scanning integration
- **NEW**: Automatic ZIP extraction and hash verification
- **NEW**: Clean output with optional debug mode

## Requirements
- Python 3.13
- requests
- beautifulsoup4

## Installation
```bash
pip install -r requirements.txt
```

## Configuration

1. Copy the example configuration file:
```bash
cp .config.example.json .config.json
```

2. Edit `.config.json` with your settings:

```json
{
    "virustotal": {
        "api_key": "your_virustotal_api_key_here",
        "enabled": true,
        "timeout": 30
    },
    "download": {
        "extract_zip": true,
        "verify_hash": true
    }
}
```

### VirusTotal API Key
To enable malware scanning, you need a VirusTotal API key:
1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from your profile
3. Replace `"your_virustotal_api_key_here"` with your actual API key

**Note**: The `.config.json` file is ignored by git to protect your API key. Use `.config.example.json` as a template.

## How to Get a VirusTotal API Key

To use the VirusTotal integration, you need a free API key. Follow these steps:

1. Go to [https://www.virustotal.com/](https://www.virustotal.com/)
2. Click on **Sign up** (top right) and create a free account, or log in if you already have one.
3. Once logged in, click on your user icon (top right) and select **API key** from the dropdown menu.
4. Copy the API key shown on the page.
5. Paste this key into your `.config.json` file under the `api_key` field:

```json
{
    "virustotal": {
        "api_key": "your_virustotal_api_key_here",
        "enabled": true
    }
}
```

**Note:** The free API key has request limits. For higher usage, consider a paid plan at VirusTotal.

## Usage

### Download a single DLL
```bash
python dll-downloader.py msvcp140.dll
```

### Download with specific architecture
```bash
python dll-downloader.py msvcp140.dll --arch x86
python dll-downloader.py msvcp140.dll --arch x64
```

### Download multiple DLLs from a file
```bash
python dll-downloader.py --file list.txt
```

### Enable debug mode for verbose output
```bash
python dll-downloader.py msvcp140.dll --debug
```

Downloaded DLL files will be saved in the `downloads/` folder.

## Output Examples

### Normal Mode (Default)
```
Filtering for x64 architecture...
Found x64 version: 14.26.28804.1 - 64
Found 29 x64 versions
Downloaded: msvcp140.dll.zip
Extracting DLL from ZIP...
Extracted: msvcp140.dll
Calculating file hash...
SHA-256 Hash: 3c6a772319fff3ee56d4cedbe332bb5c0c2f394714cf473c6cdf933754114784
Checking with VirusTotal...
VirusTotal scan: 0/72 engines detected malware
✅ No malware detected by VirusTotal
```

### Debug Mode (`--debug`)
```
Establishing session...
Searching in: https://es.dll-files.com/search/?q=msvcp140.dll
Status code: 200
Response length: 14983 characters
Content-Encoding: none
Page title: Resultado de búsqueda para msvcp140.dll | DLL‑files.com
Saved page content to debug_page.html for inspection
DLL page: https://es.dll-files.com/msvcp140.dll.html
Saved DLL page content to debug_dll_page.html for inspection
Filtering for x64 architecture...
Found x64 version: 14.26.28804.1 - 64
...
Found 29 x64 versions
Download URL: https://es.dll-files.com/download/...
Direct URL: https://download.zip.dll-files.com/...
Downloaded: msvcp140.dll.zip
Extracting DLL from ZIP...
Extracted: msvcp140.dll
Calculating file hash...
SHA-256 Hash: 3c6a772319fff3ee56d4cedbe332bb5c0c2f394714cf473c6cdf933754114784
Checking with VirusTotal...
VirusTotal scan: 0/72 engines detected malware
✅ No malware detected by VirusTotal
```

## Security Features

The tool includes several security features:

1. **Hash Calculation**: Automatically calculates SHA-256 hash of extracted DLLs
2. **VirusTotal Integration**: Scans downloaded files against 70+ antivirus engines
3. **Malware Detection**: Warns if any antivirus engine detects malware
4. **Safe Extraction**: Extracts DLLs from ZIP files safely

## License
This project is licensed under a permissive Attribution License. If you use this project or substantial portions of it, you **must** give appropriate credit, provide a link to the repository, and indicate if changes were made. See [LICENSE](LICENSE) for details.

## Attribution
Author: Marc Rivero | [@seifreed](https://github.com/seifreed)

Project repository: https://github.com/seifreed/DLL-Downloader 