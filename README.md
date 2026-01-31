<p align="center">
  <img src="https://img.shields.io/badge/DLL--Downloader-Windows%20DLLs-blue?style=for-the-badge" alt="DLL-Downloader">
</p>

<h1 align="center">DLL-Downloader</h1>

<p align="center">
  <strong>Search, download, and optionally scan DLL files with VirusTotal</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/dll-downloader/"><img src="https://img.shields.io/pypi/v/dll-downloader?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/dll-downloader/"><img src="https://img.shields.io/pypi/pyversions/dll-downloader?style=flat-square&logo=python&logoColor=white" alt="Python Versions"></a>
  <a href="https://github.com/seifreed/DLL-Downloader/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT%20%2B%20Attribution-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/DLL-Downloader/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/DLL-Downloader/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/DLL-Downloader/stargazers"><img src="https://img.shields.io/github/stars/seifreed/DLL-Downloader?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/DLL-Downloader/issues"><img src="https://img.shields.io/github/issues/seifreed/DLL-Downloader?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**DLL-Downloader** is a Python tool that searches and downloads DLL files from trusted sources and can optionally scan them using VirusTotal. It works as both a CLI tool and a Python library.

### Key Features

| Feature | Description |
|---------|-------------|
| **Search & Download** | Resolve DLL names and download the correct file |
| **Architecture Support** | x86 and x64 downloads |
| **VirusTotal Scan** | Optional security scan before saving |
| **Batch Mode** | Download many DLLs from a file |
| **Library Mode** | Use the downloader directly from Python |
| **Clean Architecture** | Domain/use-case/infrastructure separation |

---

## Installation

### From PyPI (Recommended)

```bash
pip install dll-downloader
```

### From Source

```bash
git clone https://github.com/seifreed/DLL-Downloader.git
cd DLL-Downloader
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

---

## Configuration

You can configure settings using `.config.json`, environment variables, or `~/.vt.toml`.

### JSON config (`.config.json`)

```json
{
  "virustotal_api_key": "your_virustotal_api_key_here",
  "download_directory": "./downloads",
  "download_base_url": "https://es.dll-files.com",
  "http_timeout": 60,
  "verify_ssl": true,
  "scan_before_save": true,
  "malicious_threshold": 5,
  "suspicious_threshold": 1,
  "log_level": "INFO",
  "user_agent": null
}
```

### VirusTotal key via `~/.vt.toml`

```toml
apikey="your_virustotal_api_key_here"
```

### Environment variables

```bash
export DLL_VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
export DLL_DOWNLOAD_DIRECTORY="./downloads"
```

---

## Quick Start

```bash
# Download a single DLL
python3 dll-downloader.py msvcp140.dll

# Download x86
python3 dll-downloader.py msvcp140.dll --arch x86

# Download from a list
python3 dll-downloader.py --file dll_list.txt
```

---

## Usage

### Command Line Interface

```bash
python3 dll-downloader.py <dll_name> [options]
```

### Available Options

| Option | Description |
|--------|-------------|
| `--file` | File with one DLL name per line |
| `--arch` | Target architecture (`x86` or `x64`) |
| `--debug` | Enable debug output |
| `--no-scan` | Skip VirusTotal scan |
| `--force` | Force download even if cached |
| `--output-dir` | Custom output directory |

---

## Python Library

### Basic Usage

```python
from dll_downloader.application.use_cases.download_dll import DownloadDLLUseCase, DownloadDLLRequest
from dll_downloader.infrastructure.config.settings import Settings
from dll_downloader.interfaces.cli import create_dependencies
from dll_downloader.domain.entities.dll_file import Architecture

settings = Settings.load()
use_case, http_client, scanner = create_dependencies(settings)

try:
    response = use_case.execute(DownloadDLLRequest(
        dll_name="msvcp140.dll",
        architecture=Architecture.X64,
        scan_before_save=True,
        force_download=False,
    ))
    print(response)
finally:
    http_client.close()
    if scanner:
        scanner.close()
```

---

## Requirements

- Python 3.10+
- See `pyproject.toml` for dependencies

---

## Contributing

Contributions are welcome. Please open a PR with clear changes and tests if needed.

---

## Support the Project

If you find DLL-Downloader useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

See the [LICENSE](LICENSE) file for details.

**Attribution Required:**
- Author: **Marc Rivero Lopez**
- Repository: [github.com/seifreed/DLL-Downloader](https://github.com/seifreed/DLL-Downloader)

---

<p align="center">
  <sub>Built for secure, reliable DLL acquisition</sub>
</p>
