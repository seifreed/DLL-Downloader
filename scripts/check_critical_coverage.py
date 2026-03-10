"""
Fail when critical architectural modules fall below per-file coverage thresholds.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

THRESHOLDS = {
    "bootstrap.py": (0.9, 0.9),
    "api.py": (1.0, 1.0),
    "interfaces/cli_runner.py": (0.84, 0.55),
    "application/use_cases/download_dll.py": (0.94, 0.95),
    "infrastructure/composition.py": (0.9, 0.9),
    "infrastructure/config/loader.py": (1.0, 1.0),
    "infrastructure/http/dll_files_resolver.py": (1.0, 1.0),
    "infrastructure/persistence/file_repository.py": (0.93, 0.8),
    "infrastructure/services/virustotal.py": (0.94, 0.8),
}


def main() -> int:
    coverage_file = Path("coverage.xml")
    if not coverage_file.exists():
        print("coverage.xml not found")
        return 1

    root = ET.parse(coverage_file).getroot()
    measured: dict[str, tuple[float, float]] = {}

    for class_node in root.findall(".//class"):
        filename = class_node.attrib.get("filename")
        line_rate = class_node.attrib.get("line-rate")
        branch_rate = class_node.attrib.get("branch-rate")
        if filename is None or line_rate is None or branch_rate is None:
            continue
        measured[filename] = (float(line_rate), float(branch_rate))

    failures = [
        (
            f"{path}: line {measured.get(path, (0.0, 0.0))[0]:.2%} < {thresholds[0]:.0%}"
            if measured.get(path, (0.0, 0.0))[0] < thresholds[0]
            else f"{path}: branch {measured.get(path, (0.0, 0.0))[1]:.2%} < {thresholds[1]:.0%}"
        )
        for path, thresholds in THRESHOLDS.items()
        if (
            measured.get(path, (0.0, 0.0))[0] < thresholds[0]
            or measured.get(path, (0.0, 0.0))[1] < thresholds[1]
        )
    ]

    if failures:
        print("Critical coverage thresholds failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Critical coverage thresholds passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
