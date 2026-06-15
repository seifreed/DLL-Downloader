#!/usr/bin/env python3
"""Enforce the SBOM quality contract: 10.0/10.0 Grade A on every profile.

Runs ``sbomqs score`` against the committed CycloneDX SBOM and fails if any
required profile (NTIA and BSI TR-03183-2) scores below a perfect 10.0/A.

Usage:
    python scripts/check_sbom_quality.py [sbom.cdx.json]
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REQUIRED_PROFILES = (
    "ntia",
    "ntia-2025",
    "bsi-v1.1",
    "bsi-v2.0",
    "bsi-v2.1",
)
REQUIRED_SCORE = 10.0
REQUIRED_GRADE = "A"


def score_sbom(sbom_path: str) -> list[dict[str, Any]]:
    """Run sbomqs and return the per-profile score entries."""
    sbomqs = shutil.which("sbomqs")
    if sbomqs is None:
        raise SystemExit("sbomqs not found on PATH; install it to score the SBOM")
    completed = subprocess.run(
        [
            sbomqs,
            "score",
            "--json",
            "--profile",
            ",".join(REQUIRED_PROFILES),
            sbom_path,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads(completed.stdout)
    files = report.get("files") or []
    if not files:
        raise SystemExit(f"sbomqs produced no results for {sbom_path}")
    profiles = files[0].get("profiles") or []
    return list(profiles)


def main() -> int:
    sbom_path = sys.argv[1] if len(sys.argv) > 1 else "sbom.cdx.json"
    if not Path(sbom_path).is_file():
        print(f"SBOM not found: {sbom_path}", file=sys.stderr)
        return 1

    profiles = score_sbom(sbom_path)
    failures: list[str] = []
    for entry in profiles:
        name = str(entry.get("profile", "?"))
        score = float(entry.get("score", 0.0))
        grade = str(entry.get("grade", "?"))
        status = "OK" if score >= REQUIRED_SCORE and grade == REQUIRED_GRADE else "FAIL"
        print(f"[{status}] {name}: {score:.1f}/10.0 Grade {grade}")
        if status == "FAIL":
            failures.append(f"{name} ({score:.1f}/10.0 Grade {grade})")

    if failures:
        print(
            "\nSBOM quality below 10.0/A for: " + ", ".join(failures),
            file=sys.stderr,
        )
        return 1
    print("\nSBOM quality contract met: 10.0/10.0 Grade A on all profiles.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
