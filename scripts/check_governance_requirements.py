"""
Fail when governance source-of-truth files stop expressing required policy hooks.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    "docs/ARCHITECTURE.md": (
        "dll_downloader.api",
        "dll_downloader.interfaces.cli",
        "current source of truth",
    ),
    "docs/PUBLIC_API.md": (
        "dll_downloader.api",
        "dll_downloader.interfaces.cli",
        "Versioning Policy",
        "Breaking changes",
        "stable public API for the full `1.x` line",
    ),
    "docs/GOVERNANCE.md": (
        "ADR",
        "docs/ARCHITECTURE.md",
        "Public API",
        "docs/PUBLIC_API.md",
    ),
    ".github/pull_request_template.md": (
        "ADR",
        "docs/ARCHITECTURE.md",
        "Public API",
        "docs/PUBLIC_API.md",
        "forbidden layer imports",
    ),
    "docs/adr/README.md": (
        "Superseded",
        "Accepted",
        "Update this README index",
    ),
}


def main() -> int:
    failures: list[str] = []

    for relative_path, required_fragments in REQUIRED_FILES.items():
        file_path = PROJECT_ROOT / relative_path
        if not file_path.exists():
            failures.append(f"{relative_path}: missing")
            continue
        text = file_path.read_text()
        missing_fragments = [
            fragment for fragment in required_fragments if fragment not in text
        ]
        if missing_fragments:
            failures.append(
                f"{relative_path}: missing {', '.join(sorted(missing_fragments))}"
            )

    if failures:
        print("Governance guardrails failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Governance guardrails passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
