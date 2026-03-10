"""
Fail when structural code changes are not accompanied by architecture/doc updates.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

STRUCTURAL_PATH_PREFIXES = (
    "dll_downloader/__init__.py",
    "dll_downloader/api.py",
    "dll_downloader/bootstrap.py",
    "dll_downloader/infrastructure/composition.py",
    "dll_downloader/interfaces/cli.py",
    "dll_downloader/interfaces/cli_contracts.py",
    "dll_downloader/interfaces/cli_output.py",
    "dll_downloader/interfaces/cli_runner.py",
    "dll_downloader/interfaces/presenters/download_presenter.py",
    "dll_downloader/interfaces/__init__.py",
)
REQUIRED_DOC_PREFIXES = (
    "ARCHITECTURE.md",
    "docs/GOVERNANCE.md",
    "docs/PUBLIC_API.md",
    "docs/adr/",
)
STRUCTURAL_DIFF_MARKERS = (
    "__all__",
    "__version__",
    "API_VERSION",
    "build_download_application",
    "build_default_download_application",
    "DownloadApplicationAssembler",
    "DownloadComponentFactory",
)


def _git_output(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args],
        cwd=PROJECT_ROOT,
        text=True,
    ).strip()


def _first_existing_ref(candidates: list[str]) -> str | None:
    for candidate in candidates:
        try:
            _git_output("rev-parse", "--verify", candidate)
        except subprocess.CalledProcessError:
            continue
        return candidate
    return None


def _comparison_base() -> str | None:
    base_ref = os.environ.get("GITHUB_BASE_REF")
    candidate_refs = (
        [f"origin/{base_ref}", base_ref]
        if base_ref
        else ["origin/main", "main"]
    )
    merge_target = _first_existing_ref(candidate_refs)
    if merge_target is not None:
        try:
            return _git_output("merge-base", "HEAD", merge_target)
        except subprocess.CalledProcessError:
            pass

    return _first_existing_ref(["HEAD~1"])


def _changed_files() -> list[str]:
    base = _comparison_base()
    if base is None:
        return []

    output = _git_output("diff", "--name-only", f"{base}..HEAD")
    return [line.strip() for line in output.splitlines() if line.strip()]


def _diff_contains_structural_markers(base: str, relative_path: str) -> bool:
    diff_text = _git_output("diff", "--unified=0", f"{base}..HEAD", "--", relative_path)
    return any(marker in diff_text for marker in STRUCTURAL_DIFF_MARKERS)


def main() -> int:
    base = _comparison_base()
    if base is None:
        print("Structural doc sync skipped: no comparable git diff range.")
        return 0

    changed_files = _changed_files()
    if not changed_files:
        print("Structural doc sync passed: no structural code changes detected.")
        return 0

    structural_changes = [
        path
        for path in changed_files
        if path.startswith(STRUCTURAL_PATH_PREFIXES)
        or _diff_contains_structural_markers(base, path)
    ]
    if not structural_changes:
        print("Structural doc sync passed: no structural code changes detected.")
        return 0

    touched_docs = [
        path
        for path in changed_files
        if path.startswith(REQUIRED_DOC_PREFIXES)
    ]
    if touched_docs:
        print("Structural doc sync passed.")
        return 0

    print("Structural doc sync failed:")
    print("- Structural code changed without ADR/architecture/public API documentation updates")
    print(f"- Comparison base: {base}")
    for path in structural_changes:
        print(f"- {path}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
