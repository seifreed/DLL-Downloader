"""
Fail when critical modules exceed agreed size limits.
"""

from __future__ import annotations

import ast
from pathlib import Path

MAX_LINES = {
    "dll_downloader/interfaces/cli.py": 280,
    "dll_downloader/interfaces/cli_runner.py": 340,
    "dll_downloader/api.py": 120,
    "dll_downloader/runtime.py": 140,
    "dll_downloader/infrastructure/composition.py": 140,
    "dll_downloader/infrastructure/http/http_client.py": 220,
}
MAX_FUNCTION_LINES = {
    "dll_downloader/interfaces/cli.py": 80,
    "dll_downloader/interfaces/cli_runner.py": 80,
    "dll_downloader/api.py": 35,
    "dll_downloader/infrastructure/composition.py": 55,
    "dll_downloader/infrastructure/http/http_client.py": 55,
}
MAX_FUNCTION_COMPLEXITY = {
    "dll_downloader/interfaces/cli.py": 6,
    "dll_downloader/interfaces/cli_runner.py": 6,
    "dll_downloader/api.py": 5,
    "dll_downloader/interfaces/presenters/download_presenter.py": 10,
    "dll_downloader/infrastructure/http/http_client.py": 9,
}


def _function_line_violations(file_path: Path, max_lines: int) -> list[str]:
    tree = ast.parse(file_path.read_text(), filename=str(file_path))
    violations: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_lineno = getattr(node, "end_lineno", node.lineno)
        line_count = end_lineno - node.lineno + 1
        if line_count > max_lines:
            violations.append(f"{file_path}: {node.name} -> {line_count} > {max_lines}")

    return violations


def _function_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    complexity = 1
    branch_nodes = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.IfExp,
        ast.Assert,
        ast.Match,
    )

    for child in ast.walk(node):
        if isinstance(child, branch_nodes):
            complexity += 1
        elif isinstance(child, ast.BoolOp):
            complexity += max(0, len(child.values) - 1)
        elif isinstance(child, ast.Try):
            complexity += len(child.handlers) + bool(child.orelse) + bool(child.finalbody)
        elif isinstance(child, ast.comprehension):
            complexity += 1

    return complexity


def _function_complexity_violations(file_path: Path, max_complexity: int) -> list[str]:
    tree = ast.parse(file_path.read_text(), filename=str(file_path))
    violations: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        complexity = _function_complexity(node)
        if complexity > max_complexity:
            violations.append(
                f"{file_path}: {node.name} complexity {complexity} > {max_complexity}"
            )

    return violations


def main() -> int:
    failures: list[str] = []

    for relative_path, max_lines in MAX_LINES.items():
        file_path = Path(relative_path)
        if not file_path.exists():
            failures.append(f"{relative_path}: missing")
            continue
        line_count = len(file_path.read_text().splitlines())
        if line_count > max_lines:
            failures.append(f"{relative_path}: {line_count} > {max_lines}")

    for relative_path, max_lines in MAX_FUNCTION_LINES.items():
        file_path = Path(relative_path)
        if not file_path.exists():
            failures.append(f"{relative_path}: missing")
            continue
        failures.extend(_function_line_violations(file_path, max_lines))

    for relative_path, max_complexity in MAX_FUNCTION_COMPLEXITY.items():
        file_path = Path(relative_path)
        if not file_path.exists():
            failures.append(f"{relative_path}: missing")
            continue
        failures.extend(_function_complexity_violations(file_path, max_complexity))

    if failures:
        print("Module guardrails failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("Module guardrails passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
