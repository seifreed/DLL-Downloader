# Contributing to DLL-Downloader

Thanks for your interest in improving DLL-Downloader. This document explains how
to report problems, propose changes, and the standards a contribution must meet
to be accepted.

## Reporting Bugs and Requesting Features

- **Bugs and feature requests** are tracked as
  [GitHub issues](https://github.com/seifreed/DLL-Downloader/issues). Search the
  existing issues first; if none match, open a new one with enough detail to
  reproduce or understand the request.
- **Security vulnerabilities** must **not** be filed as public issues. Follow
  the private process in [SECURITY.md](SECURITY.md).

## Proposing Changes

This project uses the standard GitHub fork-and-pull-request workflow:

1. Fork the repository and create a topic branch from `main`.
2. Make your change with focused, coherent commits.
3. Open a pull request describing **why** the change is needed, **what** it
   does, and the validation you performed. The
   [pull request template](.github/pull_request_template.md) lists what to include.
4. Discussion and review happen on the pull request.

Use short, imperative commit messages (e.g. `Refine HTTP transport contracts`).

## Development Setup

```bash
pip install -e .[dev]
pre-commit install        # optional: runs the hook suite on each commit
```

## Contribution Requirements

All changes must pass the same checks CI enforces. Run them locally before
opening a pull request:

| Concern            | Command                                              |
| ------------------ | ---------------------------------------------------- |
| Lint               | `ruff check .`                                       |
| Formatting         | `ruff format --check .`                              |
| Static typing      | `mypy dll_downloader tests` (strict)                 |
| Design/logic lint  | `pylint dll_downloader`                              |
| Security lint      | `bandit -c pyproject.toml -r dll_downloader`         |
| Dependency audit   | `pip-audit`                                          |
| Tests + coverage   | `pytest --cov=dll_downloader --cov-report=term-missing` |
| Critical coverage  | `python scripts/check_critical_coverage.py`          |
| Module guardrails  | `python scripts/check_module_guardrails.py`          |

Additional expectations:

- Target Python **3.13** and **3.14** only; use explicit type hints.
- Keep business logic in `application/`, CLI formatting in `interfaces/`, and
  transport details in `infrastructure/` (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)).
- Do not suppress findings inline (`# noqa`, `# nosec`, `# pragma: no cover`,
  `# pylint: disable`) or weaken checks to make them pass; fix the underlying issue.
- Do not hardcode secrets. JSON/SARIF output is a machine-readable contract;
  keep `stdout` clean in those modes.
- When changing architecture, the public API, or structured output, update the
  relevant docs in `docs/` and ADRs in `docs/adr/`.

## Testing Policy

Tests are required, not optional:

- As major new functionality or behavior is added, **tests covering it MUST be
  added** to the automated suite (`tests/`) in the same change.
- Every bug fix MUST include a regression test that fails without the fix.
- Tests must exercise real code paths; avoid mocks and `monkeypatch` except for
  narrow, unavoidable fault injection.
- The repository enforces **100% coverage** across `dll_downloader/`; new code
  must keep it at 100%.

## Code of Conduct

Be respectful and constructive in all project spaces. Reports of unacceptable
behavior can be sent to **mriverolopez@gmail.com**.
