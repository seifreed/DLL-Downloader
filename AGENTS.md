# Repository Guidelines

## Project Structure & Module Organization

- `dll_downloader/`: application code.
  - `domain/`: entities, ports, domain services.
  - `application/`: use cases and application errors.
  - `infrastructure/`: HTTP, persistence, config, production wiring.
  - `interfaces/`: CLI entrypoint, formatters, presenters.
- `tests/`: unit, integration, architecture, and CLI tests.
- `docs/`: architecture, governance, public API, structured-output contracts, ADRs.
- `.github/workflows/`: CI and publish pipelines.

## Build, Test, and Development Commands

- `pip install -e .[dev]`: install the package and development tooling.
- `python3 dll-downloader.py msvcp140.dll --extract`: run the CLI locally.
- `ruff check .`: lint Python code.
- `mypy dll_downloader tests`: run strict type checks.
- `pytest -q`: run the full test suite.
- `pytest --cov=dll_downloader --cov-report=term-missing -q`: run tests with coverage.
- `python scripts/check_critical_coverage.py`: enforce critical-module coverage.
- `python scripts/check_module_guardrails.py`: enforce file/function size and complexity limits.

## Coding Style & Naming Conventions

- Target Python: `3.13` and `3.14` only.
- Use 4-space indentation and explicit type hints.
- Follow `ruff` and `mypy --strict`; keep imports clean and public exports explicit.
- Prefer descriptive names: `DownloadDLLUseCase`, `RetryPolicy`, `RequestHeaderBuilder`.
- Keep business logic in `application/`; keep CLI formatting in `interfaces/`; keep transport details in `infrastructure/`.

## Testing Guidelines

- Framework: `pytest`.
- Tests must exercise real code paths; avoid mocks and `monkeypatch`.
- Name test files `test_*.py` and test functions `test_<behavior>()`.
- Add focused tests for new branches and contract changes, especially for CLI JSON/SARIF output and HTTP transport behavior.
- The repository currently enforces `100%` coverage across `dll_downloader/`.

## Commit & Pull Request Guidelines

- Use short imperative commit messages, e.g. `Refine HTTP transport and structured output contracts`.
- Keep commits coherent: one change set per concern.
- PRs should explain the why, list validation performed, and note contract changes.
- When changing architecture, public API, or structured output, update:
  - `docs/ARCHITECTURE.md`
  - `docs/PUBLIC_API.md`
  - `docs/STRUCTURED_OUTPUTS.md`
  - relevant ADRs in `docs/adr/`

## Security & Configuration Tips

- Do not hardcode API keys. Use environment variables or config files.
- Main config lives in JSON/env-based settings; see `dll_downloader/infrastructure/config/`.
- JSON and SARIF modes are pipeline-facing contracts: keep `stdout` clean and machine-readable.
