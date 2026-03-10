# Architecture

This document is the current source of truth for the runtime architecture.

## Layers

- `dll_downloader.domain`
  - Entities, service contracts, repository contracts, domain-level errors.
- `dll_downloader.application`
  - Use cases and application-level orchestration rules.
- `dll_downloader.infrastructure`
  - Concrete adapters, config loading, persistence, HTTP, security services, production composition.
- `dll_downloader.interfaces`
  - CLI entrypoint, argument normalization, presenters, boundary translation.

## Current Boundaries

- `domain` must not import `application`, `infrastructure`, or `interfaces`.
- `application` depends on domain contracts, not concrete adapters.
- `infrastructure` implements ports and owns production wiring in `infrastructure/composition.py`.
- `interfaces/cli.py` is an entrypoint adapter, not a library façade.
- Programmatic integration uses `dll_downloader.api`.
- `Settings` is a data model only; loading lives in `SettingsLoader` and the public `load_settings()` wrapper.

## Supported Public API

- Stable library API: `dll_downloader.api`
- Stable default runtime helpers: `dll_downloader.runtime`
- Stable CLI entrypoint: `dll_downloader.interfaces.cli:main`
- Stable symbol list and compatibility rules live in `docs/PUBLIC_API.md`
- Stable machine-readable CLI output contract lives in `docs/STRUCTURED_OUTPUTS.md`
- `Settings` remains part of the supported public API for the full current major version line.
- Internal modules are not considered stable unless explicitly exported through `__all__`.
- `dll_downloader.api` is the contract/data-facing surface and does not expose default runtime wiring helpers.
- `dll_downloader.runtime` reaches the default runtime wiring lazily inside public functions.
- `interfaces/cli.py` uses the public runtime surface for settings loading and default application creation instead of importing infrastructure wiring directly.

## Composition

- `bootstrap.py` defines runtime contracts and shapes only.
- `infrastructure/composition.py` builds the default production runtime.
- `interfaces/cli_runner.py` receives an injected application builder instead of importing production wiring directly.
- `DllFilesResolver` requires an injected HTTP text client; infrastructure adapters do not self-wire hidden concrete dependencies.

## Shared Technical Resources

- HTTP session lifecycle uses composition via `infrastructure/http_session.py`.
- Concrete adapters may share that resource, but not through inheritance-based architecture shortcuts.
- HTTP retry policy, request-header construction, and retried transport execution are explicit technical collaborators under `infrastructure/http/`.

## Guardrails

- `tests/test_architecture.py` checks layer boundaries, bootstrap purity, and the narrowed CLI public API.
- Behavior-oriented tests should prefer `dll_downloader.api`, `dll_downloader.interfaces.cli`, and public domain contracts over internal modules.
- Structural changes must update ADRs plus `docs/ARCHITECTURE.md` and `docs/PUBLIC_API.md`.
- Structured CLI output changes must also update `docs/STRUCTURED_OUTPUTS.md`.
- `mypy` runs on the package and the full test suite in CI.
- `ruff` and `pytest` run in CI on every push and pull request.
- CI also enforces critical coverage, module/function guardrails, and governance source-of-truth files.
- Legacy compatibility shims are intentionally removed rather than preserved once callers and tests have migrated.

## Historical Notes

- ADR 001 is superseded.
- Older documents that defend `SessionMixin` reflect a previous design stage and should not be treated as current architecture.
