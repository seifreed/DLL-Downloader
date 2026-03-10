# Governance

These rules keep the architecture from drifting.

## Required For Structural Changes

- Add or update an ADR for changes to wiring, ports, boundaries, or public API.
- Update `ARCHITECTURE.md` if the current runtime structure changes.
- Update `docs/PUBLIC_API.md` when the supported symbol surface changes.
- Update architecture guardrails if a new boundary is introduced.
- Keep `Settings` stable throughout the current major version line unless a major-version migration is introduced.

Structural changes include:

- changes to `__all__` in public modules
- changes to production wiring or bootstrap/composition boundaries
- changes to layer import allowlists or forbidden dependency rules
- changes to supported CLI/library entrypoints

## Pull Request Checklist

- Public API changes are intentional and documented.
- Public API versioning implications were reviewed.
- No new forbidden imports were introduced between layers.
- CLI adapters remain thin and do not absorb business logic.
- New infrastructure adapters implement domain/application contracts explicitly.
- `ruff`, `mypy`, and `pytest` pass locally.

## Public API Rule

- Supported programmatic API lives in `dll_downloader.api`.
- Supported default runtime helpers live in `dll_downloader.runtime`.
- Supported CLI entrypoint lives in `dll_downloader.interfaces.cli`.
- Public compatibility and versioning policy lives in `docs/PUBLIC_API.md`.
- Tests should prefer stable public modules over semiprivate helpers.
- Documentation examples must not import internal modules directly.
- Behavior tests and interface adapters must not take shortcuts into internal wiring or infrastructure internals.
- Compatibility shims should be removed once callers and tests are migrated; they are not preserved by default.
