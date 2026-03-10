# ADR 011: Public API Versioning and CLI Output Boundary

**Status**: Accepted
**Date**: 2026-03-10
**Author**: Marc Rivero López

## Context

The project already had a narrow public surface, but versioning rules for that
surface were not explicit enough and `cli_runner.py` still mixed execution with
direct console output. Some infrastructure-facing types also remained broader
than necessary in tests and boundary helpers.

## Decision

- Freeze the supported public API in `docs/PUBLIC_API.md`.
- Expose `API_VERSION` and `load_settings()` from `dll_downloader.api` so the
  public surface is explicit and documented.
- Keep `Settings` public as part of the stable library API for now.
- Move CLI output emission behind a writer boundary and keep batch rendering in
  presenters rather than `print(...)` calls inside execution code.
- Enforce coverage thresholds with line and branch requirements for critical
  modules.

## Alternatives Considered

### Hide `Settings` immediately

- Would produce a narrower API.
- Would also create avoidable breakage for existing consumers without enough
  migration benefit today.

### Leave `print(...)` in the runner

- Slightly simpler implementation.
- Keeps boundary translation and side effects mixed together.

## Consequences

- Public API changes now require an explicit compatibility review.
- CLI execution is easier to test without relying on direct stdout/stderr side effects.
- Critical modules are protected not only by file coverage but also by branch coverage.
