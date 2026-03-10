# Public API

This document defines the supported stable surface for consumers of the project.

## Stable Modules

- `dll_downloader.api`
- `dll_downloader.runtime`
- `dll_downloader.interfaces.cli`
- `dll_downloader`
- `docs/STRUCTURED_OUTPUTS.md`

## Stable Library Symbols (`dll_downloader.api`)

- `API_VERSION`
- `Architecture`
- `Settings`
- `DownloadDLLRequest`
- `DownloadDLLResponse`

`dll_downloader.api` is the stable contract/data surface. It does not own
default runtime wiring helpers.

## Stable Runtime Symbols (`dll_downloader.runtime`)

- `load_settings`
- `create_application`
- `create_dependencies`
- `process_downloads`
- `Settings`
- `Architecture`

`Settings` remains part of the stable public API for the full `1.x` line.
Any replacement with a narrower public configuration surface must ship as a `2.0` breaking change with explicit migration guidance.

## Stable Package Symbols (`dll_downloader`)

- `__version__`

## Versioning Policy

- Backward-compatible additions to the public API require documentation updates.
- Breaking changes to the public API require a major version change.
- `Settings` must remain stable throughout the current major version line.
- Structured CLI output changes require `docs/STRUCTURED_OUTPUTS.md` review.
- Any change to the stable module list or exported symbol list requires:
  - ADR update
  - `ARCHITECTURE.md` update
  - `docs/GOVERNANCE.md` review
