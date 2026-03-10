# ADR 003: Settings Loading Strategy

## Status
Accepted

## Context

`Settings` was responsible for both representing configuration and loading it
from JSON, environment variables, and `~/.vt.toml`. That mixed multiple reasons
to change into a single class.

## Decision

- `Settings` is now a data model plus validation helpers.
- `SettingsLoader` handles external configuration sources and precedence.
- External configuration loading must go through `SettingsLoader`.
- `dll_downloader.api.load_settings()` is the stable public entrypoint for
  library consumers that need the default loading behavior.

## Consequences

- The configuration model is easier to reason about.
- Loading behavior is isolated and easier to test.
- The settings model no longer acts as a compatibility façade for loading logic.
