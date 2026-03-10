# ADR 013: Remove Legacy Compatibility Shims

**Status**: Accepted  
**Date**: 2026-03-10  
**Author**: Marc Rivero López

## Context

After the architecture cleanup, a small amount of deliberate legacy remained:

- `Settings` still exposed loading helpers that simply proxied to `SettingsLoader`
- infrastructure adapters still exposed `_session` bridges for tests
- some tests still relied on those compatibility surfaces instead of current code

Those shims kept old access patterns alive even though the current architecture
already had cleaner equivalents.

## Decision

- `Settings` remains a pure configuration model plus validation helpers only.
- All external configuration loading goes through `SettingsLoader` or the stable
  public wrapper `dll_downloader.api.load_settings()`.
- HTTP infrastructure tests now inject `HTTPSessionResource` explicitly instead
  of mutating adapter-private `_session` attributes.
- Compatibility shims are removed rather than kept indefinitely.

## Consequences

- The codebase has fewer accidental APIs and less architectural ambiguity.
- Tests now exercise current dependency boundaries instead of historical bridges.
- Reintroducing compatibility helpers becomes a visible architecture regression.
