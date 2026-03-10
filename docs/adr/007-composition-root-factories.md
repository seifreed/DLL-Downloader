# ADR 007: Composition Root Factories

## Status
Accepted

## Context

The project already had a dedicated composition root, but it still instantiated
concrete infrastructure components directly inside `bootstrap.py`. That is
acceptable in a pragmatic system, yet it makes the composition root harder to
substitute and test if we want stricter architectural boundaries.

## Decision

- `bootstrap.py` now builds the runtime through a `DownloadComponentFactory`
  protocol.
- Production wiring uses `DefaultDownloadComponentFactory`.
- The runtime object exposed to callers is typed against closeable protocols
  rather than concrete adapters.

## Consequences

- Concrete infrastructure choices remain isolated in one default factory.
- The composition root is easier to test with injected factories.
- The interface layer depends less on concrete infrastructure details.
