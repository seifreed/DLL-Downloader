# ADR 002: Layer Dependencies and Ports

## Status
Accepted

## Context

The project already had a layered structure, but some infrastructure adapters
still bypassed shared contracts. The clearest example was the DLL resolver,
which used `requests` directly instead of going through the project's HTTP port.

## Decision

- The domain layer remains dependency-free with respect to `application`,
  `interfaces`, and `infrastructure`.
- Cross-layer behavior is expressed through explicit ports such as
  `IHTTPClient` and `IDownloadURLResolver`.
- Infrastructure adapters may create default implementations internally, but
  they interact through those ports rather than bypassing them.
- Architectural rules are enforced with tests.

## Consequences

- Adapters are easier to substitute and test.
- HTTP behavior is centralized instead of duplicated.
- The architecture is protected against future accidental imports.
