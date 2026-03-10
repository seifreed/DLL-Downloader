# ADR 005: Error Taxonomy and Boundary Handling

## Status
Accepted

## Context

The project mixed `ValueError` and adapter-specific exceptions across several
layers. That made it hard to know which failures belonged to the domain-facing
ports, which ones were application orchestration failures, and which ones were
pure interface concerns.

## Decision

- Domain-facing ports use shared error base classes from `dll_downloader.domain.errors`.
- Infrastructure adapters raise subclasses of those shared port errors.
- Application use cases translate port failures into application errors.
- Generic exception handling is allowed only at the outer interface boundary.

## Consequences

- Failure handling is more predictable across the codebase.
- Use cases no longer need to know infrastructure-specific exception types.
- CLI error mapping stays at the edge of the system.
