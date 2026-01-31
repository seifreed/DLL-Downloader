# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records documenting significant architectural and design decisions made during the development of the DLL Downloader project.

## What is an ADR?

An Architecture Decision Record (ADR) is a document that captures an important architectural decision made along with its context and consequences. ADRs provide:

1. **Historical Context**: Why decisions were made
2. **Transparency**: Clear rationale for design choices
3. **Knowledge Transfer**: Help new team members understand the codebase
4. **Review Material**: Enable architectural review and validation

## ADR Format

Each ADR follows this structure:

```markdown
# ADR [number]: [Title]

**Status**: [Proposed | Accepted | Deprecated | Superseded]
**Date**: YYYY-MM-DD
**Author**: Name

## Context
[Describe the forces at play, including technological, political, social, and project local]

## Decision
[Describe our response to these forces]

## Alternatives Considered
[Describe alternative approaches and why they were rejected]

## Consequences
[Describe the resulting context after applying the decision]
```

## Index of ADRs

| Number | Title | Status | Date |
|--------|-------|--------|------|
| [001](001-sessionmixin-for-http-session-management.md) | SessionMixin for HTTP Session Management | Accepted | 2026-01-31 |

## Contributing

When making significant architectural decisions:

1. Create a new ADR with the next sequential number
2. Follow the template format above
3. Get peer review before marking as "Accepted"
4. Update this README index

## Statuses

- **Proposed**: Under discussion, not yet implemented
- **Accepted**: Approved and implemented
- **Deprecated**: No longer recommended, but still in codebase
- **Superseded**: Replaced by a newer ADR (reference the replacement)

## License

All ADRs are licensed under GPLv3 and authored by Marc Rivero López unless otherwise noted.

---

**Last Updated**: 2026-01-31
