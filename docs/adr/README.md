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
| [001](001-sessionmixin-for-http-session-management.md) | SessionMixin for HTTP Session Management | Superseded | 2026-01-31 |
| [002](002-layer-dependencies-and-ports.md) | Layer Dependencies and Ports | Accepted | 2026-03-10 |
| [003](003-settings-loading-strategy.md) | Settings Loading Strategy | Accepted | 2026-03-10 |
| [004](004-cli-adapters-and-batch-orchestration.md) | CLI Adapters and Batch Orchestration | Accepted | 2026-03-10 |
| [005](005-error-taxonomy-and-boundary-handling.md) | Error Taxonomy and Boundary Handling | Accepted | 2026-03-10 |
| [006](006-stricter-cli-boundaries-and-typed-test-doubles.md) | Stricter CLI Boundaries and Typed Test Doubles | Accepted | 2026-03-10 |
| [007](007-composition-root-factories.md) | Composition Root Factories | Accepted | 2026-03-10 |
| [008](008-cli-entrypoint-and-session-contracts.md) | CLI Entrypoint and Session Contracts | Accepted | 2026-03-10 |
| [009](009-purer-bootstrap-and-cli-compat-boundary.md) | Purer Bootstrap and CLI Compatibility Boundary | Accepted | 2026-03-10 |
| [010](010-public-api-enforcement-and-thin-cli-boundary.md) | Public API Enforcement and Thin CLI Boundary | Accepted | 2026-03-10 |
| [011](011-public-api-versioning-and-cli-output-boundary.md) | Public API Versioning and CLI Output Boundary | Accepted | 2026-03-10 |
| [012](012-public-api-freeze-and-merge-base-guardrails.md) | Public API Freeze and Merge-Base Guardrails | Accepted | 2026-03-10 |
| [013](013-remove-legacy-compatibility-shims.md) | Remove Legacy Compatibility Shims | Accepted | 2026-03-10 |
| [014](014-lazy-public-wiring-and-explicit-resolver-dependencies.md) | Lazy Public Wiring and Explicit Resolver Dependencies | Accepted | 2026-03-10 |
| [015](015-split-core-api-from-default-runtime-surface.md) | Split Core API from Default Runtime Surface | Accepted | 2026-03-10 |

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

**Last Updated**: 2026-03-10
