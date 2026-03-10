# ADR 010: Public API Enforcement and Thin CLI Boundary

**Status**: Accepted
**Date**: 2026-03-10
**Author**: Marc Rivero López

## Context

The project already had a strong layered design, but a few behavior-oriented
tests still imported internal `application` and `infrastructure` modules.
`cli.py` also retained some orchestration details that belonged closer to the
CLI session service, and governance rules depended too much on human review.

## Decision

- Keep `dll_downloader.api` and `dll_downloader.interfaces.cli` as the supported
  public entrypoints for programmatic and CLI usage.
- Treat behavior-oriented tests as consumers of that public surface, while
  allowing module-specific test suites to import internals only when they are
  testing those internals directly.
- Move CLI summary rendering and session execution wiring into
  `interfaces/cli_runner.py` so `cli.py` remains a thin adapter.
- Enforce documentation and governance policy in CI with dedicated guardrail
  scripts and architecture tests.

## Alternatives Considered

### Keep test imports pragmatic

- Faster in the short term
- Keeps tests coupled to implementation details and weakens public API discipline

### Push all CLI behavior into the entrypoint

- Simpler file graph
- Makes the entrypoint absorb lifecycle and rendering logic over time

## Consequences

- Public API drift is now harder to introduce accidentally.
- CLI orchestration sits closer to the session boundary instead of the
  entrypoint file.
- CI now checks not only code quality but also governance/documentation
  requirements that preserve architectural intent.
