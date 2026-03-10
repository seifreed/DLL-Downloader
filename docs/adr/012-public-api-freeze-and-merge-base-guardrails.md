# ADR 012: Public API Freeze and Merge-Base Guardrails

**Status**: Accepted  
**Date**: 2026-03-10  
**Author**: Marc Rivero López

## Context

The project already had a narrowed public API and strong documentation guardrails,
but two ambiguities remained:

1. `Settings` was exported publicly without an explicit final decision for the
   current major version line.
2. Structural documentation checks compared against `HEAD~1`, which is too weak
   for multi-commit branches and pull requests.

At this stage, the risk is not architectural confusion inside the current code,
but accidental drift in future changes.

## Decision

- Freeze `Settings` as part of the supported `dll_downloader.api` surface for the
  full `1.x` line.
- Require any replacement with a narrower public configuration surface to happen
  only in a major version with explicit migration guidance.
- Make structural documentation enforcement compare against a merge-base or base
  branch reference when possible, with `HEAD~1` only as fallback.
- Treat public export changes and composition/wiring changes as structural
  changes that require ADR and source-of-truth documentation updates.

## Alternatives Considered

### Remove `Settings` from the public API immediately

Rejected because it would create churn for consumers and force a breaking change
without enough architectural benefit at this point.

### Keep `HEAD~1` structural checks

Rejected because it misses real multi-commit branch changes and gives false
confidence in CI.

## Consequences

- Consumers now have an explicit guarantee that `Settings` remains stable
  throughout the current major version line.
- CI evaluates structural drift against a more realistic change range.
- Future changes to exports and wiring are more likely to trigger the required
  architecture and policy updates automatically.
