# ADR 006: Stricter CLI Boundaries and Typed Test Doubles

## Status
Accepted

## Context

The project had already improved its layer boundaries, but some pragmatic
choices remained:

- The CLI still referenced concrete infrastructure types in type hints.
- Test doubles covered behavior well, but several of them were not typed as
  real implementations of the project's ports.

That made the architecture slightly less strict than it looked and reduced the
value of static analysis around the most important test paths.

## Decision

- The CLI depends on closeable protocols at its boundary instead of concrete
  infrastructure classes when that detail is unnecessary.
- Representative test doubles must implement the same public contracts as the
  production ports.
- A selected subset of tests is now included in `mypy` to keep typed test
  doubles honest without requiring an all-at-once typing migration for the full
  test suite.

## Consequences

- The interface layer is less coupled to infrastructure details.
- Typed tests now validate architectural contracts, not just runtime behavior.
- The repository can keep increasing type coverage incrementally with CI
  enforcement on the most valuable test slices first.
