# ADR 001: SessionMixin for HTTP Session Management

**Status**: Accepted

**Date**: 2026-01-31

**Author**: Marc Rivero López

**License**: GPLv3

## Context

Multiple infrastructure components (`RequestsHTTPClient` and `VirusTotalScanner`) require identical HTTP session management behavior:

1. Lazy initialization of `requests.Session` objects
2. Configurable default headers per instance
3. Context manager protocol (`__enter__`/`__exit__`) for resource cleanup
4. Explicit cleanup via `close()` method
5. Proper connection pooling and session reuse

Initial architectural review identified this shared dependency as a potential coupling concern between HTTP client and security scanner components.

## Decision

We will use a **mixin class** (`SessionMixin`) to provide shared HTTP session management functionality to both `RequestsHTTPClient` and `VirusTotalScanner`.

### Implementation

```python
# dll_downloader/infrastructure/base.py
class SessionMixin:
    """Mixin providing lazy-initialized requests session management."""

    _session: Optional[requests.Session] = None
    _session_headers: dict[str, str] = {}

    @property
    def session(self) -> requests.Session:
        """Lazy initialization of requests session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update(self._session_headers)
        return self._session

    def close(self) -> None:
        """Close the HTTP session and release resources."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
```

## Alternatives Considered

### Alternative 1: SessionManager with Composition

Create a dedicated `SessionManager` class and inject it into both consumers.

```python
class SessionManager:
    def __init__(self, headers: dict[str, str]):
        self._session = None
        self._headers = headers

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update(self._headers)
        return self._session

class RequestsHTTPClient:
    def __init__(self, session_manager: SessionManager):
        self._session_manager = session_manager

    def get(self, url: str):
        return self._session_manager.session.get(url)
```

**Rejected because**:
- Adds unnecessary indirection layer
- Requires boilerplate delegation in both classes
- No testability benefit (both patterns equally testable)
- Session management is not a variation point requiring strategy pattern
- Increases complexity without architectural benefit

### Alternative 2: Duplicate Implementation

Duplicate the session management code in both classes.

**Rejected because**:
- Violates DRY principle
- Creates maintenance burden (bug fixes in two places)
- No architectural benefit
- Less maintainable than mixin approach

### Alternative 3: Single Base Class

Create `HTTPComponent` base class with session management.

```python
class HTTPComponent:
    def __init__(self):
        self._session = None
        self._session_headers = {}
    # ... session methods
```

**Rejected because**:
- Forces inheritance hierarchy where none is conceptually needed
- `RequestsHTTPClient` and `VirusTotalScanner` are fundamentally different concerns
- Would suggest they share an "is-a" relationship when they don't
- Mixin is more flexible and semantically accurate

## Consequences

### Positive

1. **Code Reuse**: Single implementation of session lifecycle management
2. **DRY Compliance**: No duplication of technical infrastructure code
3. **Maintainability**: Bug fixes and improvements in one location
4. **Python Idiomatic**: Mixins are well-established pattern for cross-cutting concerns
5. **Type Safety**: Maintains full type hint coverage
6. **Testability**: Both consumers remain independently testable
7. **SOLID Compliance**: Maintains Single Responsibility (session management separated)

### Negative

1. **Coupling**: Minor coupling between two infrastructure components
   - **Mitigation**: Both are in the same architectural layer (infrastructure)
   - **Severity**: Low - technical coupling, not business logic coupling

2. **Multiple Inheritance**: Uses Python's MRO (Method Resolution Order)
   - **Mitigation**: Mixin is simple with no method conflicts
   - **Severity**: Negligible - well-understood Python pattern

### Neutral

1. **Documentation Requirement**: Must document the intentional coupling
2. **Learning Curve**: Team must understand mixin pattern (standard Python knowledge)

## Architectural Justification

This decision does NOT violate separation of concerns because:

1. **Same Layer**: Both consumers are in the infrastructure layer
2. **Technical Concern**: Sharing technical infrastructure, not business logic
3. **No Domain Coupling**: Domain layer has no knowledge of this implementation
4. **Interface Compliance**: Both still comply with their domain interfaces (`IHTTPClient`, `ISecurityScanner`)
5. **Dependency Direction**: No reverse dependencies introduced

## Compliance Check

- **Clean Architecture**: ✓ (Layer boundaries maintained)
- **SOLID Principles**: ✓ (Single Responsibility, Interface Segregation preserved)
- **DRY**: ✓ (No code duplication)
- **YAGNI**: ✓ (No speculative complexity)
- **KISS**: ✓ (Simplest solution that works)

## Validation

All 94 unit and integration tests pass with this implementation:
- Entity tests: 20/20 passed
- Use case tests: 10/10 passed
- Repository integration tests: 34/34 passed
- HTTP client tests: 30/30 passed

## Review Decision

After architectural review, this design is deemed **optimal** for the following reasons:

1. Pragmatism over architectural purity without sacrificing principles
2. Production-ready codebase requires stability over refactoring churn
3. No measurable benefit from more complex alternatives
4. Clear documentation makes the decision transparent and maintainable

## References

- Python Mixin Pattern: [PEP 3119 - Abstract Base Classes](https://peps.python.org/pep-3119/)
- Clean Architecture: Robert C. Martin, "Clean Architecture" (2017)
- SOLID Principles: Robert C. Martin, "Agile Software Development" (2002)

## Revision History

| Date       | Author            | Change                |
|------------|-------------------|-----------------------|
| 2026-01-31 | Marc Rivero López | Initial ADR creation  |

---

**License**: GNU General Public License v3 (GPLv3)

This architectural decision record is part of the DLL Downloader project and is licensed under GPLv3. Any derivative work must maintain attribution to Marc Rivero López and be distributed under the same license.
