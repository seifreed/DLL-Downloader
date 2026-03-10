## Status
Accepted

## Context
The project had already moved closer to clean architecture, but three compromises remained visible:

- `cli.py` still exposed compatibility helpers that made the entrypoint look like a library façade.
- `bootstrap.py` still knew about concrete infrastructure wiring.
- shared HTTP session lifecycle still lived behind inheritance, which kept infrastructure reuse practical but not especially pure.

## Decision
We tightened those boundaries further.

- `cli.py` is now treated as an entrypoint-focused adapter.
- Compatibility helpers were removed from the CLI layer and replaced by the explicit library API in `dll_downloader.api`.
- `bootstrap.py` now defines contracts and runtime shapes only. Concrete production wiring moved to `dll_downloader.infrastructure.composition`.
- HTTP session lifecycle now uses composition through `HTTPSessionResource` instead of a shared base mixin.

## Consequences

Positive:

- The CLI entrypoint is more honest about its responsibility.
- Bootstrap contracts are infrastructure-free and easier to test as pure architecture primitives.
- Session reuse remains shared without inheritance coupling.
- Architecture tests can now verify bootstrap purity and the reduced CLI public API.

Tradeoff:

- There is one extra compatibility module for callers that used the old CLI helper surface.
- The design uses more small contracts and explicit wiring modules than before.
