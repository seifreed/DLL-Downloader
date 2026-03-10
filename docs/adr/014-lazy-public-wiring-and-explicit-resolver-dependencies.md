## Status

Accepted

## Context

The project had already separated contracts, use cases, adapters, and runtime
composition well, but a few pragmatic shortcuts remained:

- `dll_downloader.api` imported production wiring modules eagerly at module load.
- `interfaces/cli.py` imported infrastructure composition and config loading directly.
- `DllFilesResolver` created a concrete `RequestsHTTPClient` when none was supplied.
- `SettingsLoader` still relied on broader `Any`-style mapping shapes than needed.

These shortcuts were acceptable in practice, but they made the public API and
CLI entrypoint know more about infrastructure than necessary.

## Decision

- `dll_downloader.api` now imports default wiring lazily inside public helper
  functions.
- `interfaces/cli.py` now consumes `load_settings()` and `create_application()`
  from the public API instead of importing infrastructure modules directly.
- `DllFilesResolver` now requires an injected text HTTP client and does not
  self-wire a concrete transport.
- `SettingsLoader` now maps config sources through narrower typed values.
- The broad `except Exception` in `cli_runner.py` remains intentionally at the
  outermost boundary, with explicit documentation as a boundary normalization
  rule rather than a convenience shortcut.

## Consequences

- The public API and CLI entrypoint are thinner architectural boundaries.
- Infrastructure adapters are more explicit about their dependencies.
- Tests and guardrails can now fail if direct infrastructure imports return to
  `api.py` or `interfaces/cli.py`.
- The default runtime remains easy to use, but the knowledge of how it is built
  is less spread across the codebase.
