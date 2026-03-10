## Status
Accepted

## Context
The project already had a cleaner separation than before, but three pressure points remained:

- `cli.py` still coordinated more session flow than a thin adapter should.
- `bootstrap.py` still exposed a pragmatic but slightly under-modeled assembly flow.
- Large test suites were still outside strict `mypy` coverage because they depended on accidental concrete details.

## Decision
We tightened the boundary contracts around the CLI and infrastructure session layer.

- `cli.py` remains a compatibility facade, but session normalization now lives in `CLIApplicationService.create_invocation(...)`.
- Batch execution depends on a `SupportsDownloadExecution` protocol instead of the concrete single-download use case type.
- A later refinement in ADR 009 replaces the shared mixin with `HTTPSessionResource` composition.
- `build_download_application(...)` accepts a higher-level `DownloadApplicationAssembler` so the composition root can be assembled through a clearer contract.

## Consequences

Positive:

- The CLI entrypoint is closer to parse-and-delegate.
- Secondary adapters share an explicit technical session contract.
- `test_cli.py`, `test_http_client.py`, and `test_virustotal.py` can now run under `mypy` without relying on broad casts against production code.
- The composition root is easier to replace in tests and more explicit about where concrete wiring decisions live.

Tradeoff:

- There are more small protocols in the codebase.
- The CLI keeps some backwards-compatible helper functions for tests and callers at this stage, though ADR 009 later replaces that with the explicit `dll_downloader.api` module.
