## Status

Accepted

## Context

`dll_downloader.api` still mixed two concerns:

- stable contract/data types for consumers
- convenience helpers that built the default production runtime

That was practical, but it kept the public API module closer to infrastructure
than necessary. At the same time, the loader module still concentrated several
input-source concerns in one place, and the technical adapters (`http_client`
and `virustotal`) relied more on convention than on explicit architectural
guardrails.

## Decision

- `dll_downloader.api` now exports only the stable contract/data surface.
- Default production wiring helpers move to `dll_downloader.runtime`.
- `interfaces/cli.py` consumes `dll_downloader.runtime`, not infrastructure
  wiring modules directly.
- `cli_runner.py` keeps a broad boundary catch, but that catch is isolated in a
  dedicated boundary execution helper.
- `SettingsLoader` now delegates to focused private configuration sources for
  JSON, environment variables, and `~/.vt.toml`.
- Architecture tests now enforce narrow dependency allowlists for the technical
  adapters `infrastructure/http/http_client.py` and
  `infrastructure/services/virustotal.py`.

## Consequences

- The public API is more ascetic and less coupled to default runtime creation.
- Consumers still have an ergonomic programmatic entrypoint via
  `dll_downloader.runtime`.
- The CLI boundary and technical adapters are more explicitly governed.
- Future drift in HTTP/VirusTotal adapters is more likely to be caught in CI.
