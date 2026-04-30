# ADR 016: Runtime Safety Validation and Timeouts

## Status

Accepted

## Context

Recent regression fixes tightened download correctness, but three runtime
boundaries still needed explicit contracts:

- repository writes could follow pre-existing symlinks
- merged settings could reach production wiring without validation
- VirusTotal requests had no bounded timeout

## Decision

- Repository save and index writes reject symlink destinations and paths that
  resolve outside the repository before writing.
- Repository writes use a same-directory temporary file and atomic replace for
  regular-file updates.
- `SettingsLoader.load()` validates the final merged settings before returning.
- `Settings` includes `virustotal_timeout` with JSON and environment loading.
- Production composition passes `virustotal_timeout` into `VirusTotalScanner`.

## Consequences

- Unsafe repository paths fail explicitly instead of writing outside the
  download directory.
- Invalid runtime configuration fails at load time.
- VirusTotal lookups, uploads, and reports use a configurable timeout.
- `Settings.virustotal_timeout` is an additive public configuration field for
  the current major version line.
