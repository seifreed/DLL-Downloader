# Changelog

All notable changes to DLL-Downloader are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Security policy ([SECURITY.md](SECURITY.md)) with a private vulnerability
  reporting process.
- Contributor guide ([CONTRIBUTING.md](CONTRIBUTING.md)) documenting the
  contribution process, coding standards, and testing policy.
- This changelog.

### Changed
- Test suite raised to 100% line and branch coverage across `dll_downloader/`.

## [1.1.0] - 2026-05-05

### Changed
- Hardened the security-sensitive paths across the codebase: ZIP extraction
  (ZIP-bomb and member-count/size limits), atomic file writes, and bounded
  redirect following.
- Hardened SSRF defenses end to end: scheme and credential validation,
  domain allowlisting, DNS-rebinding (TOCTOU) checks that fail closed, and
  redirect-hop limits in both the HTTP transport and the VirusTotal client.
- Hardened CLI, structured-output (JSON/SARIF), and HTTP response contracts,
  including boundary-error sanitization and immutable request snapshots.
- Hardened persistence: symlink-safe opens (`O_NOFOLLOW`), advisory index
  locking, index size limits, and path-containment checks.

### Fixed
- Resolved a large number of correctness and security bugs surfaced during
  hardening, including TOCTOU races, fail-open security checks, resource and
  file-descriptor leaks, FIFO/slowloris hangs, charset-detection edge cases,
  PE/architecture validation on ARM/ARM64, and type-safety regressions.

### CI
- Dropped the Windows matrix (the persistence and use-case layers rely on
  POSIX-only primitives) and stabilized coverage on the supported platforms.

## [1.0.2] - 2026-03-10

### Fixed
- Maintenance and packaging fixes following the initial public releases.

## [1.0.1] - 2026-03-10

### Added
- Initial published releases of DLL-Downloader: CLI and Python library to
  search, download, and optionally scan DLL files with VirusTotal, with JSON
  and SARIF output modes.

[Unreleased]: https://github.com/seifreed/DLL-Downloader/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/seifreed/DLL-Downloader/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/seifreed/DLL-Downloader/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/seifreed/DLL-Downloader/releases/tag/v1.0.1
