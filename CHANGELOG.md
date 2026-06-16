# Changelog

All notable changes to DLL-Downloader are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-06-16

This release focuses on supply-chain security, code-quality hardening, full
test coverage, and project governance. No public API changes; one on-disk
behavior refinement (see Changed).

### Added
- **Security tooling and CI gates:** Bandit (security lint) and pip-audit
  (dependency vulnerability scan) added to the dev tooling and enforced in CI,
  and the PyPI publish workflow is now gated on both. Pylint added for
  design/logic linting.
- **Dependency & supply-chain hardening:** Dependabot configuration for GitHub
  Actions and pip; all third-party GitHub Actions pinned to commit SHAs;
  known-vulnerable transitive dependency versions pinned out.
- **CycloneDX SBOM** generation scored 10.0/A on the NTIA and BSI profiles,
  with a dynamic SBOM-quality badge in the README.
- **Project governance:** security policy ([SECURITY.md](SECURITY.md)) with a
  private vulnerability reporting process, contributor guide
  ([CONTRIBUTING.md](CONTRIBUTING.md)) documenting standards and the testing
  policy, this changelog, and Codecov/SBOM/OpenSSF badges in the README.
- **100% test coverage** (line and branch) across `dll_downloader/`, including
  the HTTP transport, VirusTotal scanner, file repository, use cases,
  CLI/runtime, presenters, config, and infrastructure modules.

### Changed
- Unextracted ZIP downloads are now stored with a `.zip` extension so the file
  extension always matches the real payload type.
- Consolidated duplicated logic into shared modules and unified the
  `dll_files_resolver` SSRF link validation into a single gate.
- Wired the `VirusTotalScanner` threshold class constants into the `__init__`
  defaults.
- Adopted `ruff format` as the canonical formatter, enforced in CI; immutable
  HTTP response headers now use `MappingProxyType` instead of a dict subclass.
- CI: superseded runs are cancelled to avoid pile-ups, per-job timeouts added,
  and the macOS matrix dropped (GitHub-hosted macOS runners are not assigned to
  this repository).

### Removed
- Dead code and unused surface: methods referenced only by tests, the unused
  `BatchDownloadError` exception, the unused `RequestsHTTPClient.DEFAULT_USER_AGENT`
  constant, a dead parser parameter threaded through the CLI download path, and
  no-op code (now enforced via flake8-pie).
- All linter/coverage suppressions: removed `# noqa`/policy suppressions and the
  E501, C901, and coverage-exclusion config; long lines wrapped and complex
  functions refactored instead of suppressed.

### Security
- No publicly known CVEs were fixed in this release. The changes above harden
  the build, dependency, and CI supply chain.

### Fixed
- License consistency: corrected stray GPLv3 labels in test headers and ADR docs
  to the project's actual MIT License (with attribution).

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

[Unreleased]: https://github.com/seifreed/DLL-Downloader/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/seifreed/DLL-Downloader/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/seifreed/DLL-Downloader/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/seifreed/DLL-Downloader/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/seifreed/DLL-Downloader/releases/tag/v1.0.1
