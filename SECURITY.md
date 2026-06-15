# Security Policy

## Supported Versions

Security fixes are provided for the latest released version on the `main`
branch. Older versions are not maintained; please upgrade to the latest
release before reporting an issue.

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use one of the private channels below so the issue can be triaged and fixed
before it is disclosed:

1. **GitHub private vulnerability reporting (preferred).**
   Open <https://github.com/seifreed/DLL-Downloader/security/advisories/new>
   ("Report a vulnerability" on the repository's **Security** tab). Reports
   submitted this way are private to the maintainers and reporter.
2. **Email.** If you cannot use GitHub, email **mriverolopez@gmail.com** with
   the subject line `SECURITY: DLL-Downloader`. Encrypted mail is welcome; ask
   for a public key in your first message if you need one.

Please include, as far as you can:

- a description of the vulnerability and its impact,
- the affected version or commit,
- step-by-step reproduction (a minimal proof of concept is ideal), and
- any suggested remediation.

## Response Targets

- **Initial acknowledgement:** within **14 days** of the report.
- **Triage and severity assessment:** as soon as practical after acknowledgement.
- **Fix and disclosure:** medium-or-higher severity issues (CVSS ≥ 4.0) are
  fixed and released within **60 days** of public disclosure; critical issues
  are prioritized and fixed as rapidly as possible.

We will keep you informed throughout the process and credit you in the release
notes unless you ask to remain anonymous.

## Disclosure Policy

We follow coordinated disclosure. Once a fix is released, the vulnerability is
documented in [CHANGELOG.md](CHANGELOG.md) and, where a CVE applies, in a
published GitHub Security Advisory.

## Scope

This policy covers the code in this repository. Vulnerabilities in third-party
dependencies should be reported to the relevant upstream project; if a
dependency issue affects this project, we will update the affected dependency.
