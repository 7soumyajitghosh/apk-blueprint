# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Current release |

## Reporting a Vulnerability

If you discover a security vulnerability in APK Blueprint Analyzer, please
report it responsibly:

1. **Do NOT open a public issue.** Security vulnerabilities should be reported
   privately.
2. **Email**: Send a detailed report to the project maintainers via the contact
   information in the repository.
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to release a fix within
7 days for critical vulnerabilities.

## Security Design Principles

APK Blueprint Analyzer is designed with the following security principles:

- **Local-only processing**: APK files are never uploaded to external servers.
  All analysis happens on the user's machine.
- **Read-only analysis**: The tool never modifies, repacks, or signs APK files.
- **No network calls**: The core analysis pipeline makes zero network requests.
  APK content stays on disk.
- **No credential storage**: The tool does not store, request, or transmit any
  API keys, tokens, or credentials.
- **Minimal privileges**: The tool requires only filesystem read access to the
  APK and write access to the output directory.

## Responsible Use

This tool is intended for:

- Developers analyzing their own applications
- Security researchers with proper authorization
- Academic research and education

It is **not** intended for analyzing APKs without the owner's consent, reverse
engineering for piracy, or any other unauthorized purpose.
