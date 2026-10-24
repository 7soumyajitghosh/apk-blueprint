# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of APK Blueprint Analyzer
- Component extraction (Activities, Services, Receivers, Providers)
- Permission analysis with human-readable explanations
- Library/SDK detection
- Screen mapping from layout resources
- Architecture summary
- Risk flagging for security and privacy
- Markdown and JSON report generation
- CLI commands: `analyze`, `permissions`, `components`
- Comprehensive test suite

### Fixed
- Corrected project URLs in pyproject.toml (was using placeholder "your-username")

## [0.1.0] - 2026-10-24

### Added
- Initial release of APK Blueprint Analyzer
- Core analysis pipeline for Android APK files
- Local-only, read-only static analysis
- Legal disclaimer enforcement