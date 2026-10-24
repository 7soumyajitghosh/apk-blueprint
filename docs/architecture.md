# Architecture Overview

## Design Philosophy

APK Blueprint Analyzer follows a **pipeline architecture** where each stage
of analysis is handled by an independent, focused module. This design
ensures:

- **Modularity** — each analyzer can be developed, tested, and extended
  independently
- **Composability** — analyzers can be combined in different ways for
  different output needs
- **Testability** — each module has a clear interface with well-defined
  inputs and outputs

## Pipeline Flow

```
                ┌──────────────┐
                │   APK File   │
                └──────┬───────┘
                       │
                ┌──────▼───────┐
                │  ApkParser   │  Extract ZIP, metadata, file listing
                └──────┬───────┘
                       │
                ┌──────▼────────────┐
                │ ManifestAnalyzer  │  Parse AndroidManifest.xml
                └──────┬────────────┘
                       │
          ┌────────────┼────────────────────┐
          │            │                    │
  ┌───────▼──────┐ ┌───▼──────────┐  ┌─────▼──────────┐
  │  Component   │ │  Permission  │  │    Library     │
  │  Extractor   │ │  Analyzer    │  │   Detector     │
  └───────┬──────┘ └───┬──────────┘  └─────┬──────────┘
          │            │                    │
  ┌───────▼──────┐     │                    │
  │   Screen     │     │                    │
  │   Mapper     │     │                    │
  └───────┬──────┘     │                    │
          │            │                    │
          └────────────┼────────────────────┘
                       │
                ┌──────▼───────┐
                │ RiskScanner  │  Cross-module risk analysis
                └──────┬───────┘
                       │
               ┌───────▼────────┐
               │ AnalysisResult │  Aggregate data container
               └───────┬────────┘
                       │
              ┌────────▼─────────┐
              │ ReportGenerator  │  Write output files
              └──────────────────┘
```

## Module Responsibilities

### `apk_parser.py`

Opens the APK as a ZIP archive. Extracts:
- File metadata (size, hash, entry count)
- Complete file listing
- Raw file content for downstream modules

Never modifies the APK. All operations are read-only.

### `manifest_analyzer.py`

Parses the decoded `AndroidManifest.xml` to extract:
- Package name, version code/name
- SDK version constraints (min, target, compile)
- Declared permissions (`<uses-permission>`)
- Custom permission definitions (`<permission>`)
- Application-level attributes

Provides a `parse_manifest_from_string()` utility for testing.

### `component_extractor.py`

Walks the `<application>` element to extract all four component types:
- **Activities** — UI screens
- **Services** — background tasks
- **Broadcast Receivers** — event listeners
- **Content Providers** — data interfaces

For each component: name, exported status, permission guards, intent
filters (actions, categories, data URIs).

### `permission_analyzer.py`

Maps permission strings to a curated knowledge base containing:
- Protection level (normal, dangerous, signature)
- Risk category (low, medium, high, critical)
- Human-readable description
- Permission group

Provides filtering by risk level and protection level.

### `library_detector.py`

Scans APK file paths against a fingerprint database of 40+ known
libraries and SDKs. Categories include:
- Analytics & tracking
- Advertising
- Networking
- Image loading
- Database
- UI frameworks
- Cross-platform frameworks
- Crash reporting

Flags privacy-relevant libraries.

### `screen_mapper.py`

Infers the app's screen structure by:
- Mapping Activities to screen concepts
- Matching Activity names to layout XML files (via CamelCase→snake_case)
- Using naming heuristics to infer screen purpose
- Identifying the launcher (entry point) screen
- Detecting deep link handlers

### `risk_scanner.py`

Cross-references data from all analyzers to identify:
- Exported components without permission guards
- Critical/high-risk permissions
- Privacy-relevant SDK usage
- Manifest misconfigurations (debuggable, allowBackup, cleartext)
- Network configuration files

Sorts findings by severity.

### `report_generator.py`

Takes the aggregated `AnalysisResult` and writes 7 output files:
- `report.md` — Executive summary
- `blueprint.json` — Machine-readable structured data
- `permissions.md` — Permission detail table
- `components.md` — Component listing by type
- `libraries.md` — Library detection results
- `screens.md` — Screen navigation map
- `risks.md` — Risk assessment with severity, evidence, recommendations

### `cli.py`

Click-based CLI providing:
- `analyze` — Full analysis pipeline → report files
- `permissions` — Permission-only view to terminal
- `components` — Component-only view to terminal
- `--format json` — JSON output to stdout
- `--help` — Auto-generated help for all commands

Uses Rich for formatted terminal output including tables and panels.

## Data Flow

All modules communicate through well-typed dataclasses:

| Dataclass | Module | Purpose |
|---|---|---|
| `ApkMetadata` | `apk_parser` | File-level metadata |
| `ManifestInfo` | `manifest_analyzer` | Parsed manifest data |
| `ComponentInfo` | `component_extractor` | Single component |
| `IntentFilterInfo` | `component_extractor` | Intent filter data |
| `PermissionDetail` | `permission_analyzer` | Permission with explanation |
| `LibraryMatch` | `library_detector` | Detected library |
| `ScreenInfo` | `screen_mapper` | Inferred screen |
| `RiskFinding` | `risk_scanner` | Security/privacy finding |
| `AnalysisResult` | `report_generator` | Aggregated results |

Every dataclass implements `to_dict()` for JSON serialization.

## Extending the Analyzer

To add a new analyzer:

1. Create `src/apk_blueprint_analyzer/my_analyzer.py`
2. Define input/output dataclasses with `to_dict()`
3. Implement the analysis logic
4. Add it to the pipeline in `cli.py`'s `_run_analysis()`
5. Add a report section in `ReportGenerator`
6. Include the data in `AnalysisResult.to_dict()`
7. Write tests in `tests/test_my_analyzer.py`
