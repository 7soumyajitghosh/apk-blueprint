# APK Blueprint Analyzer

**Understand Android apps through safe static analysis.**

APK Blueprint Analyzer is a local-only, read-only command-line tool that
inspects Android APK files and produces a comprehensive **App Blueprint
Report**. It helps developers, security researchers, and educators understand
what an app does — without ever modifying, repacking, or redistributing the
APK.

---

## ⚠️ Legal & Ethical Use Notice

> **This tool is intended exclusively for APKs you own or are explicitly
> authorized to analyze.** Use it for your own apps, authorized security
> assessments, or academic research only.
>
> Do **not** use this tool to circumvent security protections, crack paid
> applications, remove license checks, distribute modified APKs, or engage in
> any form of software piracy. Unauthorized analysis of third-party
> applications may violate applicable laws.

---

## What It Does

| Capability | Description |
|---|---|
| 🧩 **Component Extraction** | Lists all Activities, Services, Broadcast Receivers, and Content Providers declared in the manifest |
| 🔒 **Permission Analysis** | Identifies all declared and requested permissions with human-readable explanations of their likely purpose |
| 📚 **Library Detection** | Detects major SDKs, frameworks, and third-party dependencies bundled in the APK |
| 🗺️ **Screen Mapping** | Maps Activities and layout resources to infer the app's navigation structure |
| 🏗️ **Architecture Summary** | Summarizes the app's likely architecture, feature set, and design patterns |
| 🚨 **Risk Flagging** | Flags sensitive permissions, exported components, potential network endpoints, and privacy-relevant indicators |
| 📄 **Report Generation** | Outputs a complete, human-readable App Blueprint Report in Markdown and structured JSON |

## What It Does NOT Do

- ❌ **No APK modification** — never alters, patches, or tampers with APK files
- ❌ **No repacking or signing** — never rebuilds or re-signs APK files
- ❌ **No cracking** — never removes license checks, DRM, or security controls
- ❌ **No malware distribution** — never facilitates creation or distribution of
  malicious software
- ❌ **No network uploads** — all processing happens locally on your machine

---

## Installation

### Prerequisites

- **Python 3.10+**
- **Apktool** (optional, for deeper resource analysis) —
  [Installation guide](https://apktool.org/docs/install)
- **JADX** (optional, for decompiled source inspection) —
  [GitHub releases](https://github.com/skylot/jadx/releases)

### Install from source

```bash
git clone https://github.com/your-username/apk-blueprint-analyzer.git
cd apk-blueprint-analyzer
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -e ".[dev]"
```

### Verify installation

```bash
apk-blueprint --help
```

---

## Quick Start

### Analyze an APK

```bash
apk-blueprint analyze path/to/app.apk --output reports/myapp
```

Or run as a Python module:

```bash
python -m apk_blueprint_analyzer analyze path/to/app.apk --output reports/myapp
```

### Output structure

After analysis, the output directory will contain:

```
reports/myapp/
├── report.md          # Full App Blueprint Report
├── blueprint.json     # Structured analysis data (machine-readable)
├── permissions.md     # Detailed permission breakdown
├── components.md      # Activities, Services, Receivers, Providers
├── libraries.md       # Detected SDKs and third-party libraries
├── screens.md         # Inferred screen/navigation map
└── risks.md           # Security and privacy risk flags
```

### Additional commands

```bash
# Show only permissions
apk-blueprint permissions path/to/app.apk

# Show only components
apk-blueprint components path/to/app.apk

# Get JSON output to stdout
apk-blueprint analyze path/to/app.apk --format json
```

---

## Example Output

See [`examples/sample_report.md`](examples/sample_report.md) for a full sample
report.

**Snippet from `permissions.md`:**

```markdown
## Requested Permissions

| Permission | Protection Level | Purpose |
|---|---|---|
| `android.permission.INTERNET` | Normal | Network access for API calls or content loading |
| `android.permission.CAMERA` | Dangerous | Camera access, likely for photo capture or QR scanning |
| `android.permission.ACCESS_FINE_LOCATION` | Dangerous | Precise GPS location, used for maps or location-based features |
```

---

## Architecture

The tool is organized into modular, single-responsibility components:

```
src/apk_blueprint_analyzer/
├── cli.py                 # Click-based CLI commands
├── apk_parser.py          # APK extraction and file handling
├── manifest_analyzer.py   # AndroidManifest.xml parsing
├── component_extractor.py # Activity/Service/Receiver/Provider extraction
├── permission_analyzer.py # Permission identification and explanation
├── library_detector.py    # SDK and library fingerprinting
├── screen_mapper.py       # Screen/navigation inference from layouts
├── risk_scanner.py        # Security and privacy risk detection
├── report_generator.py    # Markdown and JSON report assembly
└── utils.py               # Shared utilities and helpers
```

See [`docs/architecture.md`](docs/architecture.md) for a detailed design
overview. See [`docs/usage.md`](docs/usage.md) for complete usage
documentation.

---

## Extending with New Analyzers

APK Blueprint Analyzer is designed to be extensible. To add a new analyzer:

1. Create a new module in `src/apk_blueprint_analyzer/`
2. Implement a function or class that accepts parsed APK data
3. Register it in the report generation pipeline
4. Add tests and update documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details.

---

## Credits

This tool builds on the work of excellent open-source projects:

- **[Apktool](https://apktool.org/)** — APK resource decoding (Apache 2.0)
- **[JADX](https://github.com/skylot/jadx)** — DEX-to-Java decompiler (Apache
  2.0)
- **[Click](https://click.palletsprojects.com/)** — CLI framework (BSD-3)
- **[Rich](https://github.com/Textualize/rich)** — Terminal formatting (MIT)

Users must respect the licenses of these third-party tools and of any APK files
they analyze.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on scope, setup, and pull request expectations.

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for
details.

> **Note**: This license covers the APK Blueprint Analyzer tool itself. APK
> files you analyze, and third-party tools like Apktool and JADX, are governed
> by their own respective licenses. You are responsible for complying with all
> applicable licenses and terms of service.
