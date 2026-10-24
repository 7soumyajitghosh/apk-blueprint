# Usage Guide

## Installation

### From source (recommended during development)

```bash
git clone https://github.com/your-username/apk-blueprint-analyzer.git
cd apk-blueprint-analyzer
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows
pip install -e ".[dev]"
```

### Prerequisites

- **Python 3.10+** is required.
- **Apktool** (optional) — for decoding binary XML resources. Install from
  [apktool.org](https://apktool.org/docs/install).
- **JADX** (optional) — for viewing decompiled Java source. Install from
  [GitHub releases](https://github.com/skylot/jadx/releases).

> **Note:** APK Blueprint Analyzer works without Apktool or JADX. However,
> some APKs contain binary-encoded `AndroidManifest.xml` files that cannot be
> parsed without prior decoding. If you see a warning about binary manifests,
> decode the APK with Apktool first:
>
> ```bash
> apktool d your_app.apk -o decoded_app/
> ```

## CLI Commands

### `analyze` — Full Analysis

Run a complete analysis and generate all report files:

```bash
apk-blueprint analyze app.apk --output reports/myapp
```

**Arguments:**
- `APK_PATH` (required) — Path to the `.apk` file.

**Options:**
- `--output`, `-o` — Output directory for reports. Defaults to
  `<apk_name>_blueprint/`.
- `--format`, `-f` — Output format: `full` (default, writes files) or `json`
  (prints JSON to stdout).
- `--no-disclaimer` — Suppress the legal notice banner.

**Examples:**

```bash
# Analyze and save reports to a custom directory
apk-blueprint analyze myapp.apk -o analysis/myapp

# Get JSON output to stdout (pipe to jq, file, etc.)
apk-blueprint analyze myapp.apk -f json > blueprint.json

# Run as a Python module
python -m apk_blueprint_analyzer analyze myapp.apk -o reports/
```

### `permissions` — Permission Analysis

Show permission analysis in the terminal without generating files:

```bash
apk-blueprint permissions app.apk
```

Displays a Rich-formatted table showing each permission, its protection level,
risk category, and description.

### `components` — Component Listing

Show all app components in the terminal:

```bash
apk-blueprint components app.apk
```

Displays tables grouped by component type (Activities, Services, Receivers,
Providers) with export status and permission guards.

### `--help`

Every command supports `--help`:

```bash
apk-blueprint --help
apk-blueprint analyze --help
apk-blueprint permissions --help
```

## Output Files

After running `analyze`, the output directory contains:

| File | Description |
|---|---|
| `report.md` | Executive summary — overview, component counts, risk highlights |
| `blueprint.json` | Machine-readable JSON with all analysis data |
| `permissions.md` | Full permission table with levels, risks, descriptions |
| `components.md` | All Activities, Services, Receivers, Providers with details |
| `libraries.md` | Detected SDKs and third-party libraries |
| `screens.md` | Inferred screen/navigation map from Activities and layouts |
| `risks.md` | Security and privacy findings with severity and recommendations |

## Working with Binary Manifests

Some APKs contain binary-encoded XML that Python's standard XML parser cannot
read directly. If you encounter a "binary manifest" warning:

1. Install [Apktool](https://apktool.org/docs/install)
2. Decode the APK:
   ```bash
   apktool d your_app.apk -o decoded_app/
   ```
3. Run the analyzer on the decoded manifest:
   ```bash
   # The tool will find the decoded AndroidManifest.xml in the extracted APK
   apk-blueprint analyze decoded_app/your_app.apk -o reports/
   ```

## Programmatic Use

You can also use the analyzer modules directly in Python:

```python
from apk_blueprint_analyzer.apk_parser import ApkParser
from apk_blueprint_analyzer.manifest_analyzer import ManifestAnalyzer
from apk_blueprint_analyzer.permission_analyzer import PermissionAnalyzer

# Parse an APK
with ApkParser("app.apk") as parser:
    metadata = parser.get_metadata()
    print(f"Package has {metadata.entry_count} files")

# Analyze permissions
analyzer = PermissionAnalyzer([
    "android.permission.CAMERA",
    "android.permission.INTERNET",
])
for perm in analyzer.analyze():
    print(f"{perm.short_name}: {perm.risk_category.value} — {perm.description}")
```

## Troubleshooting

### "Not a valid APK (ZIP) file"

The file may be corrupted or not an APK. Verify it opens in a ZIP tool.

### "Failed to parse AndroidManifest.xml"

The manifest is binary-encoded. Decode the APK with Apktool first.

### No libraries detected

Library detection relies on matching file paths inside the APK. If the app
uses ProGuard or R8 with aggressive obfuscation, library package names may
be renamed, reducing detection accuracy.

### Permission shows as "unknown"

The built-in permission database covers 35+ common permissions. Custom or
uncommon permissions will show as "unknown" with a generic description.
