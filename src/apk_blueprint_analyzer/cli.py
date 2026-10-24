"""Command-line interface for APK Blueprint Analyzer.

Provides the ``apk-blueprint`` CLI with commands for analyzing APK files
and generating App Blueprint Reports. Built with Click for clean argument
parsing and helpful ``--help`` output.

Usage::

    apk-blueprint analyze path/to/app.apk --output reports/myapp
    python -m apk_blueprint_analyzer analyze path/to/app.apk --output reports/myapp
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apk_blueprint_analyzer import __project__, __version__
from apk_blueprint_analyzer.apk_parser import ApkParser
from apk_blueprint_analyzer.component_extractor import ComponentExtractor
from apk_blueprint_analyzer.library_detector import LibraryDetector
from apk_blueprint_analyzer.manifest_analyzer import ManifestAnalyzer
from apk_blueprint_analyzer.permission_analyzer import PermissionAnalyzer
from apk_blueprint_analyzer.report_generator import AnalysisResult, ReportGenerator
from apk_blueprint_analyzer.risk_scanner import RiskScanner
from apk_blueprint_analyzer.screen_mapper import ScreenMapper

console = Console()

# ── Legal disclaimer shown before analysis ───────────────────────────

_DISCLAIMER = (
    "[bold yellow]⚠️  Legal Notice[/bold yellow]\n\n"
    "This tool is intended [bold]only[/bold] for APKs you own or are "
    "explicitly authorized to analyze.\n"
    "Do not use it to circumvent security protections, crack paid apps, "
    "remove license checks,\n"
    "or distribute modified APKs. Unauthorized analysis may violate "
    "applicable laws.\n\n"
    "All processing is performed [bold]locally[/bold]. No data is "
    "transmitted over the network."
)


def _show_disclaimer() -> None:
    """Display the legal disclaimer panel."""
    console.print(Panel(_DISCLAIMER, title="APK Blueprint Analyzer", border_style="yellow"))
    console.print()


def _run_analysis(apk_path: str, output_dir: str | None) -> AnalysisResult:
    """Execute the full analysis pipeline on an APK file.

    Args:
        apk_path: Path to the APK file.
        output_dir: Optional output directory for decoded manifest.

    Returns:
        Aggregated :class:`AnalysisResult`.

    Raises:
        click.ClickException: On any analysis error.
    """
    apk_file = Path(apk_path)

    # Validate APK exists.
    if not apk_file.exists():
        raise click.ClickException(f"APK file not found: {apk_file}")
    if not apk_file.suffix.lower() == ".apk":
        raise click.ClickException(
            f"File does not have .apk extension: {apk_file}"
        )

    console.print(f"[bold blue]📦 Analyzing:[/bold blue] {apk_file.name}")
    console.print()

    try:
        with ApkParser(apk_file) as parser:
            # Step 1: APK metadata.
            console.print("  [dim]→ Extracting APK metadata...[/dim]")
            metadata = parser.get_metadata()

            if not metadata.has_manifest:
                raise click.ClickException(
                    "APK does not contain AndroidManifest.xml. "
                    "The file may be corrupted or not a valid APK."
                )

            # Step 2: Extract APK to temp dir for manifest parsing.
            # We only need the decoded manifest; binary manifests require
            # external tools like Apktool for full decoding.
            console.print("  [dim]→ Extracting APK contents...[/dim]")
            work_dir = Path(tempfile.mkdtemp(prefix="apk_blueprint_"))
            parser.extract_to(work_dir)

            manifest_path = work_dir / "AndroidManifest.xml"

            # Step 3: Parse manifest.
            console.print("  [dim]→ Parsing AndroidManifest.xml...[/dim]")
            try:
                manifest_analyzer = ManifestAnalyzer(manifest_path)
                manifest_info = manifest_analyzer.parse()
            except ValueError as exc:
                console.print(
                    f"  [yellow]⚠ Manifest parsing limited: {exc}[/yellow]"
                )
                console.print(
                    "  [yellow]  Tip: Use Apktool to decode the APK first "
                    "for full manifest analysis.[/yellow]"
                )
                # Create a minimal manifest info from what we can extract.
                from apk_blueprint_analyzer.manifest_analyzer import ManifestInfo
                manifest_info = ManifestInfo(package_name="(binary manifest)")

            # Step 4: Extract components.
            console.print("  [dim]→ Extracting components...[/dim]")
            if manifest_info.raw_xml_root is not None:
                comp_extractor = ComponentExtractor(manifest_info.raw_xml_root)
                components = comp_extractor.extract()
            else:
                components = []

            # Step 5: Analyze permissions.
            console.print("  [dim]→ Analyzing permissions...[/dim]")
            perm_analyzer = PermissionAnalyzer(manifest_info.uses_permissions)
            permissions = perm_analyzer.analyze()

            # Step 6: Detect libraries.
            console.print("  [dim]→ Detecting libraries...[/dim]")
            lib_detector = LibraryDetector(metadata.file_list)
            libraries = lib_detector.detect()

            # Step 7: Map screens.
            console.print("  [dim]→ Mapping screens...[/dim]")
            activities = [c for c in components if c.component_type == "activity"]
            layout_files = parser.get_layout_files()
            screen_mapper = ScreenMapper(activities, layout_files)
            screens = screen_mapper.map_screens()

            # Step 8: Scan for risks.
            console.print("  [dim]→ Scanning for risks...[/dim]")
            risk_scanner = RiskScanner(
                manifest_info=manifest_info,
                components=components,
                permissions=permissions,
                libraries=libraries,
                file_paths=metadata.file_list,
            )
            risks = risk_scanner.scan()

            # Assemble result.
            result = AnalysisResult(
                metadata=metadata,
                manifest=manifest_info,
                components=components,
                permissions=permissions,
                libraries=libraries,
                screens=screens,
                risks=risks,
            )

            console.print()
            return result

    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc))
    except Exception as exc:
        raise click.ClickException(f"Unexpected error during analysis: {exc}")


# ── CLI Group ────────────────────────────────────────────────────────

@click.group()
@click.version_option(version=__version__, prog_name=__project__)
def main() -> None:
    """APK Blueprint Analyzer — Understand Android apps through safe static analysis.

    Perform read-only static analysis on Android APK files and generate
    comprehensive App Blueprint Reports.

    All processing is local. No data is transmitted over the network.
    Only analyze APKs you own or are authorized to inspect.
    """
    pass


# ── Analyze Command ─────────────────────────────────────────────────

@main.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output directory for reports. Defaults to '<apk_name>_blueprint/'.",
)
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["full", "json"], case_sensitive=False),
    default="full",
    help="Output format: 'full' for all report files, 'json' for JSON to stdout.",
)
@click.option(
    "--no-disclaimer",
    is_flag=True,
    default=False,
    help="Suppress the legal disclaimer notice.",
)
def analyze(
    apk_path: str,
    output: str | None,
    output_format: str,
    no_disclaimer: bool,
) -> None:
    """Analyze an APK file and generate a comprehensive blueprint report.

    APK_PATH is the path to the .apk file to analyze.

    \b
    Examples:
        apk-blueprint analyze app.apk
        apk-blueprint analyze app.apk --output reports/myapp
        apk-blueprint analyze app.apk --format json
    """
    if not no_disclaimer:
        _show_disclaimer()

    result = _run_analysis(apk_path, output)

    if output_format == "json":
        # JSON to stdout.
        click.echo(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        # Generate full report files.
        if output is None:
            apk_name = Path(apk_path).stem
            output = f"{apk_name}_blueprint"

        generator = ReportGenerator(result, output)
        out_path = generator.generate_all()

        console.print(
            f"[bold green]✅ Blueprint generated![/bold green] "
            f"Reports written to: [bold]{out_path}[/bold]"
        )
        console.print()

        # Show file listing.
        table = Table(title="Generated Reports", show_header=True)
        table.add_column("File", style="cyan")
        table.add_column("Description")
        table.add_row("report.md", "Full App Blueprint Report")
        table.add_row("blueprint.json", "Structured data (machine-readable)")
        table.add_row("permissions.md", "Permission breakdown")
        table.add_row("components.md", "Component listing")
        table.add_row("libraries.md", "Detected libraries & SDKs")
        table.add_row("screens.md", "Screen & navigation map")
        table.add_row("risks.md", "Security & privacy risk assessment")
        console.print(table)


# ── Permissions Command ──────────────────────────────────────────────

@main.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--no-disclaimer", is_flag=True, default=False, help="Suppress disclaimer.")
def permissions(apk_path: str, no_disclaimer: bool) -> None:
    """Show permission analysis for an APK file.

    APK_PATH is the path to the .apk file to analyze.
    """
    if not no_disclaimer:
        _show_disclaimer()

    result = _run_analysis(apk_path, None)

    if not result.permissions:
        console.print("[dim]No permissions declared.[/dim]")
        return

    table = Table(title="Permissions", show_header=True)
    table.add_column("Permission", style="cyan", no_wrap=True)
    table.add_column("Level")
    table.add_column("Risk")
    table.add_column("Purpose", max_width=50)

    for perm in result.permissions:
        risk_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(perm.risk_category.value, "dim")
        table.add_row(
            perm.short_name,
            perm.protection_level.value,
            f"[{risk_style}]{perm.risk_category.value}[/{risk_style}]",
            perm.description,
        )

    console.print(table)


# ── Components Command ───────────────────────────────────────────────

@main.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--no-disclaimer", is_flag=True, default=False, help="Suppress disclaimer.")
def components(apk_path: str, no_disclaimer: bool) -> None:
    """Show component listing for an APK file.

    APK_PATH is the path to the .apk file to analyze.
    """
    if not no_disclaimer:
        _show_disclaimer()

    result = _run_analysis(apk_path, None)

    if not result.components:
        console.print("[dim]No components found.[/dim]")
        return

    for ctype in ("activity", "service", "receiver", "provider"):
        comps = [c for c in result.components if c.component_type == ctype]
        if comps:
            table = Table(title=f"{ctype.capitalize()}s", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("Exported")
            table.add_column("Permission")

            for c in comps:
                exported = "✅" if c.exported else "🔒"
                launcher = " 🚀" if c.is_launcher else ""
                table.add_row(
                    c.name + launcher,
                    exported,
                    c.permission or "-",
                )

            console.print(table)
            console.print()
