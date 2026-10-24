"""Tests for the report generator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apk_blueprint_analyzer.apk_parser import ApkMetadata
from apk_blueprint_analyzer.component_extractor import ComponentInfo, IntentFilterInfo
from apk_blueprint_analyzer.library_detector import LibraryMatch
from apk_blueprint_analyzer.manifest_analyzer import ManifestInfo
from apk_blueprint_analyzer.permission_analyzer import (
    PermissionDetail,
    ProtectionLevel,
    RiskCategory,
)
from apk_blueprint_analyzer.report_generator import AnalysisResult, ReportGenerator
from apk_blueprint_analyzer.risk_scanner import RiskFinding, Severity
from apk_blueprint_analyzer.screen_mapper import ScreenInfo


def _make_sample_result() -> AnalysisResult:
    """Create a sample AnalysisResult for testing."""
    metadata = ApkMetadata(
        file_path="/tmp/test.apk",
        file_name="test.apk",
        file_size=1048576,
        file_size_human="1.0 MB",
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        entry_count=150,
        file_list=["AndroidManifest.xml", "classes.dex"],
        has_manifest=True,
        has_classes_dex=True,
        dex_count=1,
    )

    manifest = ManifestInfo(
        package_name="com.example.testapp",
        version_code=10,
        version_name="1.0.0",
        min_sdk=21,
        target_sdk=34,
        uses_permissions=["android.permission.INTERNET"],
        permissions_defined=["com.example.testapp.CUSTOM"],
    )

    components = [
        ComponentInfo(
            component_type="activity",
            name=".MainActivity",
            exported=True,
            is_launcher=True,
            intent_filters=[
                IntentFilterInfo(
                    actions=["android.intent.action.MAIN"],
                    categories=["android.intent.category.LAUNCHER"],
                )
            ],
        ),
        ComponentInfo(
            component_type="service",
            name=".SyncService",
            exported=False,
        ),
    ]

    permissions = [
        PermissionDetail(
            name="android.permission.INTERNET",
            short_name="INTERNET",
            protection_level=ProtectionLevel.NORMAL,
            risk_category=RiskCategory.LOW,
            description="Network access.",
            group="network",
        ),
    ]

    libraries = [
        LibraryMatch(
            name="OkHttp",
            category="networking",
            package_pattern="okhttp3",
            description="HTTP client.",
            privacy_relevant=False,
        ),
    ]

    screens = [
        ScreenInfo(
            activity_name=".MainActivity",
            short_name="MainActivity",
            is_launcher=True,
            inferred_purpose="Main / home screen",
        ),
    ]

    risks = [
        RiskFinding(
            title="Exported activity without permission",
            severity=Severity.MEDIUM,
            category="exported-component",
            description="Test risk.",
            recommendation="Review export.",
            evidence=[".MainActivity"],
        ),
    ]

    return AnalysisResult(
        metadata=metadata,
        manifest=manifest,
        components=components,
        permissions=permissions,
        libraries=libraries,
        screens=screens,
        risks=risks,
    )


class TestAnalysisResult:
    """Test suite for AnalysisResult."""

    def test_to_dict_structure(self) -> None:
        """to_dict returns a well-structured dictionary."""
        result = _make_sample_result()
        d = result.to_dict()
        assert d["tool"] == "APK Blueprint Analyzer"
        assert "version" in d
        assert "timestamp" in d
        assert "metadata" in d
        assert "manifest" in d
        assert "components" in d
        assert "permissions" in d
        assert "libraries" in d
        assert "screens" in d
        assert "risks" in d

    def test_to_dict_is_json_serializable(self) -> None:
        """to_dict output can be serialized to JSON without errors."""
        result = _make_sample_result()
        d = result.to_dict()
        json_str = json.dumps(d, indent=2)
        assert len(json_str) > 0
        # Round-trip check.
        parsed = json.loads(json_str)
        assert parsed["manifest"]["package_name"] == "com.example.testapp"


class TestReportGenerator:
    """Test suite for ReportGenerator."""

    def test_generate_all_creates_files(self, tmp_path: Path) -> None:
        """generate_all creates all expected report files."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        out = generator.generate_all()

        assert out.exists()
        assert (out / "report.md").exists()
        assert (out / "blueprint.json").exists()
        assert (out / "permissions.md").exists()
        assert (out / "components.md").exists()
        assert (out / "libraries.md").exists()
        assert (out / "screens.md").exists()
        assert (out / "risks.md").exists()

    def test_blueprint_json_is_valid(self, tmp_path: Path) -> None:
        """blueprint.json contains valid JSON."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        json_path = output_dir / "blueprint.json"
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["manifest"]["package_name"] == "com.example.testapp"
        assert data["tool"] == "APK Blueprint Analyzer"

    def test_report_md_contains_package(self, tmp_path: Path) -> None:
        """report.md includes the package name."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        content = (output_dir / "report.md").read_text(encoding="utf-8")
        assert "com.example.testapp" in content

    def test_permissions_md_content(self, tmp_path: Path) -> None:
        """permissions.md lists the permissions."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        content = (output_dir / "permissions.md").read_text(encoding="utf-8")
        assert "INTERNET" in content

    def test_components_md_content(self, tmp_path: Path) -> None:
        """components.md lists the components."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        content = (output_dir / "components.md").read_text(encoding="utf-8")
        assert "MainActivity" in content
        assert "SyncService" in content

    def test_risks_md_content(self, tmp_path: Path) -> None:
        """risks.md includes risk findings."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        content = (output_dir / "risks.md").read_text(encoding="utf-8")
        assert "Exported activity" in content

    def test_screens_md_content(self, tmp_path: Path) -> None:
        """screens.md includes screen entries."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        content = (output_dir / "screens.md").read_text(encoding="utf-8")
        assert "MainActivity" in content

    def test_libraries_md_content(self, tmp_path: Path) -> None:
        """libraries.md includes detected libraries."""
        result = _make_sample_result()
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(result, output_dir)
        generator.generate_all()

        content = (output_dir / "libraries.md").read_text(encoding="utf-8")
        assert "OkHttp" in content
