"""Tests for the AndroidManifest.xml analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from apk_blueprint_analyzer.manifest_analyzer import (
    ManifestAnalyzer,
    ManifestInfo,
    parse_manifest_from_string,
)


class TestManifestAnalyzer:
    """Test suite for ManifestAnalyzer."""

    def test_parse_package_name(self, sample_manifest_path: Path) -> None:
        """Parsing extracts the correct package name."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info = analyzer.parse()
        assert info.package_name == "com.example.testapp"

    def test_parse_version_info(self, sample_manifest_path: Path) -> None:
        """Parsing extracts version code and name."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info = analyzer.parse()
        assert info.version_code == 42
        assert info.version_name == "2.1.0"

    def test_parse_sdk_versions(self, sample_manifest_path: Path) -> None:
        """Parsing extracts min and target SDK versions."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info = analyzer.parse()
        assert info.min_sdk == 21
        assert info.target_sdk == 34

    def test_parse_uses_permissions(self, sample_manifest_path: Path) -> None:
        """Parsing extracts all uses-permission entries."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info = analyzer.parse()
        assert "android.permission.INTERNET" in info.uses_permissions
        assert "android.permission.CAMERA" in info.uses_permissions
        assert "android.permission.ACCESS_FINE_LOCATION" in info.uses_permissions
        assert "android.permission.READ_CONTACTS" in info.uses_permissions
        assert "android.permission.SEND_SMS" in info.uses_permissions
        assert len(info.uses_permissions) == 5

    def test_parse_custom_permissions(self, sample_manifest_path: Path) -> None:
        """Parsing extracts custom permission definitions."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info = analyzer.parse()
        assert "com.example.testapp.permission.CUSTOM" in info.permissions_defined

    def test_parse_caches_result(self, sample_manifest_path: Path) -> None:
        """Repeated calls return the same cached object."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info1 = analyzer.parse()
        info2 = analyzer.parse()
        assert info1 is info2

    def test_missing_manifest_raises(self, tmp_path: Path) -> None:
        """FileNotFoundError raised for missing manifest."""
        missing = tmp_path / "nonexistent.xml"
        analyzer = ManifestAnalyzer(missing)
        with pytest.raises(FileNotFoundError):
            analyzer.parse()

    def test_invalid_xml_raises(self, tmp_path: Path) -> None:
        """ValueError raised for unparseable XML."""
        bad_file = tmp_path / "AndroidManifest.xml"
        bad_file.write_bytes(b"\x00\x01\x02binary garbage")
        analyzer = ManifestAnalyzer(bad_file)
        with pytest.raises(ValueError, match="Failed to parse"):
            analyzer.parse()

    def test_to_dict(self, sample_manifest_path: Path) -> None:
        """to_dict returns a serializable dictionary."""
        analyzer = ManifestAnalyzer(sample_manifest_path)
        info = analyzer.parse()
        d = info.to_dict()
        assert d["package_name"] == "com.example.testapp"
        assert isinstance(d["uses_permissions"], list)
        assert isinstance(d["permissions_defined"], list)

    def test_minimal_manifest(self, tmp_path: Path) -> None:
        """Parsing a minimal manifest with no permissions or SDK works."""
        minimal = tmp_path / "AndroidManifest.xml"
        minimal.write_text(
            '<?xml version="1.0"?>\n<manifest package="com.minimal.app" />\n',
            encoding="utf-8",
        )
        analyzer = ManifestAnalyzer(minimal)
        info = analyzer.parse()
        assert info.package_name == "com.minimal.app"
        assert info.uses_permissions == []
        assert info.min_sdk is None
        assert info.target_sdk is None


class TestParseManifestFromString:
    """Test suite for the parse_manifest_from_string helper."""

    def test_basic_parsing(self, sample_manifest_xml: str) -> None:
        """String-based parsing extracts correct data."""
        info = parse_manifest_from_string(sample_manifest_xml)
        assert info.package_name == "com.example.testapp"
        assert info.version_code == 42

    def test_permissions_from_string(self, sample_manifest_xml: str) -> None:
        """String-based parsing extracts permissions."""
        info = parse_manifest_from_string(sample_manifest_xml)
        assert len(info.uses_permissions) == 5

    def test_invalid_string_raises(self) -> None:
        """ValueError raised for invalid XML string."""
        with pytest.raises(ValueError):
            parse_manifest_from_string("not valid xml <<>>")
