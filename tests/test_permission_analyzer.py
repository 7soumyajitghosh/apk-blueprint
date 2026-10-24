"""Tests for the permission analyzer."""

from __future__ import annotations

import pytest

from apk_blueprint_analyzer.permission_analyzer import (
    PermissionAnalyzer,
    PermissionDetail,
    ProtectionLevel,
    RiskCategory,
)


class TestPermissionAnalyzer:
    """Test suite for PermissionAnalyzer."""

    def test_known_permission_lookup(self) -> None:
        """Known permissions are matched with correct metadata."""
        analyzer = PermissionAnalyzer(["android.permission.INTERNET"])
        results = analyzer.analyze()
        assert len(results) == 1
        perm = results[0]
        assert perm.name == "android.permission.INTERNET"
        assert perm.short_name == "INTERNET"
        assert perm.protection_level == ProtectionLevel.NORMAL
        assert perm.risk_category == RiskCategory.LOW

    def test_dangerous_permission(self) -> None:
        """Dangerous permissions are correctly classified."""
        analyzer = PermissionAnalyzer(["android.permission.CAMERA"])
        results = analyzer.analyze()
        perm = results[0]
        assert perm.protection_level == ProtectionLevel.DANGEROUS
        assert perm.risk_category == RiskCategory.HIGH

    def test_critical_permission(self) -> None:
        """Critical-risk permissions are correctly classified."""
        analyzer = PermissionAnalyzer(["android.permission.SEND_SMS"])
        results = analyzer.analyze()
        perm = results[0]
        assert perm.risk_category == RiskCategory.CRITICAL

    def test_unknown_permission(self) -> None:
        """Unknown permissions get sensible defaults."""
        analyzer = PermissionAnalyzer(["com.custom.unknown.PERM"])
        results = analyzer.analyze()
        perm = results[0]
        assert perm.protection_level == ProtectionLevel.UNKNOWN
        assert perm.risk_category == RiskCategory.UNKNOWN
        assert "Custom or uncommon" in perm.description

    def test_multiple_permissions(self) -> None:
        """Multiple permissions are all analyzed."""
        perms = [
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        analyzer = PermissionAnalyzer(perms)
        results = analyzer.analyze()
        assert len(results) == 3

    def test_get_dangerous_filter(self) -> None:
        """get_dangerous returns only dangerous-level permissions."""
        perms = [
            "android.permission.INTERNET",        # normal
            "android.permission.CAMERA",           # dangerous
            "android.permission.VIBRATE",          # normal
            "android.permission.READ_CONTACTS",    # dangerous
        ]
        analyzer = PermissionAnalyzer(perms)
        dangerous = analyzer.get_dangerous()
        assert len(dangerous) == 2
        names = {p.name for p in dangerous}
        assert "android.permission.CAMERA" in names
        assert "android.permission.READ_CONTACTS" in names

    def test_get_high_risk_filter(self) -> None:
        """get_high_risk returns high and critical risk permissions."""
        perms = [
            "android.permission.INTERNET",            # low risk
            "android.permission.SEND_SMS",             # critical
            "android.permission.ACCESS_FINE_LOCATION", # high
        ]
        analyzer = PermissionAnalyzer(perms)
        high = analyzer.get_high_risk()
        assert len(high) == 2

    def test_get_summary(self) -> None:
        """get_summary returns correct counts by protection level."""
        perms = [
            "android.permission.INTERNET",    # normal
            "android.permission.CAMERA",      # dangerous
            "android.permission.SEND_SMS",    # dangerous
        ]
        analyzer = PermissionAnalyzer(perms)
        summary = analyzer.get_summary()
        assert summary.get("normal") == 1
        assert summary.get("dangerous") == 2

    def test_empty_permissions(self) -> None:
        """Empty permission list produces empty results."""
        analyzer = PermissionAnalyzer([])
        results = analyzer.analyze()
        assert results == []

    def test_to_dict(self) -> None:
        """PermissionDetail.to_dict produces correct structure."""
        analyzer = PermissionAnalyzer(["android.permission.CAMERA"])
        results = analyzer.analyze()
        d = results[0].to_dict()
        assert d["name"] == "android.permission.CAMERA"
        assert d["protection_level"] == "dangerous"
        assert d["risk_category"] == "high"
        assert "description" in d

    def test_caches_results(self) -> None:
        """Repeated calls return cached results."""
        analyzer = PermissionAnalyzer(["android.permission.INTERNET"])
        r1 = analyzer.analyze()
        r2 = analyzer.analyze()
        assert r1 is r2
