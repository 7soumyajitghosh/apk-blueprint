"""Tests for the component extractor."""

from __future__ import annotations

from xml.etree import ElementTree as ET

import pytest

from apk_blueprint_analyzer.component_extractor import (
    ComponentExtractor,
    ComponentInfo,
    IntentFilterInfo,
)


def _parse_manifest(xml: str) -> ET.Element:
    """Parse an XML string and return the root element."""
    return ET.fromstring(xml)


class TestComponentExtractor:
    """Test suite for ComponentExtractor."""

    def test_extract_activities(self, sample_manifest_xml: str) -> None:
        """All activities are extracted from the manifest."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        activities = extractor.get_by_type("activity")
        names = [a.name for a in activities]
        assert ".SplashActivity" in names
        assert ".MainActivity" in names
        assert ".LoginActivity" in names
        assert ".SettingsActivity" in names
        assert ".DeepLinkActivity" in names
        assert len(activities) == 5

    def test_extract_services(self, sample_manifest_xml: str) -> None:
        """All services are extracted."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        services = extractor.get_by_type("service")
        assert len(services) == 2

    def test_extract_receivers(self, sample_manifest_xml: str) -> None:
        """All receivers are extracted."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        receivers = extractor.get_by_type("receiver")
        assert len(receivers) == 1
        assert receivers[0].name == ".BootReceiver"

    def test_extract_providers(self, sample_manifest_xml: str) -> None:
        """All providers are extracted."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        providers = extractor.get_by_type("provider")
        assert len(providers) == 1
        assert providers[0].name == ".data.AppContentProvider"

    def test_launcher_detection(self, sample_manifest_xml: str) -> None:
        """Launcher activity is correctly identified."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        launchers = extractor.get_launcher_activities()
        assert len(launchers) == 1
        assert launchers[0].name == ".SplashActivity"
        assert launchers[0].is_launcher is True

    def test_exported_components(self, sample_manifest_xml: str) -> None:
        """Exported components are correctly identified."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        exported = extractor.get_exported()
        exported_names = {c.name for c in exported}
        assert ".SplashActivity" in exported_names
        assert ".SettingsActivity" in exported_names
        assert ".data.AppContentProvider" in exported_names
        # MainActivity is not exported.
        assert ".MainActivity" not in exported_names

    def test_permission_on_component(self, sample_manifest_xml: str) -> None:
        """Permission guard on a component is extracted."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        services = extractor.get_by_type("service")
        messaging = [s for s in services if "Messaging" in s.name]
        assert len(messaging) == 1
        assert messaging[0].permission == "com.example.testapp.permission.CUSTOM"

    def test_intent_filter_actions(self, sample_manifest_xml: str) -> None:
        """Intent filter actions are correctly parsed."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        launchers = extractor.get_launcher_activities()
        assert len(launchers) == 1
        filters = launchers[0].intent_filters
        assert len(filters) == 1
        assert "android.intent.action.MAIN" in filters[0].actions
        assert "android.intent.category.LAUNCHER" in filters[0].categories

    def test_deeplink_data(self, sample_manifest_xml: str) -> None:
        """Deep link scheme and host are extracted from intent filters."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        activities = extractor.get_by_type("activity")
        deeplink = [a for a in activities if "DeepLink" in a.name]
        assert len(deeplink) == 1
        assert len(deeplink[0].intent_filters) == 1
        filt = deeplink[0].intent_filters[0]
        assert "https" in filt.data_schemes
        assert "example.com" in filt.data_hosts

    def test_empty_application(self) -> None:
        """Empty application element produces no components."""
        xml = '<manifest package="test"><application /></manifest>'
        root = _parse_manifest(xml)
        extractor = ComponentExtractor(root)
        assert extractor.extract() == []

    def test_no_application_element(self) -> None:
        """Missing application element produces no components."""
        xml = '<manifest package="test" />'
        root = _parse_manifest(xml)
        extractor = ComponentExtractor(root)
        assert extractor.extract() == []

    def test_to_dict(self, sample_manifest_xml: str) -> None:
        """ComponentInfo.to_dict produces correct structure."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        components = extractor.extract()
        assert len(components) > 0
        d = components[0].to_dict()
        assert "component_type" in d
        assert "name" in d
        assert "exported" in d
        assert "intent_filters" in d

    def test_caches_results(self, sample_manifest_xml: str) -> None:
        """Repeated calls return cached results."""
        root = _parse_manifest(sample_manifest_xml)
        extractor = ComponentExtractor(root)
        r1 = extractor.extract()
        r2 = extractor.extract()
        assert r1 is r2
