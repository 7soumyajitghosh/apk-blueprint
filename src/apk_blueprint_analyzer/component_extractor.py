"""Android component extractor.

Extracts all four types of Android application components from the
parsed ``AndroidManifest.xml``:

- **Activities** — UI screens
- **Services** — background processing
- **Broadcast Receivers** — system/app event handlers
- **Content Providers** — structured data interfaces

For each component, the extractor captures its fully-qualified class name,
intent filters, exported status, and other relevant attributes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET

from apk_blueprint_analyzer.utils import android_attr


@dataclass
class IntentFilterInfo:
    """Parsed intent filter from a component declaration.

    Attributes:
        actions: List of action strings.
        categories: List of category strings.
        data_schemes: List of URI scheme strings.
        data_hosts: List of host strings.
    """

    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data_schemes: list[str] = field(default_factory=list)
    data_hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "actions": self.actions,
            "categories": self.categories,
            "data_schemes": self.data_schemes,
            "data_hosts": self.data_hosts,
        }


@dataclass
class ComponentInfo:
    """Information about a single Android component.

    Attributes:
        component_type: One of ``"activity"``, ``"service"``,
            ``"receiver"``, or ``"provider"``.
        name: Fully-qualified class name.
        exported: Whether the component is exported (``True``/``False``/
            ``None`` if not specified).
        enabled: Whether the component is enabled.
        intent_filters: List of intent filters declared for this component.
        permission: Required permission to access this component, if any.
        is_launcher: Whether this is the main launcher activity.
    """

    component_type: str = ""
    name: str = ""
    exported: bool | None = None
    enabled: bool = True
    intent_filters: list[IntentFilterInfo] = field(default_factory=list)
    permission: str | None = None
    is_launcher: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "component_type": self.component_type,
            "name": self.name,
            "exported": self.exported,
            "enabled": self.enabled,
            "intent_filters": [f.to_dict() for f in self.intent_filters],
            "permission": self.permission,
            "is_launcher": self.is_launcher,
        }


class ComponentExtractor:
    """Extracts Android components from a parsed manifest XML tree.

    Iterates through the ``<application>`` element to find all declared
    activities, services, receivers, and providers.

    Args:
        manifest_root: The root :class:`~xml.etree.ElementTree.Element`
            of the parsed ``AndroidManifest.xml``.
    """

    COMPONENT_TAGS = ("activity", "service", "receiver", "provider")

    def __init__(self, manifest_root: ET.Element) -> None:
        self._root = manifest_root
        self._components: list[ComponentInfo] | None = None

    def extract(self) -> list[ComponentInfo]:
        """Extract all components from the manifest.

        Returns:
            A list of :class:`ComponentInfo` objects.
        """
        if self._components is not None:
            return self._components

        app = self._root.find("application")
        if app is None:
            self._components = []
            return self._components

        components: list[ComponentInfo] = []
        for tag in self.COMPONENT_TAGS:
            for elem in app.findall(tag):
                comp = self._parse_component(tag, elem)
                components.append(comp)

        # Also handle <activity-alias> as activities.
        for elem in app.findall("activity-alias"):
            comp = self._parse_component("activity", elem)
            components.append(comp)

        self._components = components
        return components

    def get_by_type(self, component_type: str) -> list[ComponentInfo]:
        """Return components filtered by type.

        Args:
            component_type: One of ``"activity"``, ``"service"``,
                ``"receiver"``, ``"provider"``.

        Returns:
            Filtered list of :class:`ComponentInfo` objects.
        """
        return [c for c in self.extract() if c.component_type == component_type]

    def get_exported(self) -> list[ComponentInfo]:
        """Return only components that are explicitly exported.

        Returns:
            List of exported :class:`ComponentInfo` objects.
        """
        return [c for c in self.extract() if c.exported is True]

    def get_launcher_activities(self) -> list[ComponentInfo]:
        """Return the main launcher activity (or activities).

        Returns:
            List of activities with a MAIN/LAUNCHER intent filter.
        """
        return [c for c in self.extract() if c.is_launcher]

    def _parse_component(self, tag: str, elem: ET.Element) -> ComponentInfo:
        """Parse a single component element into a :class:`ComponentInfo`."""
        name = elem.get(android_attr("name"), "")
        exported_str = elem.get(android_attr("exported"))
        enabled_str = elem.get(android_attr("enabled"), "true")
        permission = elem.get(android_attr("permission"))

        exported: bool | None = None
        if exported_str is not None:
            exported = exported_str.lower() == "true"

        enabled = enabled_str.lower() != "false"

        intent_filters = self._parse_intent_filters(elem)

        # Determine if this is the launcher activity.
        is_launcher = any(
            "android.intent.action.MAIN" in f.actions
            and "android.intent.category.LAUNCHER" in f.categories
            for f in intent_filters
        )

        # If exported is not explicitly set but intent filters exist,
        # Android defaults exported to True.
        if exported is None and intent_filters:
            exported = True

        return ComponentInfo(
            component_type=tag,
            name=name,
            exported=exported,
            enabled=enabled,
            intent_filters=intent_filters,
            permission=permission,
            is_launcher=is_launcher,
        )

    @staticmethod
    def _parse_intent_filters(elem: ET.Element) -> list[IntentFilterInfo]:
        """Parse all ``<intent-filter>`` children of a component element."""
        filters: list[IntentFilterInfo] = []
        for if_elem in elem.findall("intent-filter"):
            filt = IntentFilterInfo()
            for action in if_elem.findall("action"):
                name = action.get(android_attr("name"))
                if name:
                    filt.actions.append(name)
            for cat in if_elem.findall("category"):
                name = cat.get(android_attr("name"))
                if name:
                    filt.categories.append(name)
            for data in if_elem.findall("data"):
                scheme = data.get(android_attr("scheme"))
                host = data.get(android_attr("host"))
                if scheme:
                    filt.data_schemes.append(scheme)
                if host:
                    filt.data_hosts.append(host)
            filters.append(filt)
        return filters
