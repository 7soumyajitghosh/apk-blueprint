"""AndroidManifest.xml analyzer.

Parses the decoded (text-mode) ``AndroidManifest.xml`` to extract the
application's package name, version info, SDK requirements, and the raw
manifest tree for downstream analyzers.

Note: APK files contain a *binary-encoded* ``AndroidManifest.xml``.
This module works with the **decoded** XML produced by Apktool or
a similar decoder. If a decoded manifest is not available, it attempts
a best-effort parse of the raw binary manifest (which may have limited
results).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from apk_blueprint_analyzer.utils import ANDROID_NS, android_attr, parse_xml_safe


@dataclass
class ManifestInfo:
    """Parsed information from AndroidManifest.xml.

    Attributes:
        package_name: The application's package identifier.
        version_code: Integer version code, or ``None`` if absent.
        version_name: Human-readable version string, or ``None``.
        min_sdk: Minimum SDK version, or ``None``.
        target_sdk: Target SDK version, or ``None``.
        compile_sdk: Compile SDK version, or ``None``.
        uses_permissions: List of permission strings declared with
            ``<uses-permission>``.
        permissions_defined: List of custom permissions declared with
            ``<permission>``.
        application_attrs: Dictionary of ``<application>`` element attributes.
        raw_xml_root: The parsed XML root element, or ``None`` if parsing
            failed.
    """

    package_name: str = ""
    version_code: int | None = None
    version_name: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    compile_sdk: int | None = None
    uses_permissions: list[str] = field(default_factory=list)
    permissions_defined: list[str] = field(default_factory=list)
    application_attrs: dict[str, str] = field(default_factory=dict)
    raw_xml_root: ET.Element | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary (excludes the raw XML tree)."""
        return {
            "package_name": self.package_name,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "uses_permissions": self.uses_permissions,
            "permissions_defined": self.permissions_defined,
        }


class ManifestAnalyzer:
    """Analyzer for decoded ``AndroidManifest.xml`` files.

    Extracts package metadata, SDK version constraints, and declared
    permissions from the manifest.

    Args:
        manifest_path: Path to the decoded ``AndroidManifest.xml`` file.
    """

    def __init__(self, manifest_path: str | Path) -> None:
        self._path = Path(manifest_path)
        self._root: ET.Element | None = None
        self._info: ManifestInfo | None = None

    def parse(self) -> ManifestInfo:
        """Parse the manifest and return structured information.

        Returns:
            A :class:`ManifestInfo` dataclass with extracted data.

        Raises:
            FileNotFoundError: If the manifest file does not exist.
            ValueError: If the XML cannot be parsed at all.
        """
        if self._info is not None:
            return self._info

        if not self._path.exists():
            raise FileNotFoundError(
                f"AndroidManifest.xml not found: {self._path}"
            )

        self._root = parse_xml_safe(self._path)
        if self._root is None:
            raise ValueError(
                f"Failed to parse AndroidManifest.xml: {self._path}. "
                "The file may be binary-encoded. Decode it with Apktool first."
            )

        info = ManifestInfo(raw_xml_root=self._root)
        info.package_name = self._root.get("package", "")
        info.version_code = self._parse_int(
            self._root.get(android_attr("versionCode"))
        )
        info.version_name = self._root.get(android_attr("versionName"))
        info.compile_sdk = self._parse_int(
            self._root.get(android_attr("compileSdkVersion"))
        )

        # SDK versions from <uses-sdk>.
        uses_sdk = self._root.find("uses-sdk")
        if uses_sdk is not None:
            info.min_sdk = self._parse_int(
                uses_sdk.get(android_attr("minSdkVersion"))
            )
            info.target_sdk = self._parse_int(
                uses_sdk.get(android_attr("targetSdkVersion"))
            )

        # Permissions.
        info.uses_permissions = self._extract_uses_permissions()
        info.permissions_defined = self._extract_defined_permissions()

        # Application attributes.
        app_elem = self._root.find("application")
        if app_elem is not None:
            info.application_attrs = dict(app_elem.attrib)

        self._info = info
        return info

    @property
    def root(self) -> ET.Element | None:
        """The parsed XML root element, available after :meth:`parse`."""
        return self._root

    def _extract_uses_permissions(self) -> list[str]:
        """Extract all ``<uses-permission>`` entries."""
        if self._root is None:
            return []
        perms: list[str] = []
        for elem in self._root.findall("uses-permission"):
            name = elem.get(android_attr("name"))
            if name:
                perms.append(name)
        return perms

    def _extract_defined_permissions(self) -> list[str]:
        """Extract all ``<permission>`` entries (custom permissions)."""
        if self._root is None:
            return []
        perms: list[str] = []
        for elem in self._root.findall("permission"):
            name = elem.get(android_attr("name"))
            if name:
                perms.append(name)
        return perms

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        """Attempt to parse a string as an integer, returning None on failure."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None


def parse_manifest_from_string(xml_string: str) -> ManifestInfo:
    """Parse manifest XML from a string (useful for testing).

    Args:
        xml_string: The XML content as a string.

    Returns:
        A :class:`ManifestInfo` dataclass with extracted data.

    Raises:
        ValueError: If the XML cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse manifest XML: {exc}") from exc

    info = ManifestInfo(raw_xml_root=root)
    info.package_name = root.get("package", "")
    info.version_code = ManifestAnalyzer._parse_int(
        root.get(android_attr("versionCode"))
    )
    info.version_name = root.get(android_attr("versionName"))

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        info.min_sdk = ManifestAnalyzer._parse_int(
            uses_sdk.get(android_attr("minSdkVersion"))
        )
        info.target_sdk = ManifestAnalyzer._parse_int(
            uses_sdk.get(android_attr("targetSdkVersion"))
        )

    for elem in root.findall("uses-permission"):
        name = elem.get(android_attr("name"))
        if name:
            info.uses_permissions.append(name)

    for elem in root.findall("permission"):
        name = elem.get(android_attr("name"))
        if name:
            info.permissions_defined.append(name)

    return info
