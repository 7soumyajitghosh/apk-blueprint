"""Shared utility functions used across the APK Blueprint Analyzer package.

Provides filesystem helpers, XML parsing utilities, and common data
structures used by multiple analyzer modules.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


# Android namespace used in AndroidManifest.xml attributes.
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def android_attr(name: str) -> str:
    """Return the fully-qualified attribute name for an Android namespace attribute.

    Args:
        name: The local attribute name (e.g., ``"name"``, ``"exported"``).

    Returns:
        The attribute name prefixed with the Android XML namespace.

    Example:
        >>> android_attr("name")
        '{http://schemas.android.com/apk/res/android}name'
    """
    return f"{{{ANDROID_NS}}}{name}"


def parse_xml_safe(path: Path) -> ET.Element | None:
    """Parse an XML file, returning the root element or ``None`` on failure.

    Handles malformed XML gracefully — corrupt or binary-encoded manifest
    files will not crash the analyzer.

    Args:
        path: Path to the XML file.

    Returns:
        The root :class:`xml.etree.ElementTree.Element`, or ``None`` if
        parsing fails.
    """
    try:
        tree = ET.parse(path)
        return tree.getroot()
    except (ET.ParseError, FileNotFoundError, PermissionError, OSError):
        return None


def compute_file_hash(path: Path, algorithm: str = "sha256") -> str:
    """Compute a hex-digest hash of a file.

    Args:
        path: Path to the file.
        algorithm: Hash algorithm name (default ``"sha256"``).

    Returns:
        Hex-encoded hash string.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_directory(path: Path) -> Path:
    """Create a directory (and parents) if it does not exist.

    Args:
        path: The directory path to ensure.

    Returns:
        The same path, guaranteed to exist.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def file_size_human(size_bytes: int) -> str:
    """Format a file size in bytes as a human-readable string.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Human-readable size string (e.g., ``"4.2 MB"``).
    """
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"


def extract_package_names_from_paths(paths: list[str]) -> set[str]:
    """Extract Java/Kotlin package prefixes from a list of file paths.

    Looks for ``smali/`` or ``java/`` path segments and extracts the
    dotted package name from the directory structure.

    Args:
        paths: List of file paths within the APK.

    Returns:
        Set of dotted package name prefixes.
    """
    packages: set[str] = set()
    pattern = re.compile(r"(?:smali(?:_classes\d*)?|java)[/\\](.+?)[/\\][^/\\]+$")
    for p in paths:
        match = pattern.search(p)
        if match:
            pkg = match.group(1).replace("/", ".").replace("\\", ".")
            # Keep only the first 3 segments as a prefix.
            parts = pkg.split(".")
            if len(parts) >= 2:
                packages.add(".".join(parts[:3]))
    return packages


def safe_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dictionaries.

    Args:
        data: The root dictionary.
        *keys: Sequence of keys to traverse.
        default: Value to return if any key is missing.

    Returns:
        The value at the nested key path, or ``default``.
    """
    current: Any = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current
