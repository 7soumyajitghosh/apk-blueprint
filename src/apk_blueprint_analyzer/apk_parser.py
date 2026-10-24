"""APK file parser and extraction handler.

Handles opening APK files (which are ZIP archives), extracting contents to
a temporary working directory, and providing structured access to the APK's
internal file layout.

All operations are strictly read-only — no APK modification ever occurs.
"""

from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apk_blueprint_analyzer.utils import compute_file_hash, file_size_human


@dataclass
class ApkMetadata:
    """High-level metadata about an APK file.

    Attributes:
        file_path: Absolute path to the original APK file.
        file_name: Base filename of the APK.
        file_size: Size in bytes.
        file_size_human: Human-readable size string.
        sha256: SHA-256 hash of the APK file.
        entry_count: Number of entries in the ZIP archive.
        file_list: List of all file paths inside the APK.
        has_manifest: Whether ``AndroidManifest.xml`` is present.
        has_classes_dex: Whether at least one ``classes.dex`` is present.
        dex_count: Number of DEX files.
    """

    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    file_size_human: str = ""
    sha256: str = ""
    entry_count: int = 0
    file_list: list[str] = field(default_factory=list)
    has_manifest: bool = False
    has_classes_dex: bool = False
    dex_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize metadata to a plain dictionary for JSON output."""
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_size_human": self.file_size_human,
            "sha256": self.sha256,
            "entry_count": self.entry_count,
            "has_manifest": self.has_manifest,
            "has_classes_dex": self.has_classes_dex,
            "dex_count": self.dex_count,
        }


class ApkParser:
    """Read-only parser for Android APK files.

    Opens the APK as a ZIP archive and extracts metadata, file listings,
    and raw content for downstream analyzers. Never modifies the APK.

    Args:
        apk_path: Path to the ``.apk`` file.

    Raises:
        FileNotFoundError: If the APK file does not exist.
        ValueError: If the file is not a valid ZIP archive.
    """

    def __init__(self, apk_path: str | Path) -> None:
        self._path = Path(apk_path).resolve()
        if not self._path.exists():
            raise FileNotFoundError(f"APK file not found: {self._path}")
        if not zipfile.is_zipfile(self._path):
            raise ValueError(
                f"Not a valid APK (ZIP) file: {self._path}"
            )
        self._zip: zipfile.ZipFile | None = None
        self._metadata: ApkMetadata | None = None

    @property
    def path(self) -> Path:
        """Absolute path to the APK file."""
        return self._path

    def open(self) -> None:
        """Open the APK archive for reading.

        Must be called before accessing contents. Call :meth:`close` when
        finished, or use as a context manager.
        """
        self._zip = zipfile.ZipFile(self._path, "r")

    def close(self) -> None:
        """Close the APK archive."""
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def __enter__(self) -> "ApkParser":
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _ensure_open(self) -> zipfile.ZipFile:
        """Return the open ZIP file, raising if not yet opened."""
        if self._zip is None:
            raise RuntimeError(
                "APK not opened. Call .open() or use as a context manager."
            )
        return self._zip

    def get_metadata(self) -> ApkMetadata:
        """Compute and return APK file metadata.

        Results are cached after the first call.

        Returns:
            An :class:`ApkMetadata` instance.
        """
        if self._metadata is not None:
            return self._metadata

        zf = self._ensure_open()
        file_list = zf.namelist()
        stat = self._path.stat()
        dex_files = [f for f in file_list if f.endswith(".dex")]

        self._metadata = ApkMetadata(
            file_path=str(self._path),
            file_name=self._path.name,
            file_size=stat.st_size,
            file_size_human=file_size_human(stat.st_size),
            sha256=compute_file_hash(self._path),
            entry_count=len(file_list),
            file_list=file_list,
            has_manifest="AndroidManifest.xml" in file_list,
            has_classes_dex=len(dex_files) > 0,
            dex_count=len(dex_files),
        )
        return self._metadata

    def read_file(self, inner_path: str) -> bytes:
        """Read raw bytes of a file inside the APK.

        Args:
            inner_path: Path within the ZIP archive (e.g.,
                ``"AndroidManifest.xml"``).

        Returns:
            The file contents as bytes.

        Raises:
            KeyError: If the file is not found in the archive.
        """
        zf = self._ensure_open()
        return zf.read(inner_path)

    def has_file(self, inner_path: str) -> bool:
        """Check whether a file exists inside the APK.

        Args:
            inner_path: Path within the ZIP archive.

        Returns:
            ``True`` if the file exists.
        """
        zf = self._ensure_open()
        return inner_path in zf.namelist()

    def extract_to(self, output_dir: Path) -> Path:
        """Extract all APK contents to a directory (read-only inspection).

        Args:
            output_dir: Directory to extract into.

        Returns:
            The path to the extraction directory.
        """
        zf = self._ensure_open()
        output_dir.mkdir(parents=True, exist_ok=True)
        zf.extractall(output_dir)
        return output_dir

    def get_layout_files(self) -> list[str]:
        """Return paths to all layout XML files inside the APK.

        Returns:
            List of paths matching ``res/layout*/**.xml``.
        """
        zf = self._ensure_open()
        return [
            name
            for name in zf.namelist()
            if name.startswith("res/layout") and name.endswith(".xml")
        ]

    def get_resource_files(self, prefix: str = "res/") -> list[str]:
        """Return paths to all resource files under a given prefix.

        Args:
            prefix: Directory prefix to filter by (default ``"res/"``).

        Returns:
            List of matching file paths.
        """
        zf = self._ensure_open()
        return [name for name in zf.namelist() if name.startswith(prefix)]
