"""Tests for the library detector."""

from __future__ import annotations

import pytest

from apk_blueprint_analyzer.library_detector import LibraryDetector, LibraryMatch


class TestLibraryDetector:
    """Test suite for LibraryDetector."""

    def test_detects_firebase_analytics(self, sample_file_list: list[str]) -> None:
        """Firebase Analytics is detected from smali paths."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = {m.name for m in matches}
        assert "Firebase Analytics" in names

    def test_detects_okhttp(self, sample_file_list: list[str]) -> None:
        """OkHttp is detected from smali paths."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = {m.name for m in matches}
        assert "OkHttp" in names

    def test_detects_retrofit(self, sample_file_list: list[str]) -> None:
        """Retrofit is detected from smali paths."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = {m.name for m in matches}
        assert "Retrofit" in names

    def test_detects_glide(self, sample_file_list: list[str]) -> None:
        """Glide is detected from smali paths."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = {m.name for m in matches}
        assert "Glide" in names

    def test_detects_facebook_sdk(self, sample_file_list: list[str]) -> None:
        """Facebook SDK is detected from smali paths."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = {m.name for m in matches}
        assert "Facebook SDK" in names

    def test_detects_adjust(self, sample_file_list: list[str]) -> None:
        """Adjust SDK is detected from smali paths."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = {m.name for m in matches}
        assert "Adjust" in names

    def test_privacy_relevant_filter(self, sample_file_list: list[str]) -> None:
        """get_privacy_relevant returns only privacy-flagged libraries."""
        detector = LibraryDetector(sample_file_list)
        privacy = detector.get_privacy_relevant()
        assert all(m.privacy_relevant for m in privacy)
        names = {m.name for m in privacy}
        # Firebase Analytics, AdMob, Facebook SDK, Adjust are privacy-relevant.
        assert len(names) >= 3

    def test_category_filter(self, sample_file_list: list[str]) -> None:
        """get_by_category filters correctly."""
        detector = LibraryDetector(sample_file_list)
        networking = detector.get_by_category("networking")
        names = {m.name for m in networking}
        assert "OkHttp" in names
        assert "Retrofit" in names

    def test_no_duplicates(self, sample_file_list: list[str]) -> None:
        """Each library is reported at most once."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        names = [m.name for m in matches]
        assert len(names) == len(set(names))

    def test_empty_file_list(self) -> None:
        """Empty file list produces no matches."""
        detector = LibraryDetector([])
        assert detector.detect() == []

    def test_no_matching_paths(self) -> None:
        """Unrecognized paths produce no matches."""
        detector = LibraryDetector([
            "smali/com/mycompany/internal/Utils.smali",
            "res/layout/activity_main.xml",
        ])
        assert detector.detect() == []

    def test_to_dict(self, sample_file_list: list[str]) -> None:
        """LibraryMatch.to_dict produces correct structure."""
        detector = LibraryDetector(sample_file_list)
        matches = detector.detect()
        assert len(matches) > 0
        d = matches[0].to_dict()
        assert "name" in d
        assert "category" in d
        assert "privacy_relevant" in d

    def test_caches_results(self, sample_file_list: list[str]) -> None:
        """Repeated calls return cached results."""
        detector = LibraryDetector(sample_file_list)
        r1 = detector.detect()
        r2 = detector.detect()
        assert r1 is r2
