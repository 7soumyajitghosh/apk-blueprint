"""Third-party library and SDK detector.

Identifies known libraries, SDKs, and frameworks bundled inside an APK
by matching package-name patterns against a curated fingerprint database.

Detection is performed by scanning the APK's internal file paths
(e.g., ``smali/`` class directories, ``lib/`` native libraries, and
``assets/`` configuration files) for known signatures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LibraryMatch:
    """A detected third-party library or SDK.

    Attributes:
        name: Human-readable library name.
        category: Library category (e.g., ``"analytics"``, ``"ads"``).
        package_pattern: The pattern that matched.
        description: Brief description of the library.
        website: URL for more information, if available.
        privacy_relevant: Whether this library is privacy-relevant.
    """

    name: str = ""
    category: str = ""
    package_pattern: str = ""
    description: str = ""
    website: str = ""
    privacy_relevant: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "package_pattern": self.package_pattern,
            "description": self.description,
            "website": self.website,
            "privacy_relevant": self.privacy_relevant,
        }


# ──────────────────────────────────────────────────────────────────────
# Library fingerprint database.
#
# Each entry is a tuple of:
#   (name, category, package_regex, description, website, privacy_relevant)
#
# The regex is matched against dotted package names extracted from the
# APK's file paths (e.g., "com.google.firebase.analytics").
# ──────────────────────────────────────────────────────────────────────

_LIBRARY_FINGERPRINTS: list[tuple[str, str, str, str, str, bool]] = [
    # ── Google ──
    ("Google Play Services", "google", r"com\.google\.android\.gms",
     "Google Play Services SDK", "https://developers.google.com/android", True),
    ("Firebase Analytics", "analytics", r"com\.google\.firebase\.analytics",
     "Firebase event and user analytics", "https://firebase.google.com", True),
    ("Firebase Crashlytics", "crash-reporting", r"com\.google\.firebase\.crashlytics",
     "Crash reporting and stability monitoring", "https://firebase.google.com/products/crashlytics", False),
    ("Firebase Cloud Messaging", "messaging", r"com\.google\.firebase\.messaging",
     "Push notification service", "https://firebase.google.com/products/cloud-messaging", False),
    ("Firebase Auth", "authentication", r"com\.google\.firebase\.auth",
     "User authentication and identity", "https://firebase.google.com/products/auth", False),
    ("Google Ads (AdMob)", "ads", r"com\.google\.android\.gms\.ads",
     "Google advertising SDK", "https://admob.google.com", True),
    ("Google Maps", "maps", r"com\.google\.android\.gms\.maps",
     "Google Maps integration", "https://developers.google.com/maps", False),
    ("Google ML Kit", "machine-learning", r"com\.google\.mlkit",
     "On-device machine learning", "https://developers.google.com/ml-kit", False),

    # ── Facebook / Meta ──
    ("Facebook SDK", "social", r"com\.facebook\.(android|sdk|appevents)",
     "Facebook login, sharing, and analytics", "https://developers.facebook.com", True),
    ("Facebook Ads", "ads", r"com\.facebook\.ads",
     "Facebook audience network ads", "https://developers.facebook.com/docs/audience-network", True),

    # ── Analytics & Tracking ──
    ("Adjust", "analytics", r"com\.adjust\.sdk",
     "Mobile attribution and analytics", "https://www.adjust.com", True),
    ("AppsFlyer", "analytics", r"com\.appsflyer",
     "Mobile attribution platform", "https://www.appsflyer.com", True),
    ("Mixpanel", "analytics", r"com\.mixpanel",
     "Product analytics platform", "https://mixpanel.com", True),
    ("Amplitude", "analytics", r"com\.amplitude",
     "Product analytics and event tracking", "https://amplitude.com", True),
    ("Segment", "analytics", r"com\.segment\.analytics",
     "Customer data platform", "https://segment.com", True),
    ("Braze (Appboy)", "analytics", r"com\.braze|com\.appboy",
     "Customer engagement and analytics", "https://www.braze.com", True),

    # ── Ads ──
    ("Unity Ads", "ads", r"com\.unity3d\.ads",
     "Unity advertising SDK", "https://unity.com/solutions/unity-ads", True),
    ("AppLovin", "ads", r"com\.applovin",
     "Mobile advertising and monetization", "https://www.applovin.com", True),
    ("ironSource", "ads", r"com\.ironsource",
     "App monetization platform", "https://www.is.com", True),
    ("MoPub", "ads", r"com\.mopub",
     "Mobile ad serving platform", "https://www.mopub.com", True),

    # ── Networking ──
    ("OkHttp", "networking", r"okhttp3?\.",
     "HTTP client library", "https://square.github.io/okhttp/", False),
    ("Retrofit", "networking", r"retrofit2?\.",
     "Type-safe REST client", "https://square.github.io/retrofit/", False),
    ("Volley", "networking", r"com\.android\.volley",
     "HTTP networking library by Google", "https://developer.android.com/training/volley", False),

    # ── Image Loading ──
    ("Glide", "image-loading", r"com\.bumptech\.glide",
     "Image loading and caching library", "https://bumptech.github.io/glide/", False),
    ("Picasso", "image-loading", r"com\.squareup\.picasso",
     "Image downloading and caching", "https://square.github.io/picasso/", False),
    ("Coil", "image-loading", r"coil\-kt|coil\.compose",
     "Kotlin-first image loading library", "https://coil-kt.github.io/coil/", False),
    ("Fresco", "image-loading", r"com\.facebook\.fresco",
     "Facebook image loading library", "https://frescolib.org", False),

    # ── Dependency Injection ──
    ("Dagger/Hilt", "dependency-injection", r"dagger\.|hilt\.",
     "Compile-time dependency injection", "https://dagger.dev", False),
    ("Koin", "dependency-injection", r"org\.koin",
     "Kotlin dependency injection framework", "https://insert-koin.io", False),

    # ── Reactive / Async ──
    ("RxJava", "reactive", r"io\.reactivex",
     "Reactive Extensions for JVM", "https://github.com/ReactiveX/RxJava", False),
    ("Kotlin Coroutines", "async", r"kotlinx\.coroutines",
     "Kotlin coroutine support library", "https://kotlinlang.org/docs/coroutines-overview.html", False),

    # ── Database ──
    ("Room", "database", r"androidx\.room",
     "SQLite abstraction layer (Jetpack)", "https://developer.android.com/training/data-storage/room", False),
    ("Realm", "database", r"io\.realm",
     "Mobile-first database", "https://realm.io", False),
    ("SQLCipher", "database", r"net\.sqlcipher",
     "Encrypted SQLite database", "https://www.zetetic.net/sqlcipher/", False),

    # ── UI / Architecture ──
    ("Jetpack Compose", "ui", r"androidx\.compose",
     "Modern declarative UI toolkit", "https://developer.android.com/jetpack/compose", False),
    ("AndroidX", "architecture", r"androidx\.",
     "Android Jetpack support libraries", "https://developer.android.com/jetpack/androidx", False),
    ("Material Components", "ui", r"com\.google\.android\.material",
     "Material Design components", "https://material.io/develop/android", False),
    ("Flutter", "cross-platform", r"io\.flutter",
     "Google's cross-platform UI framework", "https://flutter.dev", False),
    ("React Native", "cross-platform", r"com\.facebook\.react",
     "Facebook's cross-platform framework", "https://reactnative.dev", False),

    # ── Crash / Error ──
    ("Sentry", "crash-reporting", r"io\.sentry",
     "Error tracking and performance monitoring", "https://sentry.io", False),
    ("Bugsnag", "crash-reporting", r"com\.bugsnag",
     "Error monitoring platform", "https://www.bugsnag.com", False),

    # ── Security ──
    ("Security Crypto (Jetpack)", "security", r"androidx\.security\.crypto",
     "Encrypted SharedPreferences and files", "https://developer.android.com/topic/security", False),
]


class LibraryDetector:
    """Detects third-party libraries and SDKs from APK file paths.

    Scans the APK's internal file listing for package patterns that match
    known library fingerprints.

    Args:
        file_paths: List of file paths inside the APK (from
            :meth:`~apk_blueprint_analyzer.apk_parser.ApkParser.get_metadata`).
    """

    def __init__(self, file_paths: list[str]) -> None:
        self._paths = file_paths
        self._matches: list[LibraryMatch] | None = None

    def detect(self) -> list[LibraryMatch]:
        """Run detection and return matched libraries.

        Returns:
            List of :class:`LibraryMatch` objects for detected libraries.
        """
        if self._matches is not None:
            return self._matches

        # Normalize paths to dotted package names for matching.
        normalized = self._normalize_paths()

        seen: set[str] = set()
        matches: list[LibraryMatch] = []

        for name, category, pattern, desc, website, privacy in _LIBRARY_FINGERPRINTS:
            if name in seen:
                continue
            regex = re.compile(pattern, re.IGNORECASE)
            for pkg in normalized:
                if regex.search(pkg):
                    matches.append(
                        LibraryMatch(
                            name=name,
                            category=category,
                            package_pattern=pattern,
                            description=desc,
                            website=website,
                            privacy_relevant=privacy,
                        )
                    )
                    seen.add(name)
                    break

        self._matches = matches
        return matches

    def get_privacy_relevant(self) -> list[LibraryMatch]:
        """Return only privacy-relevant detected libraries.

        Returns:
            Filtered list of :class:`LibraryMatch` objects.
        """
        return [m for m in self.detect() if m.privacy_relevant]

    def get_by_category(self, category: str) -> list[LibraryMatch]:
        """Return detected libraries filtered by category.

        Args:
            category: Category string (e.g., ``"ads"``, ``"analytics"``).

        Returns:
            Filtered list of :class:`LibraryMatch` objects.
        """
        return [m for m in self.detect() if m.category == category]

    def _normalize_paths(self) -> set[str]:
        """Convert APK file paths to dotted package-name format."""
        packages: set[str] = set()
        for path in self._paths:
            # Convert smali/com/example/Foo.smali -> com.example.Foo
            normalized = path.replace("/", ".").replace("\\", ".")
            packages.add(normalized)
        return packages
