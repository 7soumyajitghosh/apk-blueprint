"""Shared test fixtures for APK Blueprint Analyzer test suite."""

from __future__ import annotations

import io
import textwrap
import zipfile
from pathlib import Path

import pytest


# ── Sample manifest XML for testing ──────────────────────────────────

SAMPLE_MANIFEST_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.testapp"
        android:versionCode="42"
        android:versionName="2.1.0">

        <uses-sdk
            android:minSdkVersion="21"
            android:targetSdkVersion="34" />

        <uses-permission android:name="android.permission.INTERNET" />
        <uses-permission android:name="android.permission.CAMERA" />
        <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
        <uses-permission android:name="android.permission.READ_CONTACTS" />
        <uses-permission android:name="android.permission.SEND_SMS" />

        <permission
            android:name="com.example.testapp.permission.CUSTOM"
            android:protectionLevel="signature" />

        <application
            android:allowBackup="true"
            android:debuggable="true"
            android:usesCleartextTraffic="true"
            android:label="Test App">

            <activity
                android:name=".SplashActivity"
                android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.MAIN" />
                    <category android:name="android.intent.category.LAUNCHER" />
                </intent-filter>
            </activity>

            <activity
                android:name=".MainActivity"
                android:exported="false" />

            <activity
                android:name=".LoginActivity"
                android:exported="false" />

            <activity
                android:name=".SettingsActivity"
                android:exported="true" />

            <activity
                android:name=".DeepLinkActivity"
                android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.VIEW" />
                    <category android:name="android.intent.category.DEFAULT" />
                    <category android:name="android.intent.category.BROWSABLE" />
                    <data android:scheme="https" android:host="example.com" />
                </intent-filter>
            </activity>

            <service
                android:name=".SyncService"
                android:exported="false" />

            <service
                android:name=".MessagingService"
                android:exported="true"
                android:permission="com.example.testapp.permission.CUSTOM" />

            <receiver
                android:name=".BootReceiver"
                android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.BOOT_COMPLETED" />
                </intent-filter>
            </receiver>

            <provider
                android:name=".data.AppContentProvider"
                android:authorities="com.example.testapp.provider"
                android:exported="true" />

        </application>
    </manifest>
""")


@pytest.fixture
def sample_manifest_xml() -> str:
    """Return sample AndroidManifest.xml content as a string."""
    return SAMPLE_MANIFEST_XML


@pytest.fixture
def sample_manifest_path(tmp_path: Path) -> Path:
    """Write sample manifest to a temp file and return its path."""
    manifest_file = tmp_path / "AndroidManifest.xml"
    manifest_file.write_text(SAMPLE_MANIFEST_XML, encoding="utf-8")
    return manifest_file


@pytest.fixture
def sample_apk_path(tmp_path: Path) -> Path:
    """Create a minimal fake APK (ZIP) file for testing.

    The APK contains:
    - AndroidManifest.xml (text-mode, parseable)
    - classes.dex (empty placeholder)
    - Several fake file paths simulating a real APK structure.
    """
    apk_path = tmp_path / "test_app.apk"

    file_entries = {
        "AndroidManifest.xml": SAMPLE_MANIFEST_XML.encode("utf-8"),
        "classes.dex": b"dex placeholder",
        "classes2.dex": b"dex placeholder 2",
        "res/layout/activity_splash.xml": b"<layout/>",
        "res/layout/activity_main.xml": b"<layout/>",
        "res/layout/activity_login.xml": b"<layout/>",
        "res/layout/activity_settings.xml": b"<layout/>",
        "res/values/strings.xml": b"<resources/>",
        "res/xml/network_security_config.xml": b"<network/>",
        # Simulate library package paths.
        "smali/com/google/firebase/analytics/FirebaseAnalytics.smali": b"",
        "smali/com/google/android/gms/ads/AdView.smali": b"",
        "smali/com/facebook/sdk/Facebook.smali": b"",
        "smali/okhttp3/OkHttpClient.smali": b"",
        "smali/retrofit2/Retrofit.smali": b"",
        "smali/com/bumptech/glide/Glide.smali": b"",
        "smali/androidx/room/RoomDatabase.smali": b"",
        "smali/com/adjust/sdk/Adjust.smali": b"",
        "smali/io/sentry/Sentry.smali": b"",
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in file_entries.items():
            zf.writestr(name, data)

    apk_path.write_bytes(buf.getvalue())
    return apk_path


@pytest.fixture
def sample_file_list() -> list[str]:
    """Return a realistic list of APK file paths for library detection tests."""
    return [
        "AndroidManifest.xml",
        "classes.dex",
        "classes2.dex",
        "res/layout/activity_main.xml",
        "res/layout/activity_login.xml",
        "smali/com/google/firebase/analytics/FirebaseAnalytics.smali",
        "smali/com/google/android/gms/ads/AdView.smali",
        "smali/com/facebook/sdk/Facebook.smali",
        "smali/okhttp3/OkHttpClient.smali",
        "smali/retrofit2/Retrofit.smali",
        "smali/com/bumptech/glide/Glide.smali",
        "smali/androidx/room/RoomDatabase.smali",
        "smali/com/adjust/sdk/Adjust.smali",
        "smali/io/sentry/Sentry.smali",
    ]
