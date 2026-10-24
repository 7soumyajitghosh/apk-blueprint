"""Android permission analyzer.

Maps Android permission strings to human-readable descriptions, protection
levels, and risk categories. Helps users understand *why* an app requests
each permission and whether it warrants attention.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProtectionLevel(str, Enum):
    """Android permission protection levels."""

    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SIGNATURE = "signature"
    PRIVILEGED = "privileged"
    UNKNOWN = "unknown"


class RiskCategory(str, Enum):
    """Risk categorization for permissions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class PermissionDetail:
    """Detailed information about a single permission.

    Attributes:
        name: The full permission string.
        short_name: The permission name without the prefix.
        protection_level: The Android protection level.
        risk_category: Assessed risk category.
        description: Human-readable description of the permission's purpose.
        group: Permission group, if known.
    """

    name: str = ""
    short_name: str = ""
    protection_level: ProtectionLevel = ProtectionLevel.UNKNOWN
    risk_category: RiskCategory = RiskCategory.UNKNOWN
    description: str = "No description available."
    group: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "name": self.name,
            "short_name": self.short_name,
            "protection_level": self.protection_level.value,
            "risk_category": self.risk_category.value,
            "description": self.description,
            "group": self.group,
        }


# ──────────────────────────────────────────────────────────────────────
# Built-in permission knowledge base.
# This is intentionally a curated subset covering the most common and
# most privacy-relevant permissions. Extend as needed.
# ──────────────────────────────────────────────────────────────────────

_PERMISSION_DB: dict[str, dict[str, str]] = {
    # ── Network ──
    "android.permission.INTERNET": {
        "level": "normal",
        "risk": "low",
        "desc": "Full network access — allows the app to make HTTP/HTTPS requests.",
        "group": "network",
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "level": "normal",
        "risk": "low",
        "desc": "View network connectivity status (Wi-Fi, mobile data).",
        "group": "network",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "level": "normal",
        "risk": "low",
        "desc": "View Wi-Fi connection information.",
        "group": "network",
    },
    # ── Location ──
    "android.permission.ACCESS_FINE_LOCATION": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Precise GPS location — enables location tracking.",
        "group": "location",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Approximate location via cell towers and Wi-Fi.",
        "group": "location",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "level": "dangerous",
        "risk": "critical",
        "desc": "Access location even when the app is in the background.",
        "group": "location",
    },
    # ── Camera & Microphone ──
    "android.permission.CAMERA": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Camera access — photo/video capture or QR scanning.",
        "group": "camera",
    },
    "android.permission.RECORD_AUDIO": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Microphone access — audio recording or voice input.",
        "group": "microphone",
    },
    # ── Storage ──
    "android.permission.READ_EXTERNAL_STORAGE": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Read files from shared/external storage.",
        "group": "storage",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Write files to shared/external storage.",
        "group": "storage",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "level": "dangerous",
        "risk": "critical",
        "desc": "Broad access to all files on shared storage (Android 11+).",
        "group": "storage",
    },
    # ── Contacts & Calendar ──
    "android.permission.READ_CONTACTS": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Read the user's contacts list.",
        "group": "contacts",
    },
    "android.permission.WRITE_CONTACTS": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Modify or add contacts.",
        "group": "contacts",
    },
    "android.permission.READ_CALENDAR": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Read calendar events.",
        "group": "calendar",
    },
    "android.permission.WRITE_CALENDAR": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Create or modify calendar events.",
        "group": "calendar",
    },
    # ── Phone ──
    "android.permission.READ_PHONE_STATE": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Read phone state including IMEI, phone number, carrier.",
        "group": "phone",
    },
    "android.permission.CALL_PHONE": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Directly initiate phone calls without user interaction.",
        "group": "phone",
    },
    "android.permission.READ_CALL_LOG": {
        "level": "dangerous",
        "risk": "critical",
        "desc": "Read the user's call history.",
        "group": "phone",
    },
    # ── SMS ──
    "android.permission.SEND_SMS": {
        "level": "dangerous",
        "risk": "critical",
        "desc": "Send SMS messages (potential for premium-rate abuse).",
        "group": "sms",
    },
    "android.permission.READ_SMS": {
        "level": "dangerous",
        "risk": "critical",
        "desc": "Read SMS messages — access to sensitive verification codes.",
        "group": "sms",
    },
    "android.permission.RECEIVE_SMS": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Intercept incoming SMS messages.",
        "group": "sms",
    },
    # ── Sensors ──
    "android.permission.BODY_SENSORS": {
        "level": "dangerous",
        "risk": "high",
        "desc": "Access body sensors like heart rate monitors.",
        "group": "sensors",
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Detect physical activity (walking, driving, etc.).",
        "group": "sensors",
    },
    # ── System ──
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "level": "normal",
        "risk": "low",
        "desc": "Launch at device boot — allows auto-starting.",
        "group": "system",
    },
    "android.permission.VIBRATE": {
        "level": "normal",
        "risk": "low",
        "desc": "Control device vibration.",
        "group": "system",
    },
    "android.permission.WAKE_LOCK": {
        "level": "normal",
        "risk": "low",
        "desc": "Prevent the device from sleeping.",
        "group": "system",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "level": "normal",
        "risk": "low",
        "desc": "Run a foreground service with a persistent notification.",
        "group": "system",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "level": "signature",
        "risk": "critical",
        "desc": "Request installation of other APK packages.",
        "group": "system",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "level": "signature",
        "risk": "high",
        "desc": "Draw overlays on top of other apps.",
        "group": "system",
    },
    # ── Notifications ──
    "android.permission.POST_NOTIFICATIONS": {
        "level": "dangerous",
        "risk": "low",
        "desc": "Post notifications to the user (Android 13+).",
        "group": "notifications",
    },
    # ── Bluetooth ──
    "android.permission.BLUETOOTH": {
        "level": "normal",
        "risk": "low",
        "desc": "Access Bluetooth functionality.",
        "group": "bluetooth",
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Connect to paired Bluetooth devices (Android 12+).",
        "group": "bluetooth",
    },
    "android.permission.BLUETOOTH_SCAN": {
        "level": "dangerous",
        "risk": "medium",
        "desc": "Discover nearby Bluetooth devices (Android 12+).",
        "group": "bluetooth",
    },
}

_LEVEL_MAP = {
    "normal": ProtectionLevel.NORMAL,
    "dangerous": ProtectionLevel.DANGEROUS,
    "signature": ProtectionLevel.SIGNATURE,
    "privileged": ProtectionLevel.PRIVILEGED,
}

_RISK_MAP = {
    "low": RiskCategory.LOW,
    "medium": RiskCategory.MEDIUM,
    "high": RiskCategory.HIGH,
    "critical": RiskCategory.CRITICAL,
}


class PermissionAnalyzer:
    """Analyzes a list of Android permission strings.

    Looks up each permission in the built-in knowledge base and produces
    a detailed breakdown with descriptions, protection levels, and risk
    assessments.

    Args:
        permissions: List of permission strings (e.g.,
            ``["android.permission.INTERNET", ...]``).
    """

    def __init__(self, permissions: list[str]) -> None:
        self._permissions = permissions
        self._details: list[PermissionDetail] | None = None

    def analyze(self) -> list[PermissionDetail]:
        """Analyze all permissions and return detailed info.

        Returns:
            List of :class:`PermissionDetail` objects, one per permission.
        """
        if self._details is not None:
            return self._details

        self._details = [self._lookup(perm) for perm in self._permissions]
        return self._details

    def get_dangerous(self) -> list[PermissionDetail]:
        """Return only permissions with *dangerous* protection level.

        Returns:
            Filtered list of :class:`PermissionDetail` objects.
        """
        return [
            p
            for p in self.analyze()
            if p.protection_level == ProtectionLevel.DANGEROUS
        ]

    def get_high_risk(self) -> list[PermissionDetail]:
        """Return permissions assessed as high or critical risk.

        Returns:
            Filtered list of :class:`PermissionDetail` objects.
        """
        return [
            p
            for p in self.analyze()
            if p.risk_category in (RiskCategory.HIGH, RiskCategory.CRITICAL)
        ]

    def get_summary(self) -> dict[str, int]:
        """Return a summary count by protection level.

        Returns:
            Dictionary mapping protection level names to counts.
        """
        details = self.analyze()
        summary: dict[str, int] = {}
        for d in details:
            key = d.protection_level.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    @staticmethod
    def _lookup(permission: str) -> PermissionDetail:
        """Look up a permission in the knowledge base."""
        short_name = permission.rsplit(".", 1)[-1] if "." in permission else permission
        entry = _PERMISSION_DB.get(permission)

        if entry is not None:
            return PermissionDetail(
                name=permission,
                short_name=short_name,
                protection_level=_LEVEL_MAP.get(
                    entry["level"], ProtectionLevel.UNKNOWN
                ),
                risk_category=_RISK_MAP.get(entry["risk"], RiskCategory.UNKNOWN),
                description=entry["desc"],
                group=entry.get("group", ""),
            )

        # Unknown permission — provide a sensible default.
        return PermissionDetail(
            name=permission,
            short_name=short_name,
            protection_level=ProtectionLevel.UNKNOWN,
            risk_category=RiskCategory.UNKNOWN,
            description=f"Custom or uncommon permission: {permission}",
            group="unknown",
        )
