"""Security and privacy risk scanner.

Inspects the analyzed APK data to identify potential security risks and
privacy concerns. This is a heuristic-based assessment intended to flag
items for human review — it does not make definitive security judgements.

Risk categories:
- Exported components without permission guards
- Sensitive permissions
- Privacy-relevant SDK usage
- Potential cleartext network traffic
- Debuggable or backup-enabled configurations
- Hardcoded URLs or potential API endpoints
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from apk_blueprint_analyzer.component_extractor import ComponentInfo
from apk_blueprint_analyzer.library_detector import LibraryMatch
from apk_blueprint_analyzer.manifest_analyzer import ManifestInfo
from apk_blueprint_analyzer.permission_analyzer import PermissionDetail, RiskCategory


class Severity(str, Enum):
    """Risk finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskFinding:
    """A single risk or privacy finding.

    Attributes:
        title: Short title of the finding.
        severity: Assessed severity level.
        category: Category of the finding.
        description: Detailed explanation.
        recommendation: Suggested remediation or review action.
        evidence: Specific data supporting the finding.
    """

    title: str = ""
    severity: Severity = Severity.INFO
    category: str = ""
    description: str = ""
    recommendation: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


class RiskScanner:
    """Scans analyzed APK data for security and privacy risks.

    Aggregates findings from manifest configuration, permissions,
    components, and detected libraries.

    Args:
        manifest_info: Parsed manifest information.
        components: Extracted component list.
        permissions: Analyzed permission details.
        libraries: Detected library matches.
        file_paths: List of file paths inside the APK.
    """

    def __init__(
        self,
        manifest_info: ManifestInfo,
        components: list[ComponentInfo],
        permissions: list[PermissionDetail],
        libraries: list[LibraryMatch],
        file_paths: list[str] | None = None,
    ) -> None:
        self._manifest = manifest_info
        self._components = components
        self._permissions = permissions
        self._libraries = libraries
        self._file_paths = file_paths or []
        self._findings: list[RiskFinding] | None = None

    def scan(self) -> list[RiskFinding]:
        """Run all risk checks and return findings.

        Returns:
            List of :class:`RiskFinding` objects, sorted by severity.
        """
        if self._findings is not None:
            return self._findings

        findings: list[RiskFinding] = []
        findings.extend(self._check_exported_components())
        findings.extend(self._check_sensitive_permissions())
        findings.extend(self._check_privacy_libraries())
        findings.extend(self._check_manifest_config())
        findings.extend(self._check_network_indicators())

        # Sort by severity (critical first).
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))

        self._findings = findings
        return findings

    def get_by_severity(self, severity: Severity) -> list[RiskFinding]:
        """Return findings filtered by severity.

        Args:
            severity: The severity level to filter by.

        Returns:
            Filtered list of :class:`RiskFinding` objects.
        """
        return [f for f in self.scan() if f.severity == severity]

    def get_summary(self) -> dict[str, int]:
        """Return a count of findings by severity.

        Returns:
            Dictionary mapping severity names to counts.
        """
        findings = self.scan()
        summary: dict[str, int] = {}
        for f in findings:
            key = f.severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    # ── Check methods ────────────────────────────────────────────────

    def _check_exported_components(self) -> list[RiskFinding]:
        """Flag exported components without permission guards."""
        findings: list[RiskFinding] = []
        for comp in self._components:
            if comp.exported is True and comp.permission is None:
                findings.append(
                    RiskFinding(
                        title=f"Exported {comp.component_type} without permission guard",
                        severity=Severity.MEDIUM,
                        category="exported-component",
                        description=(
                            f"The {comp.component_type} `{comp.name}` is exported and "
                            "accessible to other apps without any permission requirement."
                        ),
                        recommendation=(
                            "Review whether this component should be exported. "
                            "If external access is intentional, consider adding a "
                            "permission requirement."
                        ),
                        evidence=[comp.name],
                    )
                )
        return findings

    def _check_sensitive_permissions(self) -> list[RiskFinding]:
        """Flag high-risk and critical permissions."""
        findings: list[RiskFinding] = []
        for perm in self._permissions:
            if perm.risk_category == RiskCategory.CRITICAL:
                findings.append(
                    RiskFinding(
                        title=f"Critical permission: {perm.short_name}",
                        severity=Severity.HIGH,
                        category="sensitive-permission",
                        description=perm.description,
                        recommendation=(
                            "Verify this permission is essential for the app's "
                            "core functionality."
                        ),
                        evidence=[perm.name],
                    )
                )
            elif perm.risk_category == RiskCategory.HIGH:
                findings.append(
                    RiskFinding(
                        title=f"High-risk permission: {perm.short_name}",
                        severity=Severity.MEDIUM,
                        category="sensitive-permission",
                        description=perm.description,
                        recommendation=(
                            "Ensure this permission is justified by the app's features."
                        ),
                        evidence=[perm.name],
                    )
                )
        return findings

    def _check_privacy_libraries(self) -> list[RiskFinding]:
        """Flag privacy-relevant third-party libraries."""
        findings: list[RiskFinding] = []
        privacy_libs = [lib for lib in self._libraries if lib.privacy_relevant]
        if privacy_libs:
            evidence = [f"{lib.name} ({lib.category})" for lib in privacy_libs]
            findings.append(
                RiskFinding(
                    title="Privacy-relevant SDKs detected",
                    severity=Severity.MEDIUM,
                    category="privacy-sdk",
                    description=(
                        f"Found {len(privacy_libs)} SDK(s) that may collect or transmit "
                        "user data: analytics trackers, ad networks, or attribution tools."
                    ),
                    recommendation=(
                        "Review the data collection practices of each SDK and "
                        "ensure they comply with your privacy requirements."
                    ),
                    evidence=evidence,
                )
            )
        return findings

    def _check_manifest_config(self) -> list[RiskFinding]:
        """Check manifest-level configuration flags."""
        findings: list[RiskFinding] = []
        app_attrs = self._manifest.application_attrs

        # Check for debuggable flag.
        from apk_blueprint_analyzer.utils import android_attr

        debuggable = app_attrs.get(android_attr("debuggable"), "").lower()
        if debuggable == "true":
            findings.append(
                RiskFinding(
                    title="Application is debuggable",
                    severity=Severity.HIGH,
                    category="manifest-config",
                    description=(
                        "The application has `android:debuggable=true` set, which "
                        "allows debugging and may expose sensitive runtime data."
                    ),
                    recommendation=(
                        "Debuggable should be false in production builds."
                    ),
                    evidence=["android:debuggable=true"],
                )
            )

        # Check for allowBackup.
        allow_backup = app_attrs.get(android_attr("allowBackup"), "").lower()
        if allow_backup == "true":
            findings.append(
                RiskFinding(
                    title="Application allows backup",
                    severity=Severity.LOW,
                    category="manifest-config",
                    description=(
                        "The application allows ADB backup, which could expose "
                        "app data if the device is connected to an untrusted computer."
                    ),
                    recommendation=(
                        "Consider setting `android:allowBackup=false` or using "
                        "encrypted backups."
                    ),
                    evidence=["android:allowBackup=true"],
                )
            )

        # Check for cleartext traffic.
        cleartext = app_attrs.get(
            android_attr("usesCleartextTraffic"), ""
        ).lower()
        if cleartext == "true":
            findings.append(
                RiskFinding(
                    title="Cleartext (HTTP) traffic allowed",
                    severity=Severity.MEDIUM,
                    category="network",
                    description=(
                        "The application permits cleartext HTTP traffic, which "
                        "is vulnerable to interception."
                    ),
                    recommendation=(
                        "Use HTTPS for all network communication. Set "
                        "`android:usesCleartextTraffic=false`."
                    ),
                    evidence=["android:usesCleartextTraffic=true"],
                )
            )

        return findings

    def _check_network_indicators(self) -> list[RiskFinding]:
        """Scan file paths for potential network configuration files."""
        findings: list[RiskFinding] = []

        # Check for network_security_config.xml.
        has_nsc = any(
            "network_security_config" in p for p in self._file_paths
        )
        if has_nsc:
            findings.append(
                RiskFinding(
                    title="Custom network security configuration found",
                    severity=Severity.INFO,
                    category="network",
                    description=(
                        "The app includes a `network_security_config.xml`, which "
                        "may define custom certificate pinning or trust anchors."
                    ),
                    recommendation=(
                        "Review the network security configuration for any "
                        "overly permissive trust settings."
                    ),
                    evidence=["network_security_config.xml"],
                )
            )

        return findings
