"""Screen and navigation mapper.

Infers the app's screen structure from Activity declarations in the
manifest and layout resource files found in the APK. Produces a
simplified navigation map showing the app's likely screen flow.

This is a heuristic-based mapper — without runtime data or explicit
navigation graphs, some inferences may be approximate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from apk_blueprint_analyzer.component_extractor import ComponentInfo


@dataclass
class ScreenInfo:
    """Represents an inferred screen in the application.

    Attributes:
        activity_name: Fully-qualified Activity class name.
        short_name: Simple class name (without package prefix).
        is_launcher: Whether this is the app's entry screen.
        is_exported: Whether the Activity is exported.
        intent_actions: List of intent actions this Activity handles.
        deeplink_schemes: URI schemes handled by this Activity.
        deeplink_hosts: Hosts handled by this Activity.
        inferred_purpose: Best-guess purpose based on naming heuristics.
        layout_files: Layout XML files likely associated with this screen.
    """

    activity_name: str = ""
    short_name: str = ""
    is_launcher: bool = False
    is_exported: bool = False
    intent_actions: list[str] = field(default_factory=list)
    deeplink_schemes: list[str] = field(default_factory=list)
    deeplink_hosts: list[str] = field(default_factory=list)
    inferred_purpose: str = ""
    layout_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "activity_name": self.activity_name,
            "short_name": self.short_name,
            "is_launcher": self.is_launcher,
            "is_exported": self.is_exported,
            "intent_actions": self.intent_actions,
            "deeplink_schemes": self.deeplink_schemes,
            "deeplink_hosts": self.deeplink_hosts,
            "inferred_purpose": self.inferred_purpose,
            "layout_files": self.layout_files,
        }


# ──────────────────────────────────────────────────────────────────────
# Name-based heuristics for inferring Activity purpose.
# Maps lowercase substrings found in Activity names to descriptions.
# ──────────────────────────────────────────────────────────────────────

_PURPOSE_HINTS: list[tuple[str, str]] = [
    ("splash", "Splash / loading screen"),
    ("onboard", "Onboarding / first-run experience"),
    ("login", "User login / sign-in"),
    ("signin", "User sign-in"),
    ("signup", "User registration / sign-up"),
    ("register", "User registration"),
    ("auth", "Authentication"),
    ("main", "Main / home screen"),
    ("home", "Home / dashboard"),
    ("dashboard", "Dashboard"),
    ("setting", "Settings / preferences"),
    ("preference", "Settings / preferences"),
    ("profile", "User profile"),
    ("account", "Account management"),
    ("detail", "Detail / item view"),
    ("list", "List / feed view"),
    ("search", "Search"),
    ("chat", "Chat / messaging"),
    ("message", "Messaging"),
    ("notification", "Notifications"),
    ("camera", "Camera / photo capture"),
    ("gallery", "Gallery / image browser"),
    ("photo", "Photo viewer"),
    ("video", "Video player"),
    ("map", "Map / location view"),
    ("payment", "Payment / checkout"),
    ("checkout", "Checkout / purchase"),
    ("cart", "Shopping cart"),
    ("webview", "Embedded web content"),
    ("browser", "In-app browser"),
    ("about", "About / info screen"),
    ("help", "Help / support"),
    ("feedback", "Feedback / contact"),
    ("share", "Sharing / social"),
    ("edit", "Editor / form"),
    ("compose", "Content creation"),
    ("scan", "Scanner (QR, barcode, etc.)"),
]


class ScreenMapper:
    """Maps Activities and layouts to infer the app's screen structure.

    Takes extracted component information and layout file paths to
    build a list of :class:`ScreenInfo` objects representing the
    app's screens.

    Args:
        activities: List of Activity :class:`ComponentInfo` objects.
        layout_files: List of layout XML file paths from the APK.
    """

    def __init__(
        self,
        activities: list[ComponentInfo],
        layout_files: list[str] | None = None,
    ) -> None:
        self._activities = activities
        self._layout_files = layout_files or []
        self._screens: list[ScreenInfo] | None = None

    def map_screens(self) -> list[ScreenInfo]:
        """Build the screen map.

        Returns:
            List of :class:`ScreenInfo` objects.
        """
        if self._screens is not None:
            return self._screens

        screens: list[ScreenInfo] = []
        for activity in self._activities:
            screen = self._activity_to_screen(activity)
            screens.append(screen)

        # Sort: launcher first, then alphabetical.
        screens.sort(key=lambda s: (not s.is_launcher, s.short_name.lower()))
        self._screens = screens
        return screens

    def get_launcher_screen(self) -> ScreenInfo | None:
        """Return the launcher (entry) screen, if any.

        Returns:
            The launcher :class:`ScreenInfo`, or ``None``.
        """
        for s in self.map_screens():
            if s.is_launcher:
                return s
        return None

    def get_deeplink_screens(self) -> list[ScreenInfo]:
        """Return screens that handle deep links.

        Returns:
            List of :class:`ScreenInfo` with deep link handlers.
        """
        return [
            s
            for s in self.map_screens()
            if s.deeplink_schemes or s.deeplink_hosts
        ]

    def _activity_to_screen(self, activity: ComponentInfo) -> ScreenInfo:
        """Convert a :class:`ComponentInfo` to a :class:`ScreenInfo`."""
        short_name = activity.name.rsplit(".", 1)[-1] if "." in activity.name else activity.name

        # Collect intent filter data.
        all_actions: list[str] = []
        all_schemes: list[str] = []
        all_hosts: list[str] = []
        for filt in activity.intent_filters:
            all_actions.extend(filt.actions)
            all_schemes.extend(filt.data_schemes)
            all_hosts.extend(filt.data_hosts)

        # Infer purpose from naming.
        purpose = self._infer_purpose(short_name)

        # Find likely associated layout files.
        layouts = self._match_layouts(short_name)

        return ScreenInfo(
            activity_name=activity.name,
            short_name=short_name,
            is_launcher=activity.is_launcher,
            is_exported=activity.exported is True,
            intent_actions=all_actions,
            deeplink_schemes=all_schemes,
            deeplink_hosts=all_hosts,
            inferred_purpose=purpose,
            layout_files=layouts,
        )

    @staticmethod
    def _infer_purpose(class_name: str) -> str:
        """Infer the purpose of an Activity from its class name."""
        lower = class_name.lower()
        for keyword, description in _PURPOSE_HINTS:
            if keyword in lower:
                return description
        return "Application screen"

    def _match_layouts(self, class_name: str) -> list[str]:
        """Match layout files by converting CamelCase to snake_case.

        For example, ``"LoginActivity"`` would match
        ``"res/layout/activity_login.xml"``.
        """
        # Convert CamelCase to snake_case.
        snake = self._camel_to_snake(class_name)
        # Remove common suffixes.
        for suffix in ("_activity", "_fragment"):
            if snake.endswith(suffix):
                snake = snake[: -len(suffix)]

        matches: list[str] = []
        for layout in self._layout_files:
            layout_lower = layout.lower()
            if snake in layout_lower or class_name.lower() in layout_lower:
                matches.append(layout)
        return matches

    @staticmethod
    def _camel_to_snake(name: str) -> str:
        """Convert a CamelCase string to snake_case."""
        import re

        s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
        return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
