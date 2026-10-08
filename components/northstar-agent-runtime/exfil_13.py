"""Screenshot exfiltration detection (mock) (screenshot-mock), Simulated.

Mock detector for screenshot-based exfiltration: flags screen-capture API calls (getDisplayMedia, canvas readback, etc.).

What this IS: a mock screen-capture API call detector.

What this IS NOT:
* MOCK: analyzes provided call-name lists, no browser hooks.
* Cannot judge intent -- flags the capability use.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_13_VERSION = "exfil-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-13.v1"


class Exfil13Error(Exception):
    """Fail-closed."""


_SUSPICIOUS = {"getDisplayMedia", "takeScreenshot", "canvas.toDataURL", "drawWindow", "getScreenDetails"}


def detect_screenshot_exfil(calls: List[str]) -> tuple:
    """Detect screenshot exfil. Returns (suspicious, reason)."""
    if not isinstance(calls, list):
        raise Exfil13Error("calls must be list")
    hits = sorted({c for c in calls if c in _SUSPICIOUS})
    if hits:
        return True, "screenshot APIs: %s" % ", ".join(hits)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    ok, _ = detect_screenshot_exfil(["fetch", "render"])
    assert ok is False
    ok, _ = detect_screenshot_exfil(["render", "canvas.toDataURL"])
    assert ok is True
    assert stdlib_only()
    print("exfil-13 OK: mock screenshot, fail-closed")


if __name__ == "__main__":
    main()
