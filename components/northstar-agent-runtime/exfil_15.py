"""QR code exfiltration detection (mock) (qr-mock), Simulated.

Mock detector for QR-encoded exfiltration: flags oversized payloads, base64 blobs, and sensitive patterns inside QR content.

What this IS: a mock QR payload content checker.

What this IS NOT:
* MOCK: analyzes decoded payload strings, no image decoding.
* Size limits are heuristic.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_15_VERSION = "exfil-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-15.v1"


class Exfil15Error(Exception):
    """Fail-closed."""


def detect_qr_exfil(payload: str) -> tuple:
    """Detect QR exfiltration. Returns (suspicious, reason)."""
    if not isinstance(payload, str):
        raise Exfil15Error("payload must be str")
    if len(payload) > 500:
        return True, "oversized QR payload: %d chars" % len(payload)
    if len(payload) > 100 and re.fullmatch(r"[A-Za-z0-9+/=\s]+", payload):
        return True, "base64 blob in QR"
    for pat, label in [(r"sk-[A-Za-z0-9]{16,}", "API key"), (r"\b\d{3}-\d{2}-\d{4}\b", "SSN")]:
        if re.search(pat, payload):
            return True, "sensitive in QR: %s" % label
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "re"}
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
    ok, _ = detect_qr_exfil("https://example.com/menu")
    assert ok is False
    ok, _ = detect_qr_exfil("x" * 600)
    assert ok is True
    ok, _ = detect_qr_exfil("token sk-abcdefghijklmnopqrst")
    assert ok is True
    assert stdlib_only()
    print("exfil-15 OK: mock qr, fail-closed")


if __name__ == "__main__":
    main()
