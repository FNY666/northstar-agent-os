"""obs_04: Log redaction (redact PII in logs), Simulated.

Replaces PII patterns with [REDACTED:type] before logging.
Patterns: email, phone, SSN, API keys.

Fail-closed: non-str input raises.
Stdlib only.
"""

from __future__ import annotations

import ast
import re

OBS04_VERSION = "obs-04.v1"
SCHEMA_PIN = "northstar.obs-04.v1"

_PATTERNS = [
    ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("PHONE", r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b"),
]


class Obs04Error(Exception):
    """Fail-closed."""


def redact(text: str) -> str:
    """Redact PII.  Returns redacted text."""
    if not isinstance(text, str):
        raise Obs04Error("text must be str")
    out = text
    for name, pattern in _PATTERNS:
        out = re.sub(pattern, f"[REDACTED:{name}]", out)
    return out


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    r = redact("email a@b.com phone 555-123-4567")
    assert "a@b.com" not in r and "[REDACTED:EMAIL]" in r
    assert "[REDACTED:PHONE]" in r
    assert redact("clean text") == "clean text"
    try:
        redact(123)  # type: ignore
        raise AssertionError("should raise")
    except Obs04Error:
        pass
    assert stdlib_only()
    print("obs_04 OK")


if __name__ == "__main__":
    main()
