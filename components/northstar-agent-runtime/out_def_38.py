"""Metadata exfiltration defense (D-OUT-038), Simulated.

Detects:
- Metadata keys outside the allow-listed policy set.
- Metadata values that smuggle emails, absolute filesystem paths, or
  secret-looking tokens (16+ char alphanumeric runs).
Cleans:
- strip_meta(): keeps only allowed keys, truncates string values to 200 chars.

What this IS:
* A policy-based gate: only {"title", "format"} pass by default.
* A heuristic scanner for PII/secret-shaped values in metadata.

What this IS NOT:
* Not a data-loss-prevention engine -- the token/email regexes are heuristic.
* Not a schema validator -- it does not check value types beyond truncation.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Set, Tuple

#: Module version.
OUT_DEF_38_VERSION = "out-def-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-38.v1"

#: Policy: metadata keys allowed through the gate.
ALLOWED_KEYS: Set[str] = {"title", "format"}

#: Max length kept for string metadata values.
MAX_VALUE_CHARS = 200

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PATH_RE = re.compile(r"(?:/[A-Za-z0-9_.\-~]+)+|[A-Za-z]:\\(?:[^\\]+\\)*[^\\]*")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")

_VALUE_CHECKS = (
    ("email", _EMAIL_RE),
    ("absolute path", _PATH_RE),
    ("secret-looking token", _TOKEN_RE),
)


def detect_meta_exfil(meta: Dict[str, object]) -> Tuple[bool, str, List[str]]:
    """Return (threat, reason, evidence).

    threat is True when any key falls outside ALLOWED_KEYS, or any value
    contains an email, an absolute path, or a secret-looking token.
    """
    evidence: List[str] = []
    for key, value in (meta or {}).items():
        if key not in ALLOWED_KEYS:
            evidence.append("key %r not in allowed set" % (key,))
        text = value if isinstance(value, str) else str(value)
        for label, pattern in _VALUE_CHECKS:
            if pattern.search(text):
                evidence.append("value of %r contains %s" % (key, label))
                break
    if evidence:
        return True, "%d metadata issue(s)" % len(evidence), evidence
    return False, "ok", []


def strip_meta(
    meta: Dict[str, object], allowed: Optional[Set[str]] = None
) -> Dict[str, object]:
    """Return a copy with only allowed keys; strings truncated to 200 chars."""
    keys = ALLOWED_KEYS if allowed is None else set(allowed)
    cleaned: Dict[str, object] = {}
    for key, value in (meta or {}).items():
        if key in keys:
            cleaned[key] = (
                value[:MAX_VALUE_CHARS] if isinstance(value, str) else value
            )
    return cleaned


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    # Disallowed key.
    threat, _, ev = detect_meta_exfil({"title": "t", "author": "mallory"})
    assert threat is True
    assert any("author" in e for e in ev)

    # Email smuggled in an allowed key's value.
    threat, _, ev = detect_meta_exfil({"title": "hi bob@example.com"})
    assert threat is True
    assert any("email" in e for e in ev)

    # Absolute path smuggled in a value.
    threat, _, _ = detect_meta_exfil({"format": "pdf /etc/passwd"})
    assert threat is True

    # Secret-looking token in a value.
    threat, _, _ = detect_meta_exfil({"title": "k=sk-abcdefghijklmnopqrst"})
    assert threat is True

    # Clean metadata passes.
    threat, _, ev = detect_meta_exfil({"title": "Report", "format": "pdf"})
    assert threat is False and ev == []

    # strip_meta keeps only allowed keys and truncates long strings.
    cleaned = strip_meta(
        {"title": "x" * 500, "format": "pdf", "author": "mallory", "email": "a@b.c"}
    )
    assert set(cleaned) == {"title", "format"}
    assert len(cleaned["title"]) == 200
    assert cleaned["format"] == "pdf"

    # Custom allow-list honored.
    cleaned = strip_meta({"a": 1, "b": 2}, allowed={"b"})
    assert cleaned == {"b": 2}

    assert stdlib_only()
    print("out-def-38 OK: meta detect, strip, truncate, stdlib")


if __name__ == "__main__":
    main()
