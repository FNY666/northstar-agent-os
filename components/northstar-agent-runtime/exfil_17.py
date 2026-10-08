"""Social media exfiltration detection (social-exfil), Simulated.

Detects sensitive data in social posts: SSNs, API keys, internal hostnames, and text marked confidential.

What this IS: a social-post PII/secrets scanner.

What this IS NOT:
* Pattern-based; paraphrased leaks may pass.
* Does not post or delete -- only detects.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_17_VERSION = "exfil-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-17.v1"


class Exfil17Error(Exception):
    """Fail-closed."""


_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\bsk-[A-Za-z0-9]{16,}\b", "API key"),
    (r"(?i)\b[a-z0-9-]+\.internal\.corp\b", "internal host"),
    (r"(?i)\bconfidential\b", "marked confidential"),
]


def detect_social_exfil(post: str) -> tuple:
    """Detect exfiltration in social post. Returns (suspicious, reason)."""
    if not isinstance(post, str):
        raise Exfil17Error("post must be str")
    for pat, label in _PATTERNS:
        if re.search(pat, post):
            return True, "sensitive in post: %s" % label
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
    ok, _ = detect_social_exfil("Had a great lunch today!")
    assert ok is False
    ok, _ = detect_social_exfil("my ssn is 123-45-6789, help")
    assert ok is True
    ok, _ = detect_social_exfil("deploy to api.internal.corp now")
    assert ok is True
    assert stdlib_only()
    print("exfil-17 OK: social exfil, fail-closed")


if __name__ == "__main__":
    main()
