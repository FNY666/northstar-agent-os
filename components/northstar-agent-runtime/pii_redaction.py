"""PII redaction: output filtering (D-OUT-001), Simulated.

Redacts PII from model outputs before delivery.  Uses the PII vault
patterns but for redaction (not masking).

What this IS: output-side PII protection.

What this IS NOT:
* Not reversible -- redaction is destructive (vs vault masking).
"""

from __future__ import annotations

import ast
import re
from typing import Dict

#: Module version.
REDACTION_VERSION = "pii-redaction.v1"
SCHEMA_PIN = "northstar.pii-redaction.v1"

PATTERNS = {
    "EMAIL": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]"),
    "PHONE": (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[REDACTED_PHONE]"),
    "SSN": (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    "API_KEY": (r"\bsk-[A-Za-z0-9]{20,}\b", "[REDACTED_KEY]"),
}

def redact(text: str) -> tuple[str, Dict[str, int]]:
    """Redact PII. Returns (redacted_text, counts)."""
    if not isinstance(text, str):
        raise ValueError("text must be str")
    counts = {}
    result = text
    for name, (pattern, replacement) in PATTERNS.items():
        matches = re.findall(pattern, result)
        if matches:
            counts[name] = len(matches)
            result = re.sub(pattern, replacement, result)
    return result, counts

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    r, c = redact("Email a@b.com, call 555-123-4567")
    assert "[REDACTED_EMAIL]" in r
    assert "[REDACTED_PHONE]" in r
    assert c["EMAIL"] == 1
    assert stdlib_only()
    print("pii-redaction OK")

if __name__ == "__main__":
    main()
