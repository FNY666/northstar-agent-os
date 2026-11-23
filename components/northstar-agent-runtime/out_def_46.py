"""Font exfiltration defense: hidden payloads in font name tables, Simulated.

Detects:
- Long base64-like tokens (>=32 chars, base64 alphabet) embedded in name strings
- Non-printable / control characters smuggled into name strings
- Unexpected name IDs (outside the standard 0-6 set) carrying long strings (>64 chars)

What this IS:
* A gate-layer check on font name-table entries before a font is trusted.
* Detection only -- it flags suspicious entries and returns them as evidence.

What this IS NOT:
* Not a full font parser -- no TTF/OTF table parsing, no checksums, no shaping.
* Not a content policy -- the host decides whether to block, strip, or quarantine.
"""

from __future__ import annotations

import ast
import re
from typing import Any

#: Module version.
OUT_DEF_46_VERSION = "out-def-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-46.v1"


class OutDef46Error(Exception):
    """Fail-closed."""


#: Standard name IDs per the OpenType name-table spec.
STANDARD_NAME_IDS = frozenset({0, 1, 2, 3, 4, 5, 6})

#: A run of base64-alphabet chars long enough to plausibly carry a payload.
_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")

#: Control / non-printable characters that have no business in a font name.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: Minimum string length that makes an unexpected name ID suspicious.
_LONG_STRING = 64


def _check_entry(entry: dict) -> list:
    """Return a list of flag labels for one name-table entry."""
    flags: list = []
    string = entry.get("string", "")
    if not isinstance(string, str):
        string = str(string)
    name_id = entry.get("name_id")

    if _BASE64_TOKEN_RE.search(string):
        flags.append("base64-like token (>=32 chars)")
    if _CONTROL_CHAR_RE.search(string):
        flags.append("control/non-printable characters")
    if (
        isinstance(name_id, int)
        and name_id not in STANDARD_NAME_IDS
        and len(string) > _LONG_STRING
    ):
        flags.append(
            f"unexpected name_id {name_id} with long string ({len(string)} chars)"
        )
    return flags


def detect_font_exfil(names: list) -> tuple[bool, str, list]:
    """Scan font name-table entries for exfil markers.

    Returns (threat_found, reason, evidence). threat_found=True means exfil
    was detected. Raises OutDef46Error (fail-closed) on malformed input.
    """
    if not isinstance(names, list):
        raise OutDef46Error(
            f"expected list of name entries, got {type(names).__name__}"
        )
    hits: list = []
    for i, entry in enumerate(names):
        if not isinstance(entry, dict):
            raise OutDef46Error(f"name entry {i} is not a dict")
        if "name_id" not in entry or "string" not in entry:
            raise OutDef46Error(f"name entry {i} missing name_id/string")
        flags = _check_entry(entry)
        if flags:
            hits.append({"entry": entry, "flags": flags})
    if hits:
        return (
            True,
            f"{len(hits)} suspicious font name entr(ies) detected",
            hits,
        )
    return False, "font name table clean", []


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
    # (a) base64-like token.
    token = "QUJD" * 16
    found, _, evidence = detect_font_exfil(
        [{"name_id": 1, "string": "MyFont " + token}]
    )
    assert found is True
    assert any("base64" in f for e in evidence for f in e["flags"])

    # (b) control characters.
    found, _, _ = detect_font_exfil(
        [{"name_id": 1, "string": "Bad\x00Name"}]
    )
    assert found is True

    # (c) unexpected name_id with long string.
    found, _, _ = detect_font_exfil(
        [{"name_id": 99, "string": "x" * 65}]
    )
    assert found is True

    # Clean: standard ids only, plus a short string on an odd id.
    found, reason, _ = detect_font_exfil(
        [
            {"name_id": 1, "string": "My Font"},
            {"name_id": 3, "string": "Copyright 2026 Example Foundry. " * 8},
            {"name_id": 99, "string": "short"},
        ]
    )
    assert found is False, reason

    # Fail-closed on malformed input.
    try:
        detect_font_exfil("not a list")  # type: ignore[arg-type]
    except OutDef46Error:
        pass
    else:
        raise AssertionError("expected OutDef46Error")

    assert stdlib_only()
    print("out-def-46 OK: base64 token, control chars, unexpected name_id, stdlib")


if __name__ == "__main__":
    main()
