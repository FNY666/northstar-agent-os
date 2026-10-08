"""HTML Entity Decoding Guard: detect double-encoded entity payloads, Simulated.

Attackers hide "<script>" and similar payloads behind HTML entities
("&lt;script&gt;") -- or double-encode them ("&amp;lt;script&amp;gt;") so a
single decode pass looks benign. This module decodes one layer with
html.unescape and flags anything that still looks entity-encoded after
that pass.

What this IS: a fail-closed detector for entity-encoding smuggling.

What this IS NOT:
* A full HTML sanitizer or allow-list filter.
* A replacement for context-appropriate output encoding.
"""

from __future__ import annotations

import ast
import html
import re
from typing import Tuple

#: Module version.
INPUT_DEFENSE_07_VERSION = "input-defense-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-07.v1"

#: Matches one HTML entity: numeric decimal, numeric hex, or named.
_ENTITY_RE = re.compile(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")


class InputDefense07Error(Exception):
    """Fail-closed."""


def _require_str(text: object) -> str:
    if not isinstance(text, str):
        raise InputDefense07Error(f"expected str, got {type(text).__name__}")
    return text


def decode_once(text: str) -> str:
    """Decode one layer of HTML entities via html.unescape."""
    return html.unescape(_require_str(text))


def is_double_encoded(text: str) -> bool:
    """True if text still contains entity syntax after one decode pass."""
    return bool(_ENTITY_RE.search(decode_once(_require_str(text))))


def check(text: str) -> Tuple[bool, str]:
    """Return (suspicious, decoded).

    suspicious is True when the input is double-encoded, or when the
    once-decoded text contains "<script" or "javascript:" (case-insensitive).
    """
    _require_str(text)
    decoded = decode_once(text)
    lowered = decoded.lower()
    suspicious = (
        is_double_encoded(text)
        or "<script" in lowered
        or "javascript:" in lowered
    )
    return suspicious, decoded


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "html"}
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
    assert decode_once("&lt;b&gt;") == "<b>"
    assert decode_once("&#60;div&#62;") == "<div>"
    assert is_double_encoded("&amp;lt;") is True
    assert is_double_encoded("&#38;lt;") is True
    assert is_double_encoded("&lt;") is False
    assert is_double_encoded("plain text") is False
    sus, dec = check("&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;")
    assert sus is True, (sus, dec)
    assert dec == "&lt;script&gt;alert(1)&lt;/script&gt;", dec
    sus2, dec2 = check("&#60;script&#62;alert(1)")
    assert sus2 is True and dec2 == "<script>alert(1)", (sus2, dec2)
    sus3, dec3 = check("fish &amp; chips")
    assert sus3 is False and dec3 == "fish & chips", (sus3, dec3)
    for fn in (decode_once, is_double_encoded, check):
        try:
            fn(123)  # type: ignore[arg-type]
        except InputDefense07Error:
            pass
        else:
            raise AssertionError("non-str must raise")
    assert stdlib_only()
    print("input-defense-07 OK")


if __name__ == "__main__":
    main()
