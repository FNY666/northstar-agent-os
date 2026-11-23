"""URL Decoding Guard: detect multi-encoded URL payloads, Simulated.

"%2e%2e%2f" looks innocent until decoded twice into "../". This module
repeatedly applies urllib.parse.unquote (up to 5 rounds) until the string
stabilizes, counts the rounds used, and flags multi-encoded input or
decoded text that contains common attack markers.

What this IS: a fail-closed detector for URL-encoding smuggling.

What this IS NOT:
* A WAF or signature engine for request paths.
* A URL parser/validator (no scheme/host handling).
"""

from __future__ import annotations

import ast
import urllib.parse
from typing import Tuple

#: Module version.
INPUT_DEFENSE_08_VERSION = "input-defense-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-08.v1"

#: Markers looked for in the fully decoded text (compared lowercase).
_ATTACK_MARKERS = ("../", "<script", "javascript:", "select ", "${")


class InputDefense08Error(Exception):
    """Fail-closed."""


def decode_all(text: str, max_rounds: int = 5) -> Tuple[str, int]:
    """Unquote repeatedly until stable; return (decoded, rounds_used)."""
    if not isinstance(text, str):
        raise InputDefense08Error(f"expected str, got {type(text).__name__}")
    decoded = text
    rounds = 0
    for _ in range(max_rounds):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
        rounds += 1
    return decoded, rounds


def check(text: str) -> Tuple[bool, str, int]:
    """Return (suspicious, decoded, rounds).

    suspicious is True when rounds > 1 (multi-encoded) or the decoded text
    contains an attack marker (case-insensitive for lettered markers).
    """
    if not isinstance(text, str):
        raise InputDefense08Error(f"expected str, got {type(text).__name__}")
    decoded, rounds = decode_all(text)
    lowered = decoded.lower()
    suspicious = rounds > 1 or any(m in lowered for m in _ATTACK_MARKERS)
    return suspicious, decoded, rounds


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "urllib"}
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
    dec, rounds = decode_all("%252e%252e%252fetc/passwd")
    assert dec == "../etc/passwd", dec
    assert rounds == 2, rounds
    dec2, rounds2 = decode_all("hello world")
    assert dec2 == "hello world" and rounds2 == 0
    dec3, rounds3 = decode_all("%41%42")
    assert dec3 == "AB" and rounds3 == 1
    sus, decd, r = check("%252e%252e%252fetc%252fpasswd")
    assert sus is True and decd == "../etc/passwd" and r == 2, (sus, decd, r)
    sus2, decd2, r2 = check("javascript%3Aalert(1)")
    assert sus2 is True and decd2 == "javascript:alert(1)" and r2 == 1
    sus3, decd3, r3 = check("%24%7bPATH%7d")
    assert sus3 is True and decd3 == "${PATH}" and r3 == 1
    sus4, decd4, r4 = check("plain text")
    assert sus4 is False and decd4 == "plain text" and r4 == 0
    for fn in (decode_all, check):
        try:
            fn(None)  # type: ignore[arg-type]
        except InputDefense08Error:
            pass
        else:
            raise AssertionError("non-str must raise")
    assert stdlib_only()
    print("input-defense-08 OK")


if __name__ == "__main__":
    main()
