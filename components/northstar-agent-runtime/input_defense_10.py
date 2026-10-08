"""Hex Decoding Guard: flag suspicious hex-encoded payloads, Simulated.

Hex strings like "3c7363726970743e" hide "<script>" from text filters.
This module finds long even-length hex runs, decodes them, and flags any
that decode to ASCII containing common attack markers.

What this IS: a fail-closed heuristic for hex-obfuscated payloads.

What this IS NOT:
* A full binary-analysis or shellcode detector.
* A handler for odd-length or non-ASCII hex content.
"""

from __future__ import annotations

import ast
import re
from typing import List, Optional, Tuple

#: Module version.
INPUT_DEFENSE_10_VERSION = "input-defense-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-10.v1"

#: Markers (lowercase) looked for in decoded ASCII.
_ATTACK_MARKERS = ("<script", "javascript:", "select", "http", "cmd", "exec")


class InputDefense10Error(Exception):
    """Fail-closed."""


def find_candidates(text: str, min_len: int = 32) -> List[str]:
    """Find even-length hex runs of at least min_len characters."""
    if not isinstance(text, str):
        raise InputDefense10Error(f"expected str, got {type(text).__name__}")
    pairs = max(1, int(min_len) // 2)
    pattern = re.compile(r"\b(?:[0-9a-fA-F]{2}){" + str(pairs) + r",}\b")
    return [m.group(0) for m in pattern.finditer(text)]


def decode_hex(s: str) -> Optional[bytes]:
    """Decode a hex string; return None when invalid."""
    if not isinstance(s, str):
        raise InputDefense10Error(f"expected str, got {type(s).__name__}")
    try:
        return bytes.fromhex(s)
    except (ValueError, TypeError):
        return None


def check(text: str) -> Tuple[bool, List[str]]:
    """Return (suspicious, decoded_hits).

    decoded_hits holds the ASCII-decoded strings that contain an attack
    marker; suspicious is True when the list is non-empty.
    """
    if not isinstance(text, str):
        raise InputDefense10Error(f"expected str, got {type(text).__name__}")
    hits: List[str] = []
    for cand in find_candidates(text):
        raw = decode_hex(cand)
        if raw is None:
            continue
        try:
            ascii_text = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        lowered = ascii_text.lower()
        if any(m in lowered for m in _ATTACK_MARKERS):
            hits.append(ascii_text)
    return (len(hits) > 0), hits


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
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
    payload = "<script>alert(1)</script>".encode("utf-8").hex()
    assert len(payload) >= 32
    cands = find_candidates("see " + payload + " end")
    assert cands == [payload], cands
    assert find_candidates("short deadbeef run") == []
    raw = decode_hex(payload)
    assert raw is not None and raw.decode("ascii") == "<script>alert(1)</script>"
    assert decode_hex("zz") is None
    assert decode_hex("abc") is None  # odd length
    sus, hits = check("see " + payload + " end")
    assert sus is True and hits == ["<script>alert(1)</script>"], (sus, hits)
    sel = "SELECT * FROM users".encode("utf-8").hex()
    sus2, hits2 = check("query " + sel + " done")
    assert sus2 is True and hits2 == ["SELECT * FROM users"], (sus2, hits2)
    benign_hex = "deadbeef" * 8  # decodes to non-ASCII bytes
    sus3, hits3 = check("blob " + benign_hex)
    assert sus3 is False and hits3 == [], (sus3, hits3)
    sus4, hits4 = check("plain text")
    assert sus4 is False and hits4 == []
    for fn in (find_candidates, decode_hex, check):
        try:
            fn(object())  # type: ignore[arg-type]
        except InputDefense10Error:
            pass
        else:
            raise AssertionError("non-str must raise")
    assert stdlib_only()
    print("input-defense-10 OK")


if __name__ == "__main__":
    main()
