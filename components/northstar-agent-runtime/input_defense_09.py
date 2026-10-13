"""Base64 Detection: flag suspicious base64 blobs in input, Simulated.

Base64 is a favorite hiding spot for shell payloads, URLs, and binary
blobs smuggled past text filters. This module finds long base64-looking
runs, validates them strictly, and flags the ones that decode to
non-printable bytes or contain suspicious markers.

What this IS: a fail-closed heuristic for base64-obfuscated payloads.

What this IS NOT:
* A classifier that can tell benign blobs from malicious ones with certainty.
* A decoder for other encodings (hex is handled by input_defense_10).
"""

from __future__ import annotations

import ast
import base64
import re
from typing import List, Tuple

#: Module version.
INPUT_DEFENSE_09_VERSION = "input-defense-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-09.v1"

#: Markers (lowercase) looked for in decoded text.
_SUSPICIOUS_MARKERS = ("http", "<", "exec")


class InputDefense09Error(Exception):
    """Fail-closed."""


def find_candidates(text: str, min_len: int = 40) -> List[str]:
    """Find runs of base64 alphabet chars of at least min_len length."""
    if not isinstance(text, str):
        raise InputDefense09Error(f"expected str, got {type(text).__name__}")
    pattern = re.compile(r"[A-Za-z0-9+/]{" + str(int(min_len)) + r",}={0,2}")
    return [m.group(0) for m in pattern.finditer(text)]


def is_valid_b64(s: str) -> bool:
    """True if s strictly decodes as base64 (validate=True)."""
    if not isinstance(s, str):
        raise InputDefense09Error(f"expected str, got {type(s).__name__}")
    try:
        base64.b64decode(s, validate=True)
    except Exception:
        return False
    return True


def _is_non_printable(raw: bytes) -> bool:
    for b in raw:
        if b in (0x09, 0x0A, 0x0D):
            continue
        if b < 0x20 or b == 0x7F:
            return True
    return False


def check(text: str) -> Tuple[bool, List[str]]:
    """Return (suspicious, candidates).

    suspicious is True when any candidate strictly decodes as base64 and
    either decodes to non-printable bytes or contains a suspicious marker.
    """
    if not isinstance(text, str):
        raise InputDefense09Error(f"expected str, got {type(text).__name__}")
    candidates = find_candidates(text)
    suspicious = False
    for cand in candidates:
        try:
            raw = base64.b64decode(cand, validate=True)
        except Exception:
            continue
        if _is_non_printable(raw):
            suspicious = True
            break
        lowered = raw.decode("latin-1").lower()
        if any(m in lowered for m in _SUSPICIOUS_MARKERS):
            suspicious = True
            break
    return suspicious, candidates


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "base64"}
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
    evil = base64.b64encode(
        b"exec <http://evil.example.com/x.sh> -- download and run"
    ).decode("ascii")
    assert len(evil) >= 40
    cands = find_candidates("prefix " + evil + " suffix")
    assert cands == [evil], cands
    assert find_candidates("short aGVsbG8= here") == []
    assert is_valid_b64("aGVsbG8=") is True
    assert is_valid_b64("!!!not b64!!!") is False
    assert is_valid_b64("abc") is False  # bad length
    sus, got = check("prefix " + evil + " suffix")
    assert sus is True and got == [evil], (sus, got)
    binary = base64.b64encode(bytes(range(256))).decode("ascii")
    sus2, _ = check(binary)
    assert sus2 is True  # non-printable decoded bytes
    benign = base64.b64encode(
        b"the quick brown fox jumps over the lazy dog and then some"
    ).decode("ascii")
    sus3, got3 = check("log line: " + benign)
    assert sus3 is False and got3 == [benign], (sus3, got3)
    sus4, got4 = check("nothing encoded here")
    assert sus4 is False and got4 == []
    for fn in (find_candidates, is_valid_b64, check):
        try:
            fn(5.5)  # type: ignore[arg-type]
        except InputDefense09Error:
            pass
        else:
            raise AssertionError("non-str must raise")
    assert stdlib_only()
    print("input-defense-09 OK")


if __name__ == "__main__":
    main()
