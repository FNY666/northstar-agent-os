"""Homoglyph exfiltration defense (D-OUT-036), Simulated.

Detects:
- Mixed-script tokens: Latin letters combined with lookalike Cyrillic/Greek
  characters (e.g. Cyrillic 'а' posing as Latin 'a') used to smuggle
  exfiltrated strings past naive filters.
- Offending tokens inside free text via scan_text().
Cleans:
- normalize_confusables(): maps known confusables back to their Latin lookalikes.

What this IS:
* A gate-layer detector for lookalike-character exfiltration tricks.
* A normalizer that rewrites confusable characters to plain Latin.

What this IS NOT:
* Not a full Unicode confusables engine (UTS #39) -- the map is a curated subset.
* Not a font or rendering oracle -- visual similarity is heuristic.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Tuple

#: Module version.
OUT_DEF_36_VERSION = "out-def-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-36.v1"

#: Non-Latin lookalikes mapped to their Latin counterparts.
CONFUSABLES: Dict[str, str] = {
    "а": "a",  # Cyrillic small letter a (U+0430)
    "е": "e",  # Cyrillic small letter ie (U+0435)
    "о": "o",  # Cyrillic small letter o (U+043E)
    "р": "p",  # Cyrillic small letter er (U+0440)
    "с": "c",  # Cyrillic small letter es (U+0441)
    "ѕ": "s",  # Cyrillic small letter dze (U+0455)
    "ј": "j",  # Cyrillic small letter je (U+0458)
    "к": "k",  # Cyrillic small letter ka (U+043A)
    "м": "m",  # Cyrillic small letter em (U+043C)
    "н": "h",  # Cyrillic small letter en (U+043D)
    "х": "x",  # Cyrillic small letter ha (U+0445)
    "у": "y",  # Cyrillic small letter u (U+0443)
    "α": "a",  # Greek small letter alpha (U+03B1)
    "ε": "e",  # Greek small letter epsilon (U+03B5)
    "ο": "o",  # Greek small letter omicron (U+03BF)
}

#: Word-token pattern (Unicode letters and digits, no underscore).
_TOKEN_RE = re.compile(r"[^\W_]+")


def detect_mixed_script(token: str) -> Tuple[bool, str]:
    """Return (threat, reason).

    threat is True when the token mixes ASCII Latin letters with known
    confusable non-Latin characters -- the classic homoglyph smuggling shape.
    """
    if not token:
        return False, "empty token"
    has_latin = any(ch.isascii() and ch.isalpha() for ch in token)
    confusables = sorted({ch for ch in token if ch in CONFUSABLES})
    if has_latin and confusables:
        shown = ", ".join("U+%04X" % ord(ch) for ch in confusables)
        return True, "mixed-script token %r: Latin + confusable(s) %s" % (
            token,
            shown,
        )
    return False, "ok"


def scan_text(text: str) -> Tuple[bool, str, List[str]]:
    """Scan free text; return (threat, reason, offending_tokens)."""
    offending: List[str] = []
    for token in _TOKEN_RE.findall(text or ""):
        threat, _ = detect_mixed_script(token)
        if threat:
            offending.append(token)
    if offending:
        return True, "%d mixed-script token(s)" % len(offending), offending
    return False, "ok", []


def normalize_confusables(text: str) -> str:
    """Rewrite known confusables back to their Latin lookalikes."""
    return "".join(CONFUSABLES.get(ch, ch) for ch in (text or ""))


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
    # Cyrillic 'а' (U+0430) smuggled into a Latin token.
    threat, reason = detect_mixed_script("pаssword")
    assert threat is True
    assert "mixed-script" in reason

    # Greek omicron (U+03BF) inside Latin.
    threat, _ = detect_mixed_script("tοken")
    assert threat is True

    # Pure Latin is clean.
    threat, _ = detect_mixed_script("password")
    assert threat is False

    # Pure Cyrillic (no Latin mixing) is not this detector's threat shape.
    threat, _ = detect_mixed_script("пароль")
    assert threat is False

    # Scan finds the offending token, leaves clean text alone.
    threat, _, bad = scan_text("all clean pаssword here")
    assert threat is True and bad == ["pаssword"]
    threat, _, bad = scan_text("nothing to see here")
    assert threat is False and bad == []

    # Normalizer maps confusables back to Latin.
    assert normalize_confusables("hеllo wοrld") == "hello world"
    assert normalize_confusables("plain") == "plain"

    assert stdlib_only()
    print("out-def-36 OK: mixed-script detect, scan, normalize, stdlib")


if __name__ == "__main__":
    main()
