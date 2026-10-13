"""White-text exfiltration defense (D-OUT-037), Simulated.

Detects:
- HTML that hides text from the reader while keeping it machine-readable:
  style attributes with color:#fff/#ffffff/white/rgb(255,255,255),
  font-size:0, display:none, visibility:hidden, opacity:0 -- where visible
  (hidden) text actually follows the tag.
- Returns evidence snippets of tag + hidden text.

What this IS:
* A gate-layer regex detector for invisible-ink HTML exfiltration tricks.

What this IS NOT:
* Not a CSS engine -- no cascade, inheritance, or computed-style evaluation.
* Not a full HTML parser -- tag/style matching is regex-based and heuristic.
"""

from __future__ import annotations

import ast
import re
from typing import List, Tuple

#: Module version.
OUT_DEF_37_VERSION = "out-def-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-37.v1"

#: Style declarations that make text invisible. Case-insensitive, whitespace tolerant.
_HIDDEN_PATTERNS = [
    r"color\s*:\s*(?:#(?:fff|ffffff)\b|white\b|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\))",
    r"font-size\s*:\s*0(?:px|pt|em|rem|%)?",
    r"display\s*:\s*none\b",
    r"visibility\s*:\s*hidden\b",
    r"opacity\s*:\s*0(?:\.0+)?\b",
]
_HIDDEN_RE = re.compile(
    "|".join("(?:%s)" % p for p in _HIDDEN_PATTERNS), re.IGNORECASE
)

#: Opening tag carrying a quoted style attribute.
_TAG_RE = re.compile(
    r"<[^>]*\bstyle\s*=\s*(['\"])(?P<style>.*?)\1[^>]*>", re.IGNORECASE
)

#: Text directly following a tag (up to the next tag).
_TEXT_AFTER_RE = re.compile(r"\s*([^<]+)")


def detect_white_text(html: str) -> Tuple[bool, str, List[str]]:
    """Return (threat, reason, evidence).

    threat is True when an element styled invisible actually carries text --
    the white-text exfiltration shape. Evidence entries are "tag + text"
    snippets, truncated for readability.
    """
    evidence: List[str] = []
    for match in _TAG_RE.finditer(html or ""):
        if not _HIDDEN_RE.search(match.group("style")):
            continue
        text_match = _TEXT_AFTER_RE.match(html, match.end())
        text = text_match.group(1).strip() if text_match else ""
        if text:
            snippet = (match.group(0) + text)[:120]
            evidence.append(snippet)
    if evidence:
        return True, "%d hidden-text span(s)" % len(evidence), evidence
    return False, "ok", []


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
    # White-on-white.
    threat, _, ev = detect_white_text(
        '<span style="color:#fff">secret payload</span>'
    )
    assert threat is True and len(ev) == 1
    assert "secret payload" in ev[0]

    # Case-insensitive + whitespace tolerant.
    threat, _, _ = detect_white_text(
        "<DIV STYLE=' DISPLAY : NONE '>hidden</DIV>"
    )
    assert threat is True

    # font-size:0 and rgb() spellings.
    threat, _, _ = detect_white_text(
        '<p style="font-size:0">zero</p><p style="color: rgb(255, 255, 255)">w</p>'
    )
    assert threat is True

    # visibility:hidden / opacity:0 spellings.
    threat, _, _ = detect_white_text(
        '<b style="visibility:hidden">v</b><i style="opacity:0">o</i>'
    )
    assert threat is True

    # Hidden style but no text following: not exfiltration.
    threat, _, ev = detect_white_text('<span style="display:none"></span>')
    assert threat is False and ev == []

    # Visible styling is clean.
    threat, _, _ = detect_white_text('<p style="color:#000">hello</p>')
    assert threat is False

    # No style at all is clean.
    threat, _, _ = detect_white_text("<p>plain text</p>")
    assert threat is False

    assert stdlib_only()
    print("out-def-37 OK: white-text detect, evidence, stdlib")


if __name__ == "__main__":
    main()
