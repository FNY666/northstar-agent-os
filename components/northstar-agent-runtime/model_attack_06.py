"""Model attack 06: adversarial example detection, Simulated.

Detects character-level adversarial perturbations in input text:
zero-width/invisible characters, Unicode homoglyphs (Cyrillic 'а'
vs Latin 'a'), bidirectional overrides, and abnormal character
repetition. These are the classic text adversarial-example carriers.

What this IS: input sanitization heuristics at the boundary.
What this IS NOT: not robust against paraphrase-level adversarial
examples; pair with semantic gates.
"""

from __future__ import annotations

import ast
import re
import unicodedata
from typing import Tuple

MODEL_ATTACK_06_VERSION = "model-attack-06.v1"

SCHEMA_PIN = "northstar.model-attack-06.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


#: Invisible / formatting characters abused in adversarial text.
_INVISIBLE = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero-width no-break space
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi controls
    "\u2066", "\u2067", "\u2068", "\u2069",
}

#: Common homoglyph substitutions (non-Latin lookalikes of Latin).
_HOMOGLYPH_RE = re.compile(
    "[\u0430-\u044f\u0410-\u042f"  # Cyrillic
    "\u03b1-\u03c9\u0391-\u03a9"  # Greek
    "\u0435\u0440\u043e\u0441\u0445\u0456\u0458]"  # extra confusables
)


def _has_mixed_scripts(word: str) -> bool:
    scripts = set()
    for ch in word:
        if "a" <= ch <= "z" or "A" <= ch <= "Z":
            scripts.add("latin")
        elif "\u0400" <= ch <= "\u04ff":
            scripts.add("cyrillic")
        elif "\u0370" <= ch <= "\u03ff":
            scripts.add("greek")
    return len(scripts) > 1


def detect_adversarial_text(text: str) -> Tuple[bool, str]:
    """Return (flagged, reason). Fail-closed on non-str."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    invisible = sum(1 for ch in text if ch in _INVISIBLE)
    if invisible:
        return True, f"{invisible} invisible/bidi control characters"
    if _HOMOGLYPH_RE.search(text):
        # Confirm mixed-script word to cut false positives on pure Greek text.
        for word in text.split():
            if _has_mixed_scripts(word):
                return True, f"homoglyph in word {word[:12]!r}"
        # Pure non-Latin block with Latin-looking intent is still suspect
        # only when mixed; otherwise treat as non-English, not adversarial.
    # Abnormal repetition: same char 6+ times (not typical prose).
    m = re.search(r"(.)\1{5,}", text)
    if m and m.group(1) not in (" ", ".", "-", "_", "="):
        return True, f"abnormal repetition: {m.group(0)[:12]!r}"
    # Excessive combining marks.
    combining = sum(1 for ch in text if unicodedata.combining(ch))
    if combining > max(3, len(text) // 50):
        return True, f"{combining} combining marks"
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing", "unicodedata"}
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
    flagged, _ = detect_adversarial_text("hello\u200bworld")
    assert flagged is True
    flagged, _ = detect_adversarial_text("раyment")  # Cyrillic 'а'
    assert flagged is True
    flagged, _ = detect_adversarial_text("plain english sentence here")
    assert flagged is False
    try:
        detect_adversarial_text(42)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-06 OK")


if __name__ == "__main__":
    main()
