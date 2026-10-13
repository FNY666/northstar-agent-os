"""Model attack 13: fingerprint evasion detection, Simulated.

Detects attempts to launder AI-generated text so model fingerprinting
fails: style-transfer requests ("write like Hemingway"), "make it
undetectable" requests, AI-detector evasion ("bypass the AI checker"),
and repeated laundering loops.

What this IS: input-side origin-laundering detection.
What this IS NOT: not a fingerprinting scheme; does not identify
which model produced the text.
"""

from __future__ import annotations

import ast
import re
from typing import List, Tuple

MODEL_ATTACK_13_VERSION = "model-attack-13.v1"

SCHEMA_PIN = "northstar.model-attack-13.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


_EVASION_PATTERNS = [
    r"write\s+(like|in\s+the\s+style\s+of)\s+",
    r"make\s+it\s+(sound\s+)?(human|undetectable|natural)",
    r"bypass\s+(the\s+)?(ai|gpt)\s+(detector|checker|detection)",
    r"evade\s+(ai\s+)?detection",
    r"fool\s+(the\s+)?(ai\s+)?detector",
    r"humanize",
    r"remove\s+(ai|gpt)\s+(traces?|fingerprints?|markers?)",
]

#: Laundering requests this many times -> flag.
LOOP_THRESHOLD = 3


def detect_fingerprint_evasion(text: str) -> Tuple[bool, str]:
    """Single-input check. Returns (flagged, reason)."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    lowered = text.lower()
    for pat in _EVASION_PATTERNS:
        m = re.search(pat, lowered)
        if m:
            return True, f"fingerprint-evasion pattern: {m.group(0)[:30]!r}"
    return False, "clean"


def detect_laundering_loop(texts: List[str]) -> Tuple[bool, str]:
    """Detect repeated laundering of similar content."""
    if not isinstance(texts, list) or not all(
        isinstance(t, str) for t in texts
    ):
        raise ModelAttackError("texts must be a list of str")
    hits = [t for t in texts if detect_fingerprint_evasion(t)[0]]
    if len(hits) >= LOOP_THRESHOLD:
        return True, f"laundering loop: {len(hits)} evasion requests"
    return False, "clean"


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
    flagged, _ = detect_fingerprint_evasion("Write like Hemingway, please")
    assert flagged is True
    flagged, _ = detect_fingerprint_evasion("Bypass the AI detector for this essay")
    assert flagged is True
    flagged, _ = detect_fingerprint_evasion("Draft a polite email to my boss")
    assert flagged is False
    flagged, _ = detect_laundering_loop(
        ["humanize this", "make it sound human", "humanize it again", "ok"]
    )
    assert flagged is True
    try:
        detect_fingerprint_evasion(9)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-13 OK")


if __name__ == "__main__":
    main()
