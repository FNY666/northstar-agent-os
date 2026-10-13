"""Model attack 12: watermark removal detection, Simulated.

Detects inputs attempting to strip AI-output watermarks: repeated
paraphrase/reword requests on the same content, synonym-substitution
bursts, translation round-trips (en->fr->en), and explicit "remove
watermark" requests.

What this IS: input-side watermark-stripping detection.
What this IS NOT: not a watermarking scheme itself; does not verify
whether the content was watermarked.
"""

from __future__ import annotations

import ast
import re
from typing import List, Tuple

MODEL_ATTACK_12_VERSION = "model-attack-12.v1"

SCHEMA_PIN = "northstar.model-attack-12.v1"


class ModelAttackError(Exception):
    """Fail-closed: bad inputs raise."""


_REWORD_PATTERNS = [
    r"\bparaphrase\b",
    r"\breword\b",
    r"\brewrite\b.{0,20}\b(different|own)\b.{0,20}\bwords?\b",
    r"\bsynonym",
    r"remove\s+(the\s+)?watermark",
    r"make\s+it\s+sound\s+human",
    r"translate\s+to\s+\w+\s+and\s+back",
]

#: Repeated reword requests on similar content this many times -> flag.
LOOP_THRESHOLD = 3


def detect_watermark_removal(text: str) -> Tuple[bool, str]:
    """Single-input check. Returns (flagged, reason)."""
    if not isinstance(text, str):
        raise ModelAttackError("text must be str")
    lowered = text.lower()
    for pat in _REWORD_PATTERNS:
        m = re.search(pat, lowered)
        if m:
            return True, f"watermark-stripping pattern: {m.group(0)[:30]!r}"
    return False, "clean"


def detect_reword_loop(texts: List[str]) -> Tuple[bool, str]:
    """Detect repeated rewording of similar content."""
    if not isinstance(texts, list) or not all(
        isinstance(t, str) for t in texts
    ):
        raise ModelAttackError("texts must be a list of str")
    hits = [t for t in texts if detect_watermark_removal(t)[0]]
    if len(hits) >= LOOP_THRESHOLD:
        return True, f"reword loop: {len(hits)} stripping requests"
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
    flagged, _ = detect_watermark_removal("Paraphrase this essay for me")
    assert flagged is True
    flagged, _ = detect_watermark_removal("Remove the watermark from this text")
    assert flagged is True
    flagged, _ = detect_watermark_removal("Explain photosynthesis simply")
    assert flagged is False
    flagged, _ = detect_reword_loop(
        ["Paraphrase this", "Reword it again", "Paraphrase once more", "hi"]
    )
    assert flagged is True
    try:
        detect_watermark_removal(7)  # type: ignore
        raise AssertionError("should raise")
    except ModelAttackError:
        pass
    assert stdlib_only()
    print("model-attack-12 OK")


if __name__ == "__main__":
    main()
