"""Output defense 17: refusal detection, Simulated.

Detects refusal patterns ("I can't", "I'm unable", ...) in model output
so the orchestrator can distinguish a genuine refusal from an empty or
evasive non-answer.  Also flags *partial* refusals (refuse then comply).

What this IS: refusal vs non-refusal classification for routing.
What this IS NOT: not a policy judge; does not decide whether the
refusal was correct.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import List, Pattern

OUTPUT_DEFENSE_17_VERSION = "output-defense-17.v1"
SCHEMA_PIN = "northstar.output-defense-17.v1"


class RefusalError(Exception):
    """Fail-closed."""


REFUSAL_PATTERNS: List[Pattern] = [
    re.compile(r"(?i)\bi (can't|cannot|won't) (help|do|provide|assist)"),
    re.compile(r"(?i)\bi'?m unable to\b"),
    re.compile(r"(?i)\bi'?m not able to\b"),
    re.compile(r"(?i)\bas an ai\b.{0,40}\b(can'?t|cannot)\b"),
    re.compile(r"(?i)\bagainst (my|the) (policy|guidelines)\b"),
    re.compile(r"(?i)\bi must decline\b"),
]


@dataclass(frozen=True)
class RefusalVerdict:
    is_refusal: bool
    is_partial: bool  # refusal phrasing + substantive content after
    matched: List[str]


def detect_refusal(text: str) -> RefusalVerdict:
    """Classify output as refusal / partial refusal / not refusal."""
    if not isinstance(text, str):
        raise RefusalError("text must be str")
    matched = [p.pattern for p in REFUSAL_PATTERNS if p.search(text)]
    if not matched:
        return RefusalVerdict(False, False, [])
    # Partial: refusal marker in first 25% but long substantive tail.
    first_hit = min(text.lower().find("can't"), text.lower().find("unable"))
    first_hit = first_hit if first_hit >= 0 else 0
    tail = text[first_hit + 20:]
    is_partial = len(tail.strip()) > 200
    return RefusalVerdict(True, is_partial, matched)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    v = detect_refusal("I can't help with that request.")
    assert v.is_refusal is True and v.is_partial is False
    v = detect_refusal("Here's the weather: sunny, 22C.")
    assert v.is_refusal is False
    v = detect_refusal("I can't provide that. " + ("However, here is a long discussion of unrelated allowed content. " * 10))
    assert v.is_refusal is True and v.is_partial is True
    try:
        detect_refusal(42)  # type: ignore
        raise AssertionError("should raise")
    except RefusalError:
        pass
    assert stdlib_only()
    print("output-defense-17 OK: refusal detection, fail-closed, stdlib")


if __name__ == "__main__":
    main()
