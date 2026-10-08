"""Output defense 09: toxicity detection (mock classifier), Simulated.

Mock classifier scores toxicity 0..1 from lexical signals.  Host plugs
in a real model via ``classifier_fn``.  Fail-closed: classifier
exception -> max score.

What this IS: thresholded toxicity gate with injectable classifier.
What this IS NOT: not a real toxicity model — lexical mock only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable, List, Optional

OUTPUT_DEFENSE_09_VERSION = "output-defense-09.v1"
SCHEMA_PIN = "northstar.output-defense-09.v1"


class ToxicityError(Exception):
    """Fail-closed."""


TOXIC_MARKERS = [
    "hate", "kill", "stupid", "idiot", "worthless",
    "shut up", "loser", "dumb",
]

INSULT_INTENSIFIERS = ["very", "extremely", "totally"]


@dataclass(frozen=True)
class ToxicityVerdict:
    score: float  # 0..1
    flagged: bool
    markers: List[str]


def mock_classify(text: str) -> float:
    """Lexical mock: base 0.05 + 0.3 per marker, +0.1 per intensifier."""
    low = text.lower()
    score = 0.05
    for m in TOXIC_MARKERS:
        if m in low:
            score += 0.30
    for i in INSULT_INTENSIFIERS:
        if i in low:
            score += 0.10
    return min(1.0, score)


def detect_toxicity(
    text: str,
    *,
    threshold: float = 0.5,
    classifier_fn: Optional[Callable[[str], float]] = None,
) -> ToxicityVerdict:
    """Detect toxicity. Classifier exception -> score 1.0 (fail-closed)."""
    if not isinstance(text, str):
        raise ToxicityError("text must be str")
    if not 0.0 <= threshold <= 1.0:
        raise ToxicityError("threshold must be in [0,1]")
    clf = classifier_fn or mock_classify
    try:
        score = float(clf(text))
    except Exception:
        score = 1.0
    score = max(0.0, min(1.0, score))
    low = text.lower()
    markers = [m for m in TOXIC_MARKERS if m in low]
    return ToxicityVerdict(score=score, flagged=score >= threshold, markers=markers)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    v = detect_toxicity("have a nice day")
    assert v.flagged is False and v.score < 0.5
    v = detect_toxicity("you are a stupid idiot")
    assert v.flagged is True and "stupid" in v.markers
    def bad(text):
        raise RuntimeError("model down")
    v = detect_toxicity("hello", classifier_fn=bad)
    assert v.score == 1.0 and v.flagged is True
    try:
        detect_toxicity(123)  # type: ignore
        raise AssertionError("should raise")
    except ToxicityError:
        pass
    assert stdlib_only()
    print("output-defense-09 OK: mock classifier, fail-closed, stdlib")


if __name__ == "__main__":
    main()
