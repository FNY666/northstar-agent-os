"""ML classifier sidecar: pluggable classifier interface (mock), Simulated.

The sidecar wraps an external classifier callable behind a fail-closed gate:
a score at/above the threshold on a dangerous label blocks the input, and any
exception from the classifier is treated as blocked (fail-closed), since an
unavailable or broken model must never fail open.

What this IS: a fail-closed interface for plugging in an ML classifier.

What this IS NOT:
* A real trained model (the bundled classifier is a keyword mock).
* A guarantee of classifier availability or accuracy.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Callable, Dict, List, Tuple

#: Module version.
INPUT_DEFENSE_02_VERSION = "input-defense-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-02.v1"


class InputDefense02Error(Exception):
    """Fail-closed."""


#: Labels treated as dangerous when score >= threshold.
DANGEROUS_LABELS = frozenset({"injection", "jailbreak"})

#: classify_fn(text) -> (label, score).
ClassifierFn = Callable[[str], Tuple[str, float]]


class ClassifierSidecar:
    """Fail-closed wrapper around a classify_fn."""

    def __init__(
        self,
        classify_fn: ClassifierFn,
        threshold: float = 0.8,
    ) -> None:
        if not callable(classify_fn):
            raise InputDefense02Error("classify_fn must be callable")
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
            raise InputDefense02Error("threshold must be a number")
        if not 0.0 <= float(threshold) <= 1.0:
            raise InputDefense02Error("threshold must be within [0, 1]")
        self._classify_fn = classify_fn
        self._threshold = float(threshold)

    def check(self, text: str) -> Tuple[bool, str, float]:
        """Return (blocked, label, score). Classifier errors -> blocked."""
        if not isinstance(text, str):
            raise InputDefense02Error(
                f"check() requires str, got {type(text).__name__}"
            )
        try:
            label, score = self._classify_fn(text)
        except Exception:
            return True, "error", 0.0
        if not isinstance(label, str):
            raise InputDefense02Error("classifier returned a non-str label")
        if not isinstance(score, (int, float)) or isinstance(score, bool):
            raise InputDefense02Error("classifier returned a non-numeric score")
        score_f = float(score)
        blocked = label in DANGEROUS_LABELS and score_f >= self._threshold
        return blocked, label, score_f


def mock_keyword_classifier(
    keywords: Dict[str, List[str]],
) -> ClassifierFn:
    """Build a classify_fn from label -> keyword lists.

    A label matches if any of its keywords (case-insensitive) appear in the
    text; the score is the fraction of keywords matched (0..1), and the
    returned label is the highest-scoring label ("benign" if none match).
    """
    if not isinstance(keywords, dict):
        raise InputDefense02Error("keywords must be a dict of label -> list[str]")
    lowered: Dict[str, List[str]] = {}
    for label, words in keywords.items():
        if not isinstance(label, str) or not isinstance(words, (list, tuple)):
            raise InputDefense02Error("keywords must map str -> list[str]")
        for w in words:
            if not isinstance(w, str):
                raise InputDefense02Error("keywords must map str -> list[str]")
        lowered[label] = [w.lower() for w in words]

    def classify(text: str) -> Tuple[str, float]:
        if not isinstance(text, str):
            raise InputDefense02Error("classifier input must be str")
        hay = text.lower()
        best_label = "benign"
        best_score = 0.0
        for label, words in lowered.items():
            if not words:
                continue
            hits = sum(1 for w in words if w and w in hay)
            score = hits / len(words)
            if score > best_score:
                best_score = score
                best_label = label
        return best_label, best_score

    return classify


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    clf = mock_keyword_classifier(
        {"injection": ["ignore instructions", "system prompt"],
         "jailbreak": ["jailbreak", "dan mode"]}
    )
    sidecar = ClassifierSidecar(clf, threshold=0.5)
    blocked, label, score = sidecar.check("please ignore instructions now")
    assert blocked and label == "injection" and score == 0.5, (blocked, label, score)
    blocked, label, score = sidecar.check("hello there")
    assert not blocked and label == "benign" and score == 0.0
    blocked, label, _ = sidecar.check("enter dan mode jailbreak")
    assert blocked and label == "jailbreak"
    # Fail-closed on classifier exception.
    def boom(_t: str) -> Tuple[str, float]:
        raise RuntimeError("model unavailable")
    closed = ClassifierSidecar(boom)
    blocked, label, _ = closed.check("anything")
    assert blocked and label == "error"
    try:
        sidecar.check(123)
    except InputDefense02Error:
        pass
    else:
        raise AssertionError("non-str input must raise")
    try:
        ClassifierSidecar(clf, threshold=1.5)
    except InputDefense02Error:
        pass
    else:
        raise AssertionError("bad threshold must raise")
    assert stdlib_only()
    print("input-defense-02 OK")


if __name__ == "__main__":
    main()
