"""Output defense 11: hallucination detection (mock), Simulated.

Flags unverified claims: sentences containing strong assertive markers
("definitely", precise numbers, named entities) that are NOT present in
the provided evidence set.  Mock — host supplies evidence and can
inject a real NLI scorer.

What this IS: claim-vs-evidence coverage check.
What this IS NOT: not semantic entailment; lexical coverage only.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import FrozenSet, List

OUTPUT_DEFENSE_11_VERSION = "output-defense-11.v1"
SCHEMA_PIN = "northstar.output-defense-11.v1"


class HallucinationError(Exception):
    """Fail-closed."""


ASSERTIVE_MARKERS = [
    re.compile(r"(?i)\bdefinitely\b"),
    re.compile(r"(?i)\bcertainly\b"),
    re.compile(r"\b\d{4,}\b"),  # large precise numbers
    re.compile(r"(?i)\bstudies show\b"),
]


@dataclass(frozen=True)
class HallucinationVerdict:
    flagged: bool
    unverified_claims: List[str]


def _sentences(text: str) -> List[str]:
    return [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]


def detect_hallucination(
    text: str, evidence: FrozenSet[str]
) -> HallucinationVerdict:
    """Flag assertive sentences with no token overlap vs evidence."""
    if not isinstance(text, str):
        raise HallucinationError("text must be str")
    if not isinstance(evidence, (set, frozenset)):
        raise HallucinationError("evidence must be a set")
    ev_tokens = set()
    for e in evidence:
        ev_tokens |= set(re.findall(r"\w+", e.lower()))
    unverified: List[str] = []
    for sent in _sentences(text):
        if not any(p.search(sent) for p in ASSERTIVE_MARKERS):
            continue
        sent_tokens = set(re.findall(r"\w+", sent.lower()))
        content = {t for t in sent_tokens if len(t) > 3}
        if content and not (content & ev_tokens):
            unverified.append(sent)
    return HallucinationVerdict(
        flagged=bool(unverified), unverified_claims=unverified
    )


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
    ev = frozenset({"The Eiffel Tower is in Paris."})
    v = detect_hallucination("The Eiffel Tower is in Paris.", ev)
    assert v.flagged is False
    v = detect_hallucination(
        "Studies show the moon is definitely made of cheese 12345.", ev
    )
    assert v.flagged is True and len(v.unverified_claims) == 1
    v = detect_hallucination("Maybe it rains tomorrow.", ev)
    assert v.flagged is False  # hedged, no assertive marker
    try:
        detect_hallucination("x", "not-a-set")  # type: ignore
        raise AssertionError("should raise")
    except HallucinationError:
        pass
    assert stdlib_only()
    print("output-defense-11 OK: claim coverage, fail-closed, stdlib")


if __name__ == "__main__":
    main()
