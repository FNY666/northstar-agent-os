"""Output defense 12: factuality checking (mock interface), Simulated.

Interface for claim verification against a knowledge base.  Ships with
an in-memory KB; host replaces ``KnowledgeBase.lookup`` with a real
retriever/verifier.  Fail-closed: unknown claims are NOT verified.

What this IS: claim -> {supported, refuted, unknown} contract.
What this IS NOT: not a real fact-checker; KB is a stub.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional

OUTPUT_DEFENSE_12_VERSION = "output-defense-12.v1"
SCHEMA_PIN = "northstar.output-defense-12.v1"


class FactualityError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ClaimVerdict:
    claim: str
    status: str  # "supported" | "refuted" | "unknown"
    source: str = ""


class KnowledgeBase:
    """Stub KB. Host subclasses or replaces with a real backend."""

    def __init__(self, facts: Optional[Dict[str, str]] = None) -> None:
        # fact text -> source label
        self._facts: Dict[str, str] = dict(facts or {})

    def add(self, fact: str, source: str) -> None:
        if not fact or not source:
            raise FactualityError("fact and source required")
        self._facts[fact.strip().lower()] = source

    def lookup(self, claim: str) -> ClaimVerdict:
        """Exact normalized lookup. Override for fuzzy/retrieval."""
        key = claim.strip().lower()
        if key in self._facts:
            return ClaimVerdict(claim, "supported", self._facts[key])
        # naive refutation marker: "not <known fact>"
        if key.startswith("not ") and key[4:] in self._facts:
            return ClaimVerdict(claim, "refuted", self._facts[key[4:]])
        return ClaimVerdict(claim, "unknown")


class FactualityChecker:
    def __init__(self, kb: KnowledgeBase) -> None:
        if not isinstance(kb, KnowledgeBase):
            raise FactualityError("kb must be KnowledgeBase")
        self._kb = kb
        self._checked: List[ClaimVerdict] = []

    def check(self, claim: str) -> ClaimVerdict:
        if not isinstance(claim, str) or not claim.strip():
            raise FactualityError("claim must be non-empty str")
        verdict = self._kb.lookup(claim)
        self._checked.append(verdict)
        return verdict

    def check_all(self, claims: List[str]) -> List[ClaimVerdict]:
        return [self.check(c) for c in claims]

    @property
    def checked(self) -> List[ClaimVerdict]:
        return list(self._checked)


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
    kb = KnowledgeBase({"water boils at 100c": "physics-textbook"})
    fc = FactualityChecker(kb)
    v = fc.check("Water boils at 100C")
    assert v.status == "supported" and v.source == "physics-textbook"
    v = fc.check("not water boils at 100c")
    assert v.status == "refuted"
    v = fc.check("the moon is cheese")
    assert v.status == "unknown"  # fail-closed: unknown != supported
    assert len(fc.checked) == 3
    try:
        fc.check("   ")
        raise AssertionError("should raise")
    except FactualityError:
        pass
    assert stdlib_only()
    print("output-defense-12 OK: supported/refuted/unknown, stdlib")


if __name__ == "__main__":
    main()
