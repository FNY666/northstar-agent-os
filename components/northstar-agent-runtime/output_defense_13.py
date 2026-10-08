"""Output defense 13: citation verification, Simulated.

Extracts citation markers ([1], (Smith 2020), [Smith2020]) and verifies
each has a matching entry in the provided reference list.  Unmatched
citations fail the check (fabricated references).

What this IS: marker -> reference-list consistency check.
What this IS NOT: not a bibliographic validator; cannot check that a
real paper says what is claimed.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import List, Set

OUTPUT_DEFENSE_13_VERSION = "output-defense-13.v1"
SCHEMA_PIN = "northstar.output-defense-13.v1"


class CitationError(Exception):
    """Fail-closed."""


NUMERIC = re.compile(r"\[(\d+)\]")
AUTHOR_YEAR = re.compile(r"\(([A-Z][A-Za-z\-]+)[^()]*\b(19|20)\d{2}\)")
BRACKET_KEY = re.compile(r"\[([A-Za-z][A-Za-z0-9\-]{2,})\]")


@dataclass(frozen=True)
class CitationVerdict:
    verified: bool
    citations_found: List[str]
    unmatched: List[str]


def extract_citations(text: str) -> List[str]:
    """Extract normalized citation keys from text."""
    if not isinstance(text, str):
        raise CitationError("text must be str")
    keys: List[str] = []
    keys += [f"[{m}]" for m in NUMERIC.findall(text)]
    keys += [f"[{m}]" for m in BRACKET_KEY.findall(text) if not m.isdigit()]
    for author, _cent in AUTHOR_YEAR.findall(text):
        keys.append(f"({author})")
    # dedupe, preserve order
    seen: Set[str] = set()
    out: List[str] = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _ref_keys(references: List[str]) -> Set[str]:
    keys: Set[str] = set()
    for ref in references:
        for m in NUMERIC.findall(ref):
            keys.add(f"[{m}]")
        for m in BRACKET_KEY.findall(ref):
            if not m.isdigit():
                keys.add(f"[{m}]")
        for author, _c in AUTHOR_YEAR.findall(ref):
            keys.add(f"({author})")
    return keys


def verify_citations(
    text: str, references: List[str]
) -> CitationVerdict:
    """Every citation marker must match a reference entry."""
    if not isinstance(references, list):
        raise CitationError("references must be a list")
    found = extract_citations(text)
    refkeys = _ref_keys(references)
    unmatched = [c for c in found if c not in refkeys]
    return CitationVerdict(
        verified=not unmatched, citations_found=found, unmatched=unmatched
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
    refs = ["[1] Smith, J. (2020). On things.", "[2] Doe, A. (2021). More."]
    v = verify_citations("As shown [1] and [2].", refs)
    assert v.verified is True and v.unmatched == []
    v = verify_citations("As shown [1] and [3].", refs)
    assert v.verified is False and "[3]" in v.unmatched
    v = verify_citations("No citations here.", refs)
    assert v.verified is True and v.citations_found == []
    try:
        verify_citations("x [1]", "not-a-list")  # type: ignore
        raise AssertionError("should raise")
    except CitationError:
        pass
    assert stdlib_only()
    print("output-defense-13 OK: citation matching, fail-closed, stdlib")


if __name__ == "__main__":
    main()
