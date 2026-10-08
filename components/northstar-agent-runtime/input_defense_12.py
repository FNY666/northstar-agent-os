"""Confusable Detection: finds known lookalike characters in input, Simulated.

Scans input for non-ASCII characters that visually mimic Latin letters
(the same set that module 11 normalizes) and reports their positions.
Detection only: nothing is rewritten. A spoofed "раураl" is flagged as
suspicious with per-character hit locations; clean ASCII passes through
as non-suspicious. Detection answers "is it spoofed?", normalization
(module 11) answers "what does it really say?".

What this IS: A scanner that reports (char, index) hits for known lookalikes.

What this IS NOT:
* A normalizer: it never rewrites the input (see module 11).
* An exhaustive confusables oracle: only the pinned non-ASCII set is checked.
"""

from __future__ import annotations

import ast
from typing import FrozenSet, List, Tuple

#: Module version.
INPUT_DEFENSE_12_VERSION = "input-defense-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-12.v1"


class InputDefense12Error(Exception):
    """Fail-closed."""


#: Non-ASCII confusable characters (mirrors the keys of module 11's
#: CONFUSABLES table, duplicated here so this module stays standalone
#: with no cross-module import).
CONFUSABLE_SET: FrozenSet[str] = frozenset({
    # Cyrillic lowercase lookalikes of Latin.
    "а", "е", "о", "р", "с", "х", "у", "і", "ј", "ѕ", "һ", "ԝ",
    # Cyrillic uppercase lookalikes of Latin.
    "А", "В", "Е", "К", "М", "Н", "О", "Р", "С", "Т", "Х",
    # Greek lookalikes of Latin.
    "α", "ε", "ο", "ρ", "υ", "ν", "κ", "μ",
})


def find_confusables(text: str) -> List[Tuple[str, int]]:
    """Return ``[(char, index), ...]`` for every confusable character.

    Fail-closed: non-str input raises :class:`InputDefense12Error`.
    """
    if not isinstance(text, str):
        raise InputDefense12Error(
            "find_confusables requires str, got %s" % type(text).__name__
        )
    return [(ch, i) for i, ch in enumerate(text) if ch in CONFUSABLE_SET]


def check(text: str) -> Tuple[bool, List[Tuple[str, int]]]:
    """Return ``(suspicious, hits)``; suspicious when any hit is found.

    Fail-closed: non-str input raises :class:`InputDefense12Error`.
    """
    hits = find_confusables(text)
    return (len(hits) > 0, hits)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}  # only modules you actually import
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
    # Classic mixed-script spoof: Cyrillic р а у р а + Latin l.
    hits = find_confusables("раураl")
    assert hits == [("р", 0), ("а", 1), ("у", 2), ("р", 3), ("а", 4)], hits
    suspicious, found = check("раураl")
    assert suspicious is True and found == hits
    # Greek lookalikes flagged too.
    assert check("αεор")[0] is True
    # Clean ASCII: no hits, not suspicious.
    assert find_confusables("paypal") == []
    assert check("paypal") == (False, [])
    assert check("") == (False, [])
    # Fail-closed on non-str.
    for bad in (None, 123, b"paypal", ["paypal"]):
        try:
            check(bad)  # type: ignore[arg-type]
        except InputDefense12Error:
            pass
        else:
            raise AssertionError("check(%r) did not raise" % (bad,))
        try:
            find_confusables(bad)  # type: ignore[arg-type]
        except InputDefense12Error:
            pass
        else:
            raise AssertionError("find_confusables(%r) did not raise" % (bad,))
    assert stdlib_only()
    print("input-defense-12 OK")


if __name__ == "__main__":
    main()
