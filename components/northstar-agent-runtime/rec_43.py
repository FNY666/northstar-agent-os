"""Phone letter combos: one digit per level

Classic telephone-keypad recursion over the digit string.

What this IS: a real recursive keypad combination generator.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_43_VERSION = "rec-phone-combos.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-phone-combos.v1"


class RecError(Exception):
    """Fail-closed."""


KEYS = {
    "2": "abc", "3": "def", "4": "ghi", "5": "jkl",
    "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz",
}


def letter_combos(digits: str):
    """Letter combos for a digit string."""
    if not digits:
        return []
    out = []

    def rec(i, cur):
        if i == len(digits):
            out.append(cur)
            return
        for ch in KEYS.get(digits[i], ""):
            rec(i + 1, cur + ch)

    rec(0, "")
    return out

def test_combos_single():
    assert letter_combos("2") == ["a", "b", "c"]


def test_combos_two():
    assert len(letter_combos("23")) == 9


def test_combos_empty():
    assert letter_combos("") == []


def test_combos_content():
    assert "ad" in letter_combos("23")

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_combos_single()
    test_combos_two()
    test_combos_empty()
    test_combos_content()
    assert stdlib_only()
    print("rec-phone-combos OK")


if __name__ == "__main__":
    main()
