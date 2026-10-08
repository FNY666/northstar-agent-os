"""String reversal: last char + reverse(rest)

Builds the reversed string one character per call.

What this IS: a real recursive string reversal.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_21_VERSION = "rec-str-reverse.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-str-reverse.v1"


class RecError(Exception):
    """Fail-closed."""


def revstr(s: str) -> str:
    """Reversed s."""
    if len(s) <= 1:
        return s
    return s[-1] + revstr(s[:-1])

def test_revstr_basic():
    assert revstr("hello") == "olleh"


def test_revstr_empty():
    assert revstr("") == ""


def test_revstr_single():
    assert revstr("a") == "a"

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
    test_revstr_basic()
    test_revstr_empty()
    test_revstr_single()
    assert stdlib_only()
    print("rec-str-reverse OK")


if __name__ == "__main__":
    main()
