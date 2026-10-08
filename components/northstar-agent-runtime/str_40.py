"""Count and say: iterative run description.

Builds term n+1 by reading runs of term n.

What this IS: a real iterative implementation.
What this IS NOT: memoized sequence generation.
"""

from __future__ import annotations

import ast

#: Module version.
STR_40_VERSION = "str-count-say.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-count-and-say.v1"


class StrError(Exception):
    """Fail-closed."""


def count_and_say(n: int) -> str:
    """n-th term of the count-and-say sequence (1-indexed)."""
    if n <= 0:
        raise StrError("n must be positive")
    s = "1"
    for _ in range(n - 1):
        out = []
        i = 0
        while i < len(s):
            j = i
            while j < len(s) and s[j] == s[i]:
                j += 1
            out.append(str(j - i) + s[i])
            i = j
        s = "".join(out)
    return s


def test_cs_one():
    assert count_and_say(1) == "1"


def test_cs_four():
    assert count_and_say(4) == "1211"


def test_cs_five():
    assert count_and_say(5) == "111221"


def test_cs_bad():
    try:
        count_and_say(0)
    except StrError:
        return
    raise AssertionError("expected StrError")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_cs_one()
    test_cs_four()
    test_cs_five()
    test_cs_bad()
    assert stdlib_only()
    print("str-40 OK: count-say")


if __name__ == "__main__":
    main()
