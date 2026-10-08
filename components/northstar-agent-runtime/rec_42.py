"""Parenthesis generation: open-then-close recursion

Builds all balanced strings: never close more than opened.

What this IS: a real recursive balanced-parens generator, fail-closed on negatives.
What this IS NOT: a substitute for iterative host code; the host picks the algorithm.
"""

from __future__ import annotations

import ast

#: Module version.
REC_42_VERSION = "rec-gen-parens.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rec-gen-parens.v1"


class RecError(Exception):
    """Fail-closed."""


def gen_parens(n: int):
    """All balanced paren strings of n pairs."""
    if n < 0:
        raise RecError("gen_parens needs n >= 0")
    out = []

    def rec(s, opened, closed):
        if len(s) == 2 * n:
            out.append(s)
            return
        if opened < n:
            rec(s + "(", opened + 1, closed)
        if closed < opened:
            rec(s + ")", opened, closed + 1)

    rec("", 0, 0)
    return out

def test_parens_zero():
    assert gen_parens(0) == [""]


def test_parens_one():
    assert gen_parens(1) == ["()"]


def test_parens_three():
    assert len(gen_parens(3)) == 5


def test_parens_negative_raises():
    try:
        gen_parens(-1)
    except RecError:
        return
    raise AssertionError("expected RecError")

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
    test_parens_zero()
    test_parens_one()
    test_parens_three()
    test_parens_negative_raises()
    assert stdlib_only()
    print("rec-gen-parens OK")


if __name__ == "__main__":
    main()
