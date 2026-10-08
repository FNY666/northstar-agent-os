"""Parenthesis balance checker

What this IS: a regex-assisted balance pre-check combined with a stack scan.

What this IS NOT: a full expression parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_25_VERSION = "rx-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-25.v1"

PAREN_RE = re.compile(r'[()]')
def is_balanced(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    depth = 0
    for ch in PAREN_RE.findall(text):
        if ch == "(":
            depth += 1
        else:
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    assert is_balanced("(a + (b))")
    assert is_balanced("")
    assert not is_balanced("(()")
    assert not is_balanced("())(")
    assert is_balanced("no parens")
    assert stdlib_only()
    print("25-paren_bal OK")


if __name__ == "__main__":
    main()
