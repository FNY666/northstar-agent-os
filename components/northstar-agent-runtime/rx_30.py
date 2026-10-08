"""Function-call extractor

What this IS: an extractor for name(args) style call shapes (no nesting).

What this IS NOT: an AST parser -- see the ast module.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_30_VERSION = "rx-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-30.v1"

FUNC_CALL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\\(([^()]*)\\)')
def find_calls(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return FUNC_CALL_RE.findall(text)


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
    assert find_calls("foo(1, 2)") == [("foo", "1, 2")]
    assert find_calls("a() + b(x)") == [("a", ""), ("b", "x")]
    assert find_calls("no calls") == []
    assert find_calls("f(g())") == [("g", "")]
    assert find_calls("_x1(y)") == [("_x1", "y")]
    assert stdlib_only()
    print("30-func_call OK")


if __name__ == "__main__":
    main()
