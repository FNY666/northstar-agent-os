"""Float literal matcher

What this IS: a matcher for decimal float literals.

What this IS NOT: a numeric tower -- complex and fractions are not matched.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_33_VERSION = "rx-33.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-33.v1"

FLOAT_RE = re.compile(r'[+-]?(?:\\d+\\.\\d*|\\.\\d+|\\d+)(?:[eE][+-]?\\d+)?')
def is_float(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return FLOAT_RE.fullmatch(text) is not None

def find_floats(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return FLOAT_RE.findall(text)


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
    assert is_float("3.14")
    assert is_float("-0.5e10")
    assert is_float("42")
    assert not is_float("abc")
    assert not is_float("1.2.3")
    assert find_floats("x 1.5 y -2") == ["1.5", "-2"]
    assert stdlib_only()
    print("33-float_num OK")


if __name__ == "__main__":
    main()
