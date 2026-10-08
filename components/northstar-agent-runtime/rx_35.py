"""Scientific notation matcher

What this IS: a strict 1.23e-4 style scientific notation matcher.

What this IS NOT: a general float matcher -- see rx-33.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_35_VERSION = "rx-35.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-35.v1"

SCI_RE = re.compile(r'[+-]?\\d+(?:\\.\\d+)?[eE][+-]?\\d+')
def is_sci(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return SCI_RE.fullmatch(text) is not None

def find_scis(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return SCI_RE.findall(text)


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
    assert is_sci("1.23e-4")
    assert is_sci("-2E10")
    assert not is_sci("1.23")
    assert not is_sci("e10")
    assert find_scis("val 6.02e23 here") == ["6.02e23"]
    assert stdlib_only()
    print("35-sci OK")


if __name__ == "__main__":
    main()
