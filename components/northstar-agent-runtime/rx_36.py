"""Roman numeral matcher

What this IS: a matcher for canonical Roman numeral shapes.

What this IS NOT: a Roman-to-int converter for non-canonical forms.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_36_VERSION = "rx-36.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-36.v1"

ROMAN_RE = re.compile(r'M{0,3}(?:CM|CD|D?C{0,3})(?:XC|XL|L?X{0,3})(?:IX|IV|V?I{0,3})')
def is_roman(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return bool(text) and ROMAN_RE.fullmatch(text) is not None

def find_romans(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return [m for m in ROMAN_RE.findall(text) if m]


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
    assert is_roman("XIV")
    assert is_roman("MMXXVI")
    assert not is_roman("IIII")
    assert not is_roman("")
    assert "XIV" in find_romans("chapter XIV")
    assert stdlib_only()
    print("36-roman OK")


if __name__ == "__main__":
    main()
