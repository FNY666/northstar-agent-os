"""Hex color matcher

What this IS: a #RGB / #RRGGBB hex color matcher.

What this IS NOT: a CSS color parser -- named colors are not matched.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_08_VERSION = "rx-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-08.v1"

HEX_COLOR_RE = re.compile(r'#[0-9A-Fa-f]{3}(?:[0-9A-Fa-f]{3})?')
def is_hex_color(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return HEX_COLOR_RE.fullmatch(text) is not None

def find_colors(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return HEX_COLOR_RE.findall(text)


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
    assert is_hex_color("#fff")
    assert is_hex_color("#1a2B3c")
    assert not is_hex_color("#ffff")
    assert not is_hex_color("red")
    assert find_colors("fg #fff bg #000000") == ["#fff", "#000000"]
    assert stdlib_only()
    print("08-hex_color OK")


if __name__ == "__main__":
    main()
