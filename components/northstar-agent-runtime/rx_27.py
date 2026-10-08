"""Whitespace normalizer

What this IS: a normalizer that collapses runs of whitespace.

What this IS NOT: a unicode normalizer -- see unicodedata for that.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_27_VERSION = "rx-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-27.v1"

WS_RE = re.compile(r'\\s+')
def normalize_ws(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return WS_RE.sub(" ", text).strip()

def split_ws(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return [t for t in WS_RE.split(text.strip()) if t]


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
    assert normalize_ws("a   b\tc") == "a b c"
    assert normalize_ws("  x  ") == "x"
    assert split_ws("a  b c") == ["a", "b", "c"]
    assert split_ws("") == []
    assert normalize_ws("") == ""
    assert stdlib_only()
    print("27-ws_norm OK")


if __name__ == "__main__":
    main()
