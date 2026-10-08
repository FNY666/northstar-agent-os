"""Quoted-string extractor

What this IS: an extractor for double-quoted string literals (no escapes).

What this IS NOT: an escape-aware string parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_29_VERSION = "rx-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-29.v1"

QUOTED_RE = re.compile(r'\"([^\"]*)\"')
def find_quoted(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return QUOTED_RE.findall(text)


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
    assert find_quoted('say "hi" now') == ["hi"]
    assert find_quoted('"a" and "b"') == ["a", "b"]
    assert find_quoted("no quotes") == []
    assert find_quoted('""') == [""]
    assert find_quoted("it's") == []
    assert stdlib_only()
    print("29-quoted_str OK")


if __name__ == "__main__":
    main()
