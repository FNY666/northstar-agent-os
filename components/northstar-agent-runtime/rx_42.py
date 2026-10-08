"""Query string parser

What this IS: a parser for a=b&c=d style query strings.

What this IS NOT: a URL decoder -- percent-encoding is not decoded.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_42_VERSION = "rx-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-42.v1"

QUERY_RE = re.compile(r'([^&=]+)=([^&]*)')
def parse_query(text: str) -> dict:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return dict(QUERY_RE.findall(text))


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
    assert parse_query("a=1&b=2") == {"a": "1", "b": "2"}
    assert parse_query("x=") == {"x": ""}
    assert parse_query("") == {}
    assert parse_query("a=1&a=2")["a"] == "2"
    assert parse_query("k=v%20x") == {"k": "v%20x"}
    assert stdlib_only()
    print("42-query_str OK")


if __name__ == "__main__":
    main()
