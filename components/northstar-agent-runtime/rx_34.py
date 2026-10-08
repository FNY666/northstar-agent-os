"""Thousands-separated integer matcher

What this IS: a matcher for 1,000 style grouped integers.

What this IS NOT: a locale-aware number parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_34_VERSION = "rx-34.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-34.v1"

INT_SEP_RE = re.compile(r'[+-]?(?:\\d{1,3}(?:,\\d{3})+|\\d+)')
def parse_int_sep(text: str):
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if INT_SEP_RE.fullmatch(text) is None:
        return None
    return int(text.replace(",", ""))


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
    assert parse_int_sep("1,000") == 1000
    assert parse_int_sep("-12,345,678") == -12345678
    assert parse_int_sep("42") == 42
    assert parse_int_sep("1,00") is None
    assert parse_int_sep("abc") is None
    assert stdlib_only()
    print("34-int_sep OK")


if __name__ == "__main__":
    main()
