"""Simple CSV splitter

What this IS: a splitter for delimiter-separated values without quoted fields.

What this IS NOT: a full CSV parser -- use the csv module for quoted fields.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_28_VERSION = "rx-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-28.v1"

CSV_SPLIT_RE = re.compile(r'\\s*,\\s*')
def split_csv_simple(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return CSV_SPLIT_RE.split(text)

def is_csv_row(text: str, ncols: int) -> bool:
    return len(split_csv_simple(text)) == ncols


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
    assert split_csv_simple("a,b,c") == ["a", "b", "c"]
    assert split_csv_simple("a, b ,c") == ["a", "b", "c"]
    assert is_csv_row("a,b", 2)
    assert not is_csv_row("a,b", 3)
    assert split_csv_simple("single") == ["single"]
    assert stdlib_only()
    print("28-csv_simple OK")


if __name__ == "__main__":
    main()
