"""Markdown header matcher

What this IS: a matcher for ATX-style markdown headers (# .. ######).

What this IS NOT: a full markdown parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_19_VERSION = "rx-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-19.v1"

MD_HEADER_RE = re.compile(r'^(#{1,6})\\s+(.+?)\\s*#*\\s*$')
def parse_md_header(line: str):
    if not isinstance(line, str):
        raise TypeError("line must be str")
    m = MD_HEADER_RE.match(line)
    if not m:
        return None
    return (len(m.group(1)), m.group(2))

def is_md_header(line: str) -> bool:
    return parse_md_header(line) is not None


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
    assert parse_md_header("# Title") == (1, "Title")
    assert parse_md_header("### Deep ###") == (3, "Deep")
    assert not is_md_header("####### too many")
    assert not is_md_header("no header")
    assert is_md_header("## Two")
    assert stdlib_only()
    print("19-md_header OK")


if __name__ == "__main__":
    main()
