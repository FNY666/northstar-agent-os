"""Markdown link extractor

What this IS: an extractor for [text](url) style markdown links.

What this IS NOT: a reference-style link parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_20_VERSION = "rx-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-20.v1"

MD_LINK_RE = re.compile(r'\\[([^\\[\\]]+)\\]\\(([^)\\s]+)(?:\\s+\"[^\"]*\")?\\)')
def find_md_links(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return MD_LINK_RE.findall(text)


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
    assert find_md_links("[a](https://a.io)") == [("a", "https://a.io")]
    assert find_md_links('[t](http://x.y "title")') == [("t", "http://x.y")]
    assert find_md_links("no link") == []
    assert find_md_links("[a](b) and [c](d)") == [("a", "b"), ("c", "d")]
    assert ("t", "http://x.y") in find_md_links('[t](http://x.y "title")')
    assert stdlib_only()
    print("20-md_link OK")


if __name__ == "__main__":
    main()
