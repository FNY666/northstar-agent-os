"""Mention extractor

What this IS: an extractor for @username mentions.

What this IS NOT: an account resolver.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_22_VERSION = "rx-22.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-22.v1"

MENTION_RE = re.compile(r'(?<![A-Za-z0-9_@])@([A-Za-z0-9_]{1,32})')
def find_mentions(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return MENTION_RE.findall(text)


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
    assert find_mentions("hi @alice") == ["alice"]
    assert find_mentions("@a and @b_c") == ["a", "b_c"]
    assert find_mentions("email a@b.com") == []
    assert find_mentions("no mentions") == []
    assert find_mentions("@@x") == ["x"]
    assert stdlib_only()
    print("22-mention OK")


if __name__ == "__main__":
    main()
