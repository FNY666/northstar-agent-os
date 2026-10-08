"""Repeated-character detector

What this IS: a detector for runs of the same character (3+).

What this IS NOT: a full spam classifier.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_24_VERSION = "rx-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-24.v1"

REPEAT_RE = re.compile(r'(.)\\1{2,}')
def has_repeat(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return REPEAT_RE.search(text) is not None

def find_repeats(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return REPEAT_RE.findall(text)


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
    assert has_repeat("sooo good")
    assert has_repeat("aaa")
    assert not has_repeat("aabb")
    assert not has_repeat("ok")
    assert find_repeats("aaabbb") == ["a", "b"]
    assert stdlib_only()
    print("24-repeat_char OK")


if __name__ == "__main__":
    main()
