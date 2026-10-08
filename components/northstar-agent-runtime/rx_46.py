"""HTML entity matcher

What this IS: a matcher for &name; / &#123; / &#x1F; entities.

What this IS NOT: an entity decoder -- see html.unescape.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_46_VERSION = "rx-46.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-46.v1"

HTML_ENTITY_RE = re.compile(r'&(?:[A-Za-z][A-Za-z0-9]+|#[0-9]+|#x[0-9A-Fa-f]+);')
def find_entities(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return HTML_ENTITY_RE.findall(text)


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
    assert find_entities("a &amp; b") == ["&amp;"]
    assert find_entities("&#65; &#x41;") == ["&#65;", "&#x41;"]
    assert find_entities("a & b") == []
    assert find_entities("&;") == []
    assert find_entities("&lt;&gt;") == ["&lt;", "&gt;"]
    assert stdlib_only()
    print("46-html_entity OK")


if __name__ == "__main__":
    main()
