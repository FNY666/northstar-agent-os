"""CSS class selector extractor

What this IS: an extractor for .class-name selectors.

What this IS NOT: a CSS parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_47_VERSION = "rx-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-47.v1"

CSS_CLASS_RE = re.compile(r'\\.(-?[_A-Za-z][_A-Za-z0-9-]*)')
def find_css_classes(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return CSS_CLASS_RE.findall(text)


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
    assert find_css_classes(".btn") == ["btn"]
    assert find_css_classes("div.a-b_c span") == ["a-b_c"]
    assert find_css_classes("no class") == []
    assert find_css_classes(".x.y") == ["x", "y"]
    assert find_css_classes("#id") == []
    assert stdlib_only()
    print("47-css_class OK")


if __name__ == "__main__":
    main()
