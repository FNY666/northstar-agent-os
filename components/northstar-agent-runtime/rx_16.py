"""kebab-case identifier matcher

What this IS: a matcher for lower-kebab-case identifiers.

What this IS NOT: a slug validator for full URLs.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_16_VERSION = "rx-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-16.v1"

KEBAB_RE = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)+')
def is_kebab(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return KEBAB_RE.fullmatch(text) is not None

def find_kebabs(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return KEBAB_RE.findall(text)


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
    assert is_kebab("kebab-case")
    assert is_kebab("my-slug-2")
    assert not is_kebab("Kebab-Case")
    assert not is_kebab("snake_case")
    assert find_kebabs("use my-slug and other-thing") == ["my-slug", "other-thing"]
    assert stdlib_only()
    print("16-kebab OK")


if __name__ == "__main__":
    main()
