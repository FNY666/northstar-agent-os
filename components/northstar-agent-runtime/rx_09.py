"""Semantic version matcher

What this IS: a semver 2.0 core-version matcher (MAJOR.MINOR.PATCH with optional pre-release/build).

What this IS NOT: a semver precedence comparator.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_09_VERSION = "rx-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-09.v1"

SEMVER_RE = re.compile(r'(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-[0-9A-Za-z.-]+)?(?:\\+[0-9A-Za-z.-]+)?')
def is_semver(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return SEMVER_RE.fullmatch(text) is not None

def find_semvers(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return SEMVER_RE.findall(text)


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
    assert is_semver("1.2.3")
    assert is_semver("0.1.0-alpha+001")
    assert not is_semver("1.2")
    assert not is_semver("v1.2.3")
    assert find_semvers("needs 1.2.3 or 2.0.0") == ["1.2.3", "2.0.0"]
    assert stdlib_only()
    print("09-semver OK")


if __name__ == "__main__":
    main()
