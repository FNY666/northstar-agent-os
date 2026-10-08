"""POSIX path matcher

What this IS: a matcher for absolute POSIX paths.

What this IS NOT: a path resolver -- .. segments are not normalized.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_40_VERSION = "rx-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-40.v1"

POSIX_PATH_RE = re.compile(r'/(?:[^\\x00/]+/)*[^\\x00/]*')
def is_posix_path(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return POSIX_PATH_RE.fullmatch(text) is not None


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
    assert is_posix_path("/home/hatch/file.txt")
    assert is_posix_path("/")
    assert not is_posix_path("relative/path")
    assert not is_posix_path("")
    assert is_posix_path("/a/b/c/")
    assert stdlib_only()
    print("40-posix_path OK")


if __name__ == "__main__":
    main()
