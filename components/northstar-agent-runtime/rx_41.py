"""Windows path matcher

What this IS: a matcher for drive-letter Windows paths.

What this IS NOT: a UNC path matcher.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_41_VERSION = "rx-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-41.v1"

WIN_PATH_RE = re.compile(r'[A-Za-z]:\\\\(?:[^\\\\/:*?\"<>|\\r\\n]+\\\\)*[^\\\\/:*?\"<>|\\r\\n]*')
def is_win_path(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return WIN_PATH_RE.fullmatch(text) is not None


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
    assert is_win_path("C:\\Users\\x")
    assert is_win_path("D:\\")
    assert not is_win_path("/home/x")
    assert not is_win_path("C:relative")
    assert not is_win_path("")
    assert stdlib_only()
    print("41-win_path OK")


if __name__ == "__main__":
    main()
