"""Git SHA matcher

What this IS: a matcher for 7-40 char hex SHAs.

What this IS NOT: a git object verifier.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_48_VERSION = "rx-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-48.v1"

GIT_SHA_RE = re.compile(r'\\b[0-9a-f]{7,40}\\b')
def is_git_sha(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return GIT_SHA_RE.fullmatch(text) is not None

def find_shas(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return GIT_SHA_RE.findall(text)


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
    assert is_git_sha("f74542e")
    assert is_git_sha("f74542edd5df4d9596f93022fb26eab5")
    assert not is_git_sha("xyz123")
    assert not is_git_sha("12345")
    assert find_shas("commit f74542e done") == ["f74542e"]
    assert stdlib_only()
    print("48-git_sha OK")


if __name__ == "__main__":
    main()
