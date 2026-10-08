"""Email address matcher

What this IS: a pragmatic RFC-5322-subset email matcher for common addresses.

What this IS NOT: a full RFC-5322 parser -- quoted local parts and IP literals are rejected.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_01_VERSION = "rx-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-01.v1"

EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
def is_email(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return EMAIL_RE.fullmatch(text) is not None

def find_emails(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return EMAIL_RE.findall(text)


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
    assert is_email("user@example.com")
    assert is_email("a.b+tag@sub.domain.org")
    assert not is_email("not-an-email")
    assert not is_email("user@.com")
    assert find_emails("a@b.com and x@y.io") == ["a@b.com", "x@y.io"]
    assert stdlib_only()
    print("01-email OK")


if __name__ == "__main__":
    main()
