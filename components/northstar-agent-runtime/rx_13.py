"""Password strength pattern

What this IS: a policy matcher: 8+ chars with lower, upper, digit and symbol.

What this IS NOT: a password meter -- length/entropy are not scored.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_13_VERSION = "rx-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-13.v1"

PASSWORD_RE = re.compile(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}')
def is_strong_password(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return PASSWORD_RE.fullmatch(text) is not None


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
    assert is_strong_password("Abcdef1!")
    assert is_strong_password("xY9$zzzz")
    assert not is_strong_password("abcdef1!")
    assert not is_strong_password("Ab1!")
    assert not is_strong_password("Abcdefgh")
    assert stdlib_only()
    print("13-password OK")


if __name__ == "__main__":
    main()
