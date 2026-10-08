"""JWT structure checker

What this IS: a structural checker for header.payload.signature JWT shapes.

What this IS NOT: a JWT verifier -- signatures are not validated.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_38_VERSION = "rx-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-38.v1"

JWT_RE = re.compile(r'[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*')
def is_jwt_shape(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return JWT_RE.fullmatch(text) is not None

def jwt_parts(text: str):
    if not is_jwt_shape(text):
        return None
    return text.split(".")


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
    assert is_jwt_shape("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig")
    assert not is_jwt_shape("just.two")
    assert not is_jwt_shape("no-dots")
    assert jwt_parts("a.b.c") == ["a", "b", "c"]
    assert jwt_parts("bad") is None
    assert stdlib_only()
    print("38-jwt OK")


if __name__ == "__main__":
    main()
