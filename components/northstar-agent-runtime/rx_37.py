"""Base64 shape detector

What this IS: a detector for base64-shaped strings (length multiple of 4).

What this IS NOT: a base64 decoder -- padding and alphabet are not validated.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_37_VERSION = "rx-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-37.v1"

B64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
def looks_like_b64(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return bool(text) and len(text) % 4 == 0 and B64_RE.fullmatch(text) is not None


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
    assert looks_like_b64("aGVsbG8=")
    assert looks_like_b64("YWJj")
    assert not looks_like_b64("abc")
    assert not looks_like_b64("a b c d")
    assert not looks_like_b64("")
    assert stdlib_only()
    print("37-b64 OK")


if __name__ == "__main__":
    main()
