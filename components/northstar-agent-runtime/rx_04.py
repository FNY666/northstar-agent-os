"""URL matcher

What this IS: an http/https URL matcher with host, optional port and path.

What this IS NOT: a URL parser -- use urllib.parse for real parsing.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_04_VERSION = "rx-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-04.v1"

URL_RE = re.compile(r'https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~:/?#\\[\\]@!$&\\'()*+,;=%-]*)?')
def is_url(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return URL_RE.fullmatch(text) is not None

def find_urls(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return URL_RE.findall(text)


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
    assert is_url("https://example.com/path?q=1")
    assert is_url("http://localhost:8080/")
    assert not is_url("ftp://example.com")
    assert not is_url("example.com")
    assert find_urls("see https://a.io and http://b.org/x") == ["https://a.io", "http://b.org/x"]
    assert stdlib_only()
    print("04-url OK")


if __name__ == "__main__":
    main()
