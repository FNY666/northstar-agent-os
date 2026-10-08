"""Cache poisoning detection (cache-poison), Simulated.

Detects cache-poisoning vectors: unkeyed parameters reflected in responses, and delimiter characters in cache keys.

What this IS: a cache key/response reflection checker.

What this IS NOT:
* Needs the response body to check reflection.
* Not a cache server.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_09_VERSION = "exfil-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-09.v1"


class Exfil09Error(Exception):
    """Fail-closed."""


def detect_cache_poisoning(cache_key: str, unkeyed_params: Dict[str, str], response_body: str) -> tuple:
    """Detect cache poisoning vectors. Returns (suspicious, reason)."""
    if not isinstance(cache_key, str):
        raise Exfil09Error("cache_key must be str")
    if not isinstance(unkeyed_params, dict) or not isinstance(response_body, str):
        raise Exfil09Error("bad types")
    for k, v in unkeyed_params.items():
        if v and v in response_body:
            return True, "unkeyed param '%s' reflected in response" % k
    if re.search(r"[;|$`]", cache_key):
        return True, "delimiter in cache key"
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "re"}
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
    ok, _ = detect_cache_poisoning("page:/home", {"utm": "x"}, "<html>home</html>")
    assert ok is False
    ok, _ = detect_cache_poisoning("page:/home", {"x": "<script>"}, "<html><script></html>")
    assert ok is True
    assert stdlib_only()
    print("exfil-09 OK: cache poisoning, fail-closed")


if __name__ == "__main__":
    main()
