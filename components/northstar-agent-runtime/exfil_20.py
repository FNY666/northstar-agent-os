"""Cookie tossing detection (cookie-toss), Simulated.

Detects cookie tossing: a subdomain setting a cookie scoped to the parent domain (without __Host- prefix) to shadow the parent's cookie.

What this IS: a cookie Domain-attribute tossing detector.

What this IS NOT:
* Analyzes provided cookie dicts; no browser access.
* Heuristic on Domain vs setter host.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_20_VERSION = "exfil-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-20.v1"


class Exfil20Error(Exception):
    """Fail-closed."""


def detect_cookie_tossing(cookie: Dict[str, str]) -> tuple:
    """Detect cookie tossing. cookie: {name, domain, set_by}. Returns (suspicious, reason)."""
    if not isinstance(cookie, dict):
        raise Exfil20Error("cookie must be dict")
    name = cookie.get("name", "")
    domain_attr = cookie.get("domain", "").lstrip(".").lower()
    setter = cookie.get("set_by", "").lower()
    if not name or not domain_attr or not setter:
        raise Exfil20Error("cookie needs name, domain, set_by")
    if setter != domain_attr and setter.endswith("." + domain_attr):
        if not name.startswith("__Host-"):
            return True, "cookie tossing: %s sets %s for %s" % (setter, name, domain_attr)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    ok, _ = detect_cookie_tossing({"name": "sid", "domain": "sub.example.com", "set_by": "sub.example.com"})
    assert ok is False
    ok, _ = detect_cookie_tossing({"name": "sid", "domain": "example.com", "set_by": "evil.example.com"})
    assert ok is True
    ok, _ = detect_cookie_tossing({"name": "__Host-sid", "domain": "example.com", "set_by": "sub.example.com"})
    assert ok is False
    assert stdlib_only()
    print("exfil-20 OK: cookie tossing, fail-closed")


if __name__ == "__main__":
    main()
