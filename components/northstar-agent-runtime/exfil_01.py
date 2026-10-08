"""DNS tunneling detection (dns-tunnel), Simulated.

Detects DNS tunneling: data smuggled out via DNS queries. Flags long labels, high-entropy subdomains, hex/base64-looking labels, and oversized queries.

What this IS: a DNS-query shape detector for tunneled data.

What this IS NOT:
* Not a DNS server or resolver -- inspects query strings only.
* Entropy thresholds are heuristic, not proof of tunneling.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import math
import re

#: Module version.
EXFIL_01_VERSION = "exfil-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-01.v1"


class Exfil01Error(Exception):
    """Fail-closed."""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def detect_dns_tunnel(query: str) -> tuple:
    """Detect DNS tunneling patterns. Returns (suspicious, reason)."""
    if not isinstance(query, str) or not query.strip():
        raise Exfil01Error("query must be non-empty str")
    labels = query.strip(".").split(".")
    longest = max(len(lbl) for lbl in labels)
    if longest > 50:
        return True, "label too long: %d chars" % longest
    if len(query) > 120:
        return True, "query too long: %d chars" % len(query)
    joined = "".join(labels)
    entropy = _shannon_entropy(joined)
    if entropy > 4.3 and len(joined) > 40:
        return True, "high entropy %.2f over %d chars" % (entropy, len(joined))
    for lbl in labels:
        if len(lbl) >= 32 and re.fullmatch(r"[0-9a-fA-F]+", lbl):
            return True, "hex-encoded long label"
        if len(lbl) >= 32 and re.fullmatch(r"[A-Za-z0-9+/=]+", lbl):
            return True, "base64-looking long label"
    if len(labels) > 10:
        return True, "too many labels: %d" % len(labels)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "math", "re"}
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
    ok, _ = detect_dns_tunnel("www.example.com")
    assert ok is False
    ok, _ = detect_dns_tunnel("a" * 60 + ".example.com")
    assert ok is True
    ok, _ = detect_dns_tunnel("x8f2k9q1m4n7b3v6c0p5s2d9f4g7h1j3k5.example.com")
    assert ok is True
    assert stdlib_only()
    print("exfil-01 OK: dns tunnel shapes, fail-closed")


if __name__ == "__main__":
    main()
