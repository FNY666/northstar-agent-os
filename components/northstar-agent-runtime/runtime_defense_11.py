"""Runtime defense 11: DNS filtering (blocklist), Simulated.

DNS query filter: blocklist of malicious/suspicious domains plus
category rules (e.g. block newly-registered-looking DGA patterns).
Fail-closed: resolution errors are treated as blocked.

What this IS: DNS query policy (blocklist + heuristics).
What this IS NOT: an actual DNS resolver/filter.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import FrozenSet, List, Tuple

#: Module version.
RUNTIME_DEFENSE_11_VERSION = "runtime-defense-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-11.v1"


class DnsFilterError(Exception):
    """Fail-closed: bad filter config raises."""


#: Heuristic: looks like a DGA domain (long random-looking label).
_DGA_RE = re.compile(r"^[a-z0-9]{16,}$")


def looks_like_dga(domain: str) -> bool:
    """Heuristic DGA detection on the leftmost label."""
    label = domain.strip().lower().rstrip(".").split(".")[0]
    if _DGA_RE.match(label):
        # High consonant ratio suggests randomness.
        vowels = sum(1 for c in label if c in "aeiou")
        return vowels / max(len(label), 1) < 0.25
    return False


@dataclass(frozen=True)
class DnsFilter:
    """DNS blocklist filter."""

    blocklist: FrozenSet[str]  # exact domains, normalized
    block_dga: bool = True

    def check(self, domain: str) -> Tuple[bool, str]:
        """Returns (allowed, reason).  Blocked -> (False, reason)."""
        d = domain.strip().lower().rstrip(".")
        if not d:
            return False, "empty query: blocked"
        if d in self.blocklist:
            return False, f"blocklisted: {d}"
        # Subdomain of a blocklisted domain is also blocked.
        for blocked in self.blocklist:
            if d.endswith("." + blocked):
                return False, f"subdomain of blocklisted {blocked}"
        if self.block_dga and looks_like_dga(d):
            return False, f"suspected DGA: {d}"
        return True, f"allowed: {d}"


def build_filter(blocklist: List[str], block_dga: bool = True) -> DnsFilter:
    """Build filter.  Blocklist may be empty (heuristics still apply)."""
    normalized = set()
    for d in blocklist:
        d = d.strip().lower().rstrip(".")
        if not d:
            raise DnsFilterError("empty blocklist entry")
        normalized.add(d)
    return DnsFilter(blocklist=frozenset(normalized), block_dga=block_dga)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
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
    f = build_filter(["malware.example", "phish.test"])
    ok, _ = f.check("good.example.com")
    assert ok is True
    ok, _ = f.check("malware.example")
    assert ok is False
    ok, _ = f.check("sub.malware.example")
    assert ok is False
    ok, reason = f.check("xkqzpvtnbmwlrqjd.example.com")
    assert ok is False and "DGA" in reason
    ok, _ = f.check("")
    assert ok is False

    f2 = build_filter(["a.b"], block_dga=False)
    ok, _ = f2.check("xkqzpvtnbmwlrqjd.example.com")
    assert ok is True  # heuristics off

    try:
        build_filter([""])
        raise AssertionError("should raise")
    except DnsFilterError:
        pass

    assert stdlib_only()
    print("runtime-defense-11 OK: dns blocklist, dga heuristic, fail-closed")


if __name__ == "__main__":
    main()
