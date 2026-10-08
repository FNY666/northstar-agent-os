"""Runtime defense 10: egress filtering (domain allowlist), Simulated.

Domain allowlist with exact and wildcard (*.example.com) matching.
DNS names are normalized (lowercase, trailing dot stripped) before
matching.  Unknown domains -> deny (fail-closed).

What this IS: domain allowlist matcher (policy).
What this IS NOT: DNS resolution or TLS SNI enforcement.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import FrozenSet, List, Tuple

#: Module version.
RUNTIME_DEFENSE_10_VERSION = "runtime-defense-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-10.v1"


class EgressFilterError(Exception):
    """Fail-closed: bad allowlist raises."""


def normalize(domain: str) -> str:
    """Lowercase, strip trailing dot and whitespace."""
    return domain.strip().lower().rstrip(".")


def _valid_label(label: str) -> bool:
    return bool(label) and len(label) <= 63 and all(
        c.isalnum() or c in ("-", "_") for c in label
    )


def validate_domain(domain: str) -> str:
    """Validate and normalize a domain entry.  Wildcards allowed as '*.' prefix."""
    d = normalize(domain)
    if d.startswith("*."):
        rest = d[2:]
        if not rest or not all(_valid_label(l) for l in rest.split(".")):
            raise EgressFilterError(f"bad wildcard domain {domain!r}")
        return d
    if not d or not all(_valid_label(l) for l in d.split(".")):
        raise EgressFilterError(f"bad domain {domain!r}")
    return d


@dataclass(frozen=True)
class DomainAllowlist:
    """Validated domain allowlist."""

    domains: FrozenSet[str]

    def matches(self, domain: str) -> bool:
        d = normalize(domain)
        for entry in self.domains:
            if entry.startswith("*."):
                suffix = entry[2:]
                if d == suffix or d.endswith("." + suffix):
                    return True
            elif d == entry:
                return True
        return False

    def check(self, domain: str) -> Tuple[bool, str]:
        if self.matches(domain):
            return True, f"allowlisted: {normalize(domain)}"
        return False, f"not allowlisted: {normalize(domain)}"


def build_allowlist(domains: List[str]) -> DomainAllowlist:
    """Build and validate an allowlist.  Empty -> fail-closed."""
    if not domains:
        raise EgressFilterError("empty allowlist: fail-closed")
    validated = frozenset(validate_domain(d) for d in domains)
    return DomainAllowlist(domains=validated)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    al = build_allowlist(["api.example.com", "*.cdn.example.net"])
    assert al.matches("api.example.com") is True
    assert al.matches("API.EXAMPLE.COM.") is True  # normalized
    assert al.matches("a.cdn.example.net") is True  # wildcard
    assert al.matches("cdn.example.net") is True  # wildcard covers apex
    assert al.matches("evil.com") is False
    assert al.matches("example.com.evil.com") is False  # suffix trick
    ok, _ = al.check("evil.com")
    assert ok is False

    try:
        build_allowlist([])
        raise AssertionError("should raise")
    except EgressFilterError:
        pass
    try:
        build_allowlist(["bad domain!"])
        raise AssertionError("should raise")
    except EgressFilterError:
        pass

    assert stdlib_only()
    print("runtime-defense-10 OK: domain allowlist, wildcards, fail-closed")


if __name__ == "__main__":
    main()
