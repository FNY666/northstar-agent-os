"""Crypto Defense 26: OAuth scopes (scope checker), Simulated.

Validates that a token's granted scopes cover the required scopes.
Supports exact match, namespace wildcards ("read:*"), and an "admin"
scope that implies everything.  Fail-closed: missing scope denies.

What this IS: scope enforcement API for OAuth-style tokens.
What this IS NOT: a real authorization server or consent flow.
"""

from __future__ import annotations

import ast
from typing import FrozenSet, List, Set

#: Module version.
CRYPTO_DEFENSE_26_VERSION = "crypto-defense-26.v1"
SCHEMA_PIN = "northstar.crypto-defense-26.v1"


class ScopeError(Exception):
    """Fail-closed."""


def parse_scopes(scope_string: str) -> FrozenSet[str]:
    """Parse a space-delimited OAuth scope string."""
    if not isinstance(scope_string, str):
        raise ScopeError("scope string must be str")
    return frozenset(s for s in scope_string.split() if s)


def _scope_covers(granted: str, required: str) -> bool:
    """One granted scope covers one required scope."""
    if granted == "admin":
        return True
    if granted == required:
        return True
    # Namespace wildcard: "read:*" covers "read:files".
    if granted.endswith(":*"):
        prefix = granted[:-2]
        return required == prefix or required.startswith(prefix + ":")
    return False


def has_scope(granted: FrozenSet[str], required: str) -> bool:
    """Check a single required scope against granted scopes."""
    if not required:
        raise ScopeError("required scope must be non-empty")
    return any(_scope_covers(g, required) for g in granted)


def has_all_scopes(granted: FrozenSet[str], required: List[str]) -> bool:
    """All required scopes must be covered."""
    return all(has_scope(granted, r) for r in required)


def missing_scopes(granted: FrozenSet[str], required: List[str]) -> Set[str]:
    """Return the required scopes that are not covered."""
    return {r for r in required if not has_scope(granted, r)}


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
    g = parse_scopes("read:files write:files")
    assert has_scope(g, "read:files") is True
    assert has_scope(g, "delete:files") is False
    # Wildcard.
    w = parse_scopes("read:*")
    assert has_scope(w, "read:files") is True
    assert has_scope(w, "write:files") is False
    # Admin implies all.
    a = parse_scopes("admin")
    assert has_scope(a, "anything:at:all") is True
    # All-required + missing report.
    assert has_all_scopes(g, ["read:files", "write:files"]) is True
    assert missing_scopes(g, ["read:files", "delete:files"]) == {"delete:files"}
    assert stdlib_only()
    print("crypto-defense-26 OK")


if __name__ == "__main__":
    main()
