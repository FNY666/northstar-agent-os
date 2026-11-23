"""Runtime defense 13: TLS interception (mock), Simulated.

Mock config for TLS-intercepting egress proxy: internal CA, per-host
generated certs, and pinned exclusions (hosts that must NOT be
intercepted, e.g. HPKP-pinned or sensitive).  This is a CONFIG MODEL --
real interception needs a MITM proxy (mitmproxy) with the CA installed.

What this IS: interception policy config (what to intercept/exclude).
What this IS NOT: actual TLS interception.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import FrozenSet, List, Tuple

#: Module version.
RUNTIME_DEFENSE_13_VERSION = "runtime-defense-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-13.v1"


class TlsInterceptError(Exception):
    """Fail-closed: bad config raises."""


@dataclass(frozen=True)
class TlsInterceptConfig:
    """TLS interception policy."""

    ca_name: str  # internal CA identifier (not the key itself)
    intercept_all: bool = True
    # Hosts that must NOT be intercepted (sensitive / pinned).
    exclusions: FrozenSet[str] = frozenset()
    # Minimum TLS version to allow through.
    min_tls_version: str = "1.2"

    def __post_init__(self):
        if not self.ca_name:
            raise TlsInterceptError("ca_name required")
        if self.min_tls_version not in ("1.0", "1.1", "1.2", "1.3"):
            raise TlsInterceptError(
                f"bad min_tls_version {self.min_tls_version!r}"
            )
        for e in self.exclusions:
            if not e or " " in e:
                raise TlsInterceptError(f"bad exclusion {e!r}")

    def should_intercept(self, host: str) -> Tuple[bool, str]:
        """Decide whether to intercept a host."""
        h = host.strip().lower().rstrip(".")
        for excl in self.exclusions:
            if excl.startswith("*."):
                suffix = excl[2:]
                if h == suffix or h.endswith("." + suffix):
                    return False, f"excluded: {h}"
            elif h == excl:
                return False, f"excluded: {h}"
        if self.intercept_all:
            return True, f"intercepted: {h}"
        return False, f"not intercepted (selective mode): {h}"


def build_config(ca_name: str, exclusions: List[str] = ()) -> TlsInterceptConfig:
    """Build interception config."""
    if not ca_name:
        raise TlsInterceptError("ca_name required")
    return TlsInterceptConfig(
        ca_name=ca_name,
        exclusions=frozenset(e.strip().lower().rstrip(".") for e in exclusions),
    )


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
    cfg = build_config("internal-ca-2026", ["bank.example.com", "*.health.example"])
    yes, _ = cfg.should_intercept("api.example.com")
    assert yes is True
    no, reason = cfg.should_intercept("bank.example.com")
    assert no is False
    no, _ = cfg.should_intercept("a.health.example")
    assert no is False

    try:
        build_config("")
        raise AssertionError("should raise")
    except TlsInterceptError:
        pass
    try:
        TlsInterceptConfig(ca_name="x", min_tls_version="0.9")
        raise AssertionError("should raise")
    except TlsInterceptError:
        pass

    assert stdlib_only()
    print("runtime-defense-13 OK: intercept policy, exclusions, stdlib")


if __name__ == "__main__":
    main()
