"""CRL checking (mock), Simulated.

Checks a certificate serial against a Certificate Revocation List.
A stale CRL (now > next_update) FAILS CLOSED -- never trust an
outdated revocation list.

What this IS: revocation lookup with freshness enforcement.

What this IS NOT:
* Not a real CRL parser -- the CRL is a host-built object.
* Stale CRL or unknown issuer -> deny (fail closed).
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

#: Module version.
DEF_EXTRA_17_VERSION = "def-extra-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-17.v1"


class CRLError(Exception):
    """Fail-closed."""


@dataclass
class CRL:
    """A certificate revocation list (mock)."""

    issuer: str
    number: int
    this_update: float
    next_update: float
    revoked: Set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.next_update <= self.this_update:
            raise CRLError("next_update must be after this_update")


class CRLChecker:
    """Hold CRLs per issuer and check serials."""

    def __init__(self) -> None:
        self._crls: Dict[str, CRL] = {}

    def install(self, crl: CRL) -> None:
        """Install (or replace) the CRL for an issuer."""
        if not crl.issuer:
            raise CRLError("issuer required")
        self._crls[crl.issuer] = crl

    def check(
        self, issuer: str, serial: str, *, now: Optional[float] = None
    ) -> Tuple[bool, str]:
        """Return (ok, detail).  ok=False means revoked OR cannot verify.

        Fail-closed: unknown issuer or stale CRL -> (False, reason).
        """
        ts = time.time() if now is None else now
        crl = self._crls.get(issuer)
        if crl is None:
            return False, "no CRL for issuer"
        if ts > crl.next_update:
            return False, "CRL stale: refuse to trust"
        if ts < crl.this_update:
            return False, "CRL from the future"
        if serial in crl.revoked:
            return False, "serial revoked"
        return True, "not revoked"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
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
    checker = CRLChecker()
    checker.install(CRL("ca-1", 7, 1000.0, 2000.0, {"AA:BB", "CC:DD"}))
    ok, _ = checker.check("ca-1", "EE:FF", now=1500.0)
    assert ok is True
    ok, reason = checker.check("ca-1", "AA:BB", now=1500.0)
    assert ok is False and "revoked" in reason
    # Stale CRL fails closed.
    ok, reason = checker.check("ca-1", "EE:FF", now=9999.0)
    assert ok is False and "stale" in reason
    # Unknown issuer fails closed.
    ok, _ = checker.check("ca-9", "EE:FF", now=1500.0)
    assert ok is False
    assert stdlib_only()
    print("def-extra-17 OK: revoked, stale, unknown issuer")


if __name__ == "__main__":
    main()
