"""Pinning violation detection (HPKP-style), Simulated.

Compares the presented SPKI hash against the pinned set for a host.
A mismatch is a HARD FAIL (possible MITM).  Hosts with no pins are
handled per policy: "report" (allow + flag) or "strict" (deny).

What this IS: trust-on-first-use pin enforcement primitive.

What this IS NOT:
* Not real TLS -- SPKI hashes are host-supplied strings.
* Pin mismatch always fails; unknown-host behavior is policy.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, Set, Tuple

#: Module version.
DEF_EXTRA_18_VERSION = "def-extra-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-18.v1"


class PinningError(Exception):
    """Fail-closed."""


@dataclass
class PinSet:
    """Pinned SPKI hashes for one host."""

    host: str
    pins: Set[str] = field(default_factory=set)
    backup_pins: Set[str] = field(default_factory=set)


class PinningEnforcer:
    """Enforce SPKI pins per host."""

    def __init__(self, *, unknown_host_policy: str = "report") -> None:
        if unknown_host_policy not in ("report", "strict"):
            raise PinningError("unknown_host_policy must be report|strict")
        self._policy = unknown_host_policy
        self._pins: Dict[str, PinSet] = {}

    def pin(self, pinset: PinSet) -> None:
        """Install pins for a host."""
        if not pinset.host or not pinset.pins:
            raise PinningError("host and at least one pin required")
        self._pins[pinset.host] = pinset

    def check(self, host: str, presented_spki: str) -> Tuple[bool, str]:
        """Check presented SPKI against pins.

        Returns (ok, detail).  Mismatch -> (False, "PIN VIOLATION").
        """
        if not host or not presented_spki:
            return False, "host and spki required"
        pinset = self._pins.get(host)
        if pinset is None:
            if self._policy == "strict":
                return False, "no pins for host (strict)"
            return True, "no pins for host (reported)"
        if presented_spki in pinset.pins or presented_spki in pinset.backup_pins:
            return True, "pin matched"
        return False, "PIN VIOLATION: possible MITM"


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
    enforcer = PinningEnforcer()
    enforcer.pin(PinSet("example.com", {"spki-AAA"}, {"spki-BBB"}))
    ok, _ = enforcer.check("example.com", "spki-AAA")
    assert ok is True
    ok, _ = enforcer.check("example.com", "spki-BBB")  # backup pin
    assert ok is True
    ok, detail = enforcer.check("example.com", "spki-EVIL")
    assert ok is False and "VIOLATION" in detail
    # Unknown host: report policy allows with note.
    ok, detail = enforcer.check("other.com", "spki-X")
    assert ok is True and "reported" in detail
    # Strict policy denies unknown hosts.
    strict = PinningEnforcer(unknown_host_policy="strict")
    ok, _ = strict.check("other.com", "spki-X")
    assert ok is False
    assert stdlib_only()
    print("def-extra-18 OK: pins, violation, policies")


if __name__ == "__main__":
    main()
