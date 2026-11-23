"""Downgrade attack detection, Simulated.

Tracks the best protocol version ever negotiated with each peer and
flags a session that negotiates LOWER than the peer's known best
(or lower than the client's offered max) -- the signature of a
STRIPTLS / version-rollback attacker.

What this IS: downgrade tripwire for negotiated sessions.

What this IS NOT:
* Not a TLS implementation -- versions are host-supplied strings.
* Detection is advisory (returns alert); the caller decides to drop.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Module version.
DEF_EXTRA_19_VERSION = "def-extra-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-19.v1"


class DowngradeError(Exception):
    """Fail-closed."""


#: Version rank, higher = newer.
VERSION_RANK: Dict[str, int] = {
    "SSL3": 0,
    "TLS1.0": 1,
    "TLS1.1": 2,
    "TLS1.2": 3,
    "TLS1.3": 4,
}


def rank(version: str) -> int:
    """Numeric rank of a protocol version."""
    if version not in VERSION_RANK:
        raise DowngradeError(f"unknown version: {version}")
    return VERSION_RANK[version]


@dataclass
class Negotiation:
    """One recorded negotiation."""

    peer: str
    offered_max: str
    negotiated: str
    flags_stripped: List[str]


class DowngradeDetector:
    """Detect version rollback and flag stripping per peer."""

    def __init__(self) -> None:
        self._best: Dict[str, int] = {}
        self._history: Dict[str, List[Negotiation]] = {}

    def observe(self, neg: Negotiation) -> Tuple[bool, str]:
        """Record a negotiation.  Returns (downgrade, detail).

        downgrade=True means a rollback or flag-strip was detected.
        """
        if not neg.peer:
            raise DowngradeError("peer required")
        offered = rank(neg.offered_max)
        got = rank(neg.negotiated)
        if got > offered:
            raise DowngradeError("negotiated above offered max")
        alerts: List[str] = []
        # Negotiated below what we offered -> suspicious.
        if got < offered:
            alerts.append(f"negotiated {neg.negotiated} below offered {neg.offered_max}")
        # Below peer's historical best -> rollback.
        best = self._best.get(neg.peer)
        if best is not None and got < best:
            best_name = next(k for k, v in VERSION_RANK.items() if v == best)
            alerts.append(f"rollback: {neg.negotiated} below peer best {best_name}")
        # Stripped flags (e.g. STARTTLS removed) -> attacker.
        if neg.flags_stripped:
            alerts.append(f"flags stripped: {','.join(neg.flags_stripped)}")
        # Update best.
        if best is None or got > best:
            self._best[neg.peer] = got
        self._history.setdefault(neg.peer, []).append(neg)
        if alerts:
            return True, "; ".join(alerts)
        return False, "ok"

    def peer_best(self, peer: str) -> Optional[str]:
        """Best version ever seen for a peer."""
        best = self._best.get(peer)
        if best is None:
            return None
        return next(k for k, v in VERSION_RANK.items() if v == best)


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
    detector = DowngradeDetector()
    down, _ = detector.observe(Negotiation("srv", "TLS1.3", "TLS1.3", []))
    assert down is False
    assert detector.peer_best("srv") == "TLS1.3"
    # Rollback to TLS1.2 after TLS1.3 seen -> downgrade.
    down, detail = detector.observe(Negotiation("srv", "TLS1.3", "TLS1.2", []))
    assert down is True and "rollback" in detail
    # Flag stripping -> downgrade.
    down, detail = detector.observe(Negotiation("srv2", "TLS1.3", "TLS1.3", ["starttls"]))
    assert down is True and "stripped" in detail
    # Unknown version rejected.
    try:
        detector.observe(Negotiation("srv3", "TLS9.9", "TLS9.9", []))
    except DowngradeError:
        pass
    else:
        raise AssertionError("expected DowngradeError")
    assert stdlib_only()
    print("def-extra-19 OK: rollback, flag-strip, unknown version")


if __name__ == "__main__":
    main()
