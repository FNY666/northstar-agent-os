"""Deception technology: mock decoy deployment, Simulated.

Decoy kinds: credential, host, share, api_key, document.
Any interaction with a decoy is critical -- decoys have no
legitimate use, so interaction == high-confidence malicious.

Lifecycle: deploy(kind, label) -> decoy_id; interact(...) -> alert;
burn(decoy_id) retires a decoy; stats() summarizes.

What this IS: decoy lifecycle + interaction alerting.

What this IS NOT:
* Not real decoy infrastructure -- the host emulates the services.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
MONITOR_19_VERSION = "monitor-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-19.v1"

_DECOY_KINDS = frozenset({"credential", "host", "share", "api_key", "document"})


class DeceptionError(Exception):
    """Fail-closed."""


@dataclass
class Decoy:
    decoy_id: str
    kind: str
    label: str
    burned: bool = False
    interactions: int = 0


@dataclass(frozen=True)
class DecoyAlert:
    decoy_id: str
    kind: str
    src: str
    interaction: str
    severity: int
    ts: float


class Deception:
    """Mock deception platform."""

    def __init__(self) -> None:
        self._decoys: Dict[str, Decoy] = {}
        self._alerts: List[DecoyAlert] = []
        self._next = 1

    def deploy(self, kind: str, label: str) -> str:
        if kind not in _DECOY_KINDS:
            raise DeceptionError(f"unknown decoy kind {kind!r}")
        if not label:
            raise DeceptionError("label required")
        decoy_id = f"decoy-{self._next:04d}"
        self._next += 1
        self._decoys[decoy_id] = Decoy(decoy_id, kind, label)
        return decoy_id

    def interact(
        self, decoy_id: str, src: str, interaction: str, ts: float = 0.0
    ) -> DecoyAlert:
        decoy = self._decoys.get(decoy_id)
        if decoy is None:
            raise DeceptionError(f"unknown decoy {decoy_id!r}")
        if decoy.burned:
            raise DeceptionError(f"decoy {decoy_id!r} is burned")
        if not src or not interaction:
            raise DeceptionError("src/interaction required")
        if ts < 0:
            raise DeceptionError("ts must be >= 0")
        decoy.interactions += 1
        alert = DecoyAlert(decoy_id, decoy.kind, src, interaction, 95, ts)
        self._alerts.append(alert)
        return alert

    def burn(self, decoy_id: str) -> None:
        decoy = self._decoys.get(decoy_id)
        if decoy is None:
            raise DeceptionError(f"unknown decoy {decoy_id!r}")
        decoy.burned = True

    def alerts(self) -> List[DecoyAlert]:
        return list(self._alerts)

    def stats(self) -> Dict[str, int]:
        decoys = list(self._decoys.values())
        return {
            "deployed": len(decoys),
            "active": sum(1 for d in decoys if not d.burned),
            "interactions": sum(d.interactions for d in decoys),
            "alerts": len(self._alerts),
        }


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
    d = Deception()
    c1 = d.deploy("credential", "svc-backup")
    h1 = d.deploy("host", "db-decoy-03")
    assert c1 != h1
    a = d.interact(c1, "10.0.0.9", "login_attempt", ts=5.0)
    assert a.severity == 95 and a.src == "10.0.0.9"
    d.interact(c1, "10.0.0.9", "login_attempt", ts=6.0)
    d.burn(h1)
    s = d.stats()
    assert s == {"deployed": 2, "active": 1, "interactions": 2, "alerts": 2}
    for bad in (
        lambda: d.deploy("nonsense", "x"),
        lambda: d.deploy("host", ""),
        lambda: d.interact("decoy-9999", "s", "i"),
        lambda: d.interact(h1, "s", "i"),  # burned
        lambda: d.interact(c1, "", "i"),
        lambda: d.burn("decoy-9999"),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except DeceptionError:
            pass
    assert stdlib_only()
    print("monitor-19 OK: deploy, interact->alert, burn, stats, fail-closed, stdlib")


if __name__ == "__main__":
    main()
