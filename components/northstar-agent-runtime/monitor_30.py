"""Root cause analysis: mock causal-chain builder, Simulated.

Maps alert kinds to tactics (mock ATT&CK-style map); builds the tactic
chain ordered by earliest alert; root cause = earliest tactic; suggests
containment actions per tactic.

What this IS: heuristic tactic mapping + containment suggestions.

What this IS NOT:
* Not causal inference -- rule-based; the host validates.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
MONITOR_30_VERSION = "monitor-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-30.v1"

# Mock tactic map: alert kind -> tactic.
TACTIC_MAP = {
    "phishing_email": "initial_access",
    "drive_by": "initial_access",
    "malware_exec": "execution",
    "suspicious_parent": "execution",
    "priv_escal": "privilege_escalation",
    "persistence": "persistence",
    "c2": "command_and_control",
    "beaconing": "command_and_control",
    "lateral_movement": "lateral_movement",
    "data_staged": "collection",
    "exfil": "exfiltration",
    "ransomware": "impact",
}

# Canonical tactic order for chain display.
TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]

CONTAINMENT = {
    "initial_access": ["block sender/domain", "reset targeted credentials"],
    "execution": ["kill process", "isolate endpoint"],
    "persistence": ["remove persistence mechanism", "reimage if needed"],
    "privilege_escalation": ["revoke sessions", "rotate credentials"],
    "lateral_movement": ["segment network", "isolate affected hosts"],
    "collection": ["restrict data access", "audit access logs"],
    "command_and_control": ["block C2 IPs/domains", "isolate endpoint"],
    "exfiltration": ["block egress", "rotate exposed secrets"],
    "impact": ["isolate systems", "restore from clean backup"],
}


class RcaError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class IncidentAlert:
    kind: str
    entity: str
    ts: float


@dataclass(frozen=True)
class RcaResult:
    root_cause: str
    chain: tuple
    containments: tuple
    coverage: float  # mapped alerts / total alerts


def known_kinds() -> List[str]:
    return sorted(TACTIC_MAP)


def analyze(alerts: List[IncidentAlert]) -> RcaResult:
    """Build tactic chain from alerts."""
    if not alerts:
        raise RcaError("alerts required")
    for a in alerts:
        if not isinstance(a, IncidentAlert):
            raise RcaError("alerts must be IncidentAlert")
        if a.kind not in TACTIC_MAP:
            raise RcaError(f"unknown alert kind {a.kind!r}")
        if a.ts < 0:
            raise RcaError("ts must be >= 0")
    tactics = {TACTIC_MAP[a.kind] for a in alerts}
    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    chain = tuple(sorted(tactics, key=lambda t: order.get(t, 999)))
    # Root cause: tactic of the earliest alert.
    earliest = min(alerts, key=lambda a: a.ts)
    root = TACTIC_MAP[earliest.kind]
    contain: List[str] = []
    for t in chain:
        for c in CONTAINMENT.get(t, []):
            if c not in contain:
                contain.append(c)
    return RcaResult(root, chain, tuple(contain), 1.0)


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
    alerts = [
        IncidentAlert("c2", "h1", 300.0),
        IncidentAlert("phishing_email", "h1", 100.0),
        IncidentAlert("malware_exec", "h1", 200.0),
        IncidentAlert("exfil", "h1", 400.0),
    ]
    r = analyze(alerts)
    assert r.root_cause == "initial_access"
    assert r.chain == ("initial_access", "execution",
                       "command_and_control", "exfiltration")
    assert "block sender/domain" in r.containments
    assert "isolate endpoint" in r.containments
    assert r.coverage == 1.0
    assert "phishing_email" in known_kinds()
    for bad in (
        lambda: analyze([]),
        lambda: analyze([IncidentAlert("nope", "h1", 1.0)]),
        lambda: analyze(["nope"]),  # type: ignore
        lambda: analyze([IncidentAlert("c2", "h1", -1.0)]),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except RcaError:
            pass
    assert stdlib_only()
    print("monitor-30 OK: chain, root cause, containments, fail-closed, stdlib")


if __name__ == "__main__":
    main()
