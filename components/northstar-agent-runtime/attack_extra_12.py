"" "OAuth scope escalation (attack_extra_12), Simulated.

The authorization server (or a confused client) grants more scopes than requested: write added to read, offline_access smuggled in, or a wildcard.

What this IS: red-team validation for granted scopes exceeding the request.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_12_VERSION = "attack-extra-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-12.v1"


class AttackExtra12Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra12Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra12Probe] = [
    AttackExtra12Probe(
        'ae12-001', 'scope_creep', 'requested read, granted read write',
        'Granted scopes exceed requested',
    ),
    AttackExtra12Probe(
        'ae12-002', 'offline_added', 'offline_access added silently',
        'Silent offline_access grant',
    ),
    AttackExtra12Probe(
        'ae12-003', 'wildcard', 'granted: *',
        'Wildcard scope grant',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    text = observed.lower()
    known = ("scope_creep", "offline_added", "wildcard")
    if attack not in known:
        return False
    parts = text.split("|")
    req = next((p for p in parts if "requested:" in p), "")
    grant = next((p for p in parts if "granted:" in p), "")
    req_scopes = set(req.replace("requested:", "").split())
    grant_scopes = set(grant.replace("granted:", "").split())
    if not grant_scopes:
        return False
    if "*" in grant_scopes or "admin" in grant_scopes:
        return True
    return not grant_scopes.issubset(req_scopes)


def run_probe(probe: AttackExtra12Probe, check_fn: Callable[[AttackExtra12Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra12Probe], bool]) -> Dict[str, Any]:
    """Run all probes through ``check_fn``. Returns block summary."""
    results = []
    blocked = 0
    for probe in PROBES:
        is_blocked, reason = run_probe(probe, check_fn)
        results.append(
            {
                "probe_id": probe.probe_id,
                "attack": probe.attack,
                "blocked": is_blocked,
                "reason": reason,
            }
        )
        if is_blocked:
            blocked += 1
    return {
        "probes": results,
        "blocked": blocked,
        "total": len(PROBES),
        "block_rate": blocked / len(PROBES) if PROBES else 0.0,
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
    for probe in PROBES:
        assert detect(probe.attack, POSITIVE) is True, probe.probe_id
    assert detect("unknown_attack", "hello world") is False
    assert stdlib_only()
    print("attack_extra_12 OK")


POSITIVE = 'requested: read | granted: read write'


if __name__ == "__main__":
    main()
