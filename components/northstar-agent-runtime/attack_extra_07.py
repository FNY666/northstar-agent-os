"" "Race conditions in approval (attack_extra_07), Simulated.

Two approvals race, or an approval lands after withdrawal. The approval state machine must be atomic: exactly one terminal state per request.

What this IS: red-team validation for concurrent approval/withdrawal races.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_07_VERSION = "attack-extra-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-07.v1"


class AttackExtra07Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra07Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra07Probe] = [
    AttackExtra07Probe(
        'ae07-001', 'double_submit', 'two approvals submitted concurrently',
        'Concurrent double approval',
    ),
    AttackExtra07Probe(
        'ae07-002', 'approve_after_withdraw', 'approval landed after withdrawal',
        'Approval after withdrawal',
    ),
    AttackExtra07Probe(
        'ae07-003', 'concurrent_mutate', 'args mutated while approval pending',
        'Mutation during pending approval',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    text = observed.lower()
    known = ("double_submit", "approve_after_withdraw", "concurrent_mutate")
    if attack not in known:
        return False
    if "duplicate" in text:
        return True
    if "approved" in text and "withdrawn" in text:
        return True
    return "while pending" in text and "mutat" in text


def run_probe(probe: AttackExtra07Probe, check_fn: Callable[[AttackExtra07Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra07Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_07 OK")


POSITIVE = 'approval #1 approved; approval #2 approved (duplicate); request withdrawn then approved'


if __name__ == "__main__":
    main()
