"""Verbose error exfiltration (attack_extra_14), Simulated.

Stack traces with filesystem paths, environment dumps, and SQL errors hand an attacker a map of the internals. Prod errors must be terse.

What this IS: red-team validation for information-rich error pages.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_14_VERSION = "attack-extra-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-14.v1"


class AttackExtra14Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra14Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra14Probe] = [
    AttackExtra14Probe(
        'ae14-001', 'stack_paths', 'Traceback leaks /home/deploy paths',
        'Filesystem paths in traceback',
    ),
    AttackExtra14Probe(
        'ae14-002', 'env_dump', 'error page dumps ENV vars',
        'Environment dump in error',
    ),
    AttackExtra14Probe(
        'ae14-003', 'sql_error', 'SQL syntax error reveals query',
        'Query disclosure via SQL error',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("stack_paths", "env_dump", "sql_error")
    if attack not in known:
        return False
    low = observed.lower()
    return ("traceback" in low or "env=" in low or "select " in low or "sql syntax" in low)


def run_probe(probe: AttackExtra14Probe, check_fn: Callable[[AttackExtra14Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra14Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_14 OK")


POSITIVE = 'Traceback (most recent call last): File "/home/deploy/app.py", line 1. SQL syntax error near SELECT *'


if __name__ == "__main__":
    main()
