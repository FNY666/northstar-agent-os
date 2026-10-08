"""Pprof exposure (attack_extra_18), Simulated.

Reachable /debug/pprof/ exposes goroutine dumps (credentials in stack args), heap profiles, and symbol tables.

What this IS: red-team validation for Go pprof endpoints in production.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_18_VERSION = "attack-extra-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-18.v1"


class AttackExtra18Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra18Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra18Probe] = [
    AttackExtra18Probe(
        'ae18-001', 'pprof_index', '/debug/pprof/ index reachable',
        'Pprof index exposed',
    ),
    AttackExtra18Probe(
        'ae18-002', 'goroutine_dump', 'goroutine stack dump downloadable',
        'Goroutine dump',
    ),
    AttackExtra18Probe(
        'ae18-003', 'heap_profile', 'heap profile downloadable',
        'Heap profile exposure',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("pprof_index", "goroutine_dump", "heap_profile")
    if attack not in known:
        return False
    low = observed.lower()
    if "debug/pprof" in low or "goroutine profile" in low or "heap profile" in low:
        return True
    return "pprof" in low and "symbol" in low


def run_probe(probe: AttackExtra18Probe, check_fn: Callable[[AttackExtra18Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra18Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_18 OK")


POSITIVE = '<a href="/debug/pprof/goroutine">goroutine</a> full goroutine stack dump'


if __name__ == "__main__":
    main()
