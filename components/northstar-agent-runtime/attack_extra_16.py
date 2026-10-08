"" "Health check info leakage (attack_extra_16), Simulated.

Health endpoints return versions, dependency lists, and internal hostnames. Attackers use them for targeted CVE selection.

What this IS: red-team validation for over-sharing /healthz endpoints.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_16_VERSION = "attack-extra-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-16.v1"


class AttackExtra16Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra16Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra16Probe] = [
    AttackExtra16Probe(
        'ae16-001', 'version_disclosure', '/healthz returns app+python versions',
        'Version disclosure',
    ),
    AttackExtra16Probe(
        'ae16-002', 'dep_list', '/healthz lists dependency versions',
        'Dependency enumeration',
    ),
    AttackExtra16Probe(
        'ae16-003', 'internal_hosts', '/healthz shows internal hostnames',
        'Internal topology leak',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("version_disclosure", "dep_list", "internal_hosts")
    if attack not in known:
        return False
    low = observed.lower()
    markers = ("python 3", "node v", "dependencies", ".internal", "build_hash", '"version"')
    return any(m in low for m in markers)


def run_probe(probe: AttackExtra16Probe, check_fn: Callable[[AttackExtra16Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra16Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_16 OK")


POSITIVE = '{"status":"ok","version":"2.3.1","python":"3.11.2","host":"api-1.internal"}'


if __name__ == "__main__":
    main()
