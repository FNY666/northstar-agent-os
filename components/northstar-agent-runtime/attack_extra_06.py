"" "Time-of-check / time-of-use in gates (attack_extra_06), Simulated.

The gate approves one version of the arguments; a different version executes. File swaps, arg mutation, and redirect changes all exploit the check/use gap.

What this IS: red-team validation for TOCTOU between gate approval and execution.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_06_VERSION = "attack-extra-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-06.v1"


class AttackExtra06Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra06Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra06Probe] = [
    AttackExtra06Probe(
        'ae06-001', 'args_mutated', 'args hash changed after approval',
        'Args mutated post-approval',
    ),
    AttackExtra06Probe(
        'ae06-002', 'file_swapped', 'file swapped between scan and read',
        'File replaced after check',
    ),
    AttackExtra06Probe(
        'ae06-003', 'redirect_swap', 'URL redirected after allowlist check',
        'Redirect target swapped post-check',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    text = observed.lower()
    known = ("args_mutated", "file_swapped", "redirect_swap")
    if attack not in known:
        return False
    if "changed after approval" in text or "swapped" in text:
        return True
    return "hash(check)" in text and "hash(use)" in text and "!=" in text


def run_probe(probe: AttackExtra06Probe, check_fn: Callable[[AttackExtra06Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra06Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_06 OK")


POSITIVE = 'approved with hash(check)=abc; executed with hash(use)=def (!=); args changed after approval'


if __name__ == "__main__":
    main()
