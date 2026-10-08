"" "DNS rebinding for tool endpoints (attack_extra_09), Simulated.

A hostname passes the allowlist, then DNS re-resolves to an internal IP (or the cloud metadata address). The fetch must re-validate the resolved IP.

What this IS: red-team validation for post-approval DNS re-resolution.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_09_VERSION = "attack-extra-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-09.v1"


class AttackExtra09Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra09Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra09Probe] = [
    AttackExtra09Probe(
        'ae09-001', 'rebind_after_approval', 'approved 93.184.216.34 -> fetch 169.254.169.254',
        'DNS re-resolved post-approval',
    ),
    AttackExtra09Probe(
        'ae09-002', 'ttl_zero', 'TTL 0 forces re-resolve to 127.0.0.1',
        'Zero-TTL rebinding',
    ),
    AttackExtra09Probe(
        'ae09-003', 'metadata_ip', 'resolved to 169.254.169.254',
        'Cloud metadata IP target',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    text = observed.lower()
    known = ("rebind_after_approval", "ttl_zero", "metadata_ip")
    if attack not in known:
        return False
    internal = ("169.254.169.254", "127.0.0.1", "10.", "192.168.", "172.16.")
    return any(ip in text for ip in internal)


def run_probe(probe: AttackExtra09Probe, check_fn: Callable[[AttackExtra09Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra09Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_09 OK")


POSITIVE = 'approved example.com -> 93.184.216.34; fetch re-resolved to 169.254.169.254'


if __name__ == "__main__":
    main()
