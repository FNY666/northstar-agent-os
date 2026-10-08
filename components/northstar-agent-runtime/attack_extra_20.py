"""WebSocket hijacking (attack_extra_20), Simulated.

Missing Origin checks allow cross-site upgrades; tokens in the WS URL leak via logs and proxies. The upgrade must validate origin and use header auth.

What this IS: red-team validation for origin and auth flaws in WS upgrade.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_20_VERSION = "attack-extra-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-20.v1"


class AttackExtra20Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra20Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra20Probe] = [
    AttackExtra20Probe(
        'ae20-001', 'no_origin_check', 'handshake accepted with no Origin',
        'Missing origin validation',
    ),
    AttackExtra20Probe(
        'ae20-002', 'token_in_url', 'wss://host/ws?token=secret',
        'Auth token in WS URL',
    ),
    AttackExtra20Probe(
        'ae20-003', 'csrf_upgrade', 'cross-site upgrade succeeded',
        'Cross-site WS upgrade (CSRF)',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("no_origin_check", "token_in_url", "csrf_upgrade")
    if attack not in known:
        return False
    low = observed.lower()
    if "no origin" in low or "origin not checked" in low:
        return True
    if "token=" in low and ("ws://" in low or "wss://" in low):
        return True
    return "cross-site" in low and "upgrade" in low


def run_probe(probe: AttackExtra20Probe, check_fn: Callable[[AttackExtra20Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra20Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_20 OK")


POSITIVE = 'handshake accepted; no origin check; wss://host/ws?token=secret123'


if __name__ == "__main__":
    main()
