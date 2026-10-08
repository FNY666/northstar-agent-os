"""Metrics endpoint exfiltration (attack_extra_17), Simulated.

Prometheus-style metrics with high-cardinality labels (emails, paths, key fragments) turn an observability endpoint into a data leak.

What this IS: red-team validation for PII and secrets in /metrics labels.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_17_VERSION = "attack-extra-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-17.v1"


class AttackExtra17Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra17Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra17Probe] = [
    AttackExtra17Probe(
        'ae17-001', 'label_pii', 'label user="a@b.com" in /metrics',
        'PII in metric labels',
    ),
    AttackExtra17Probe(
        'ae17-002', 'internal_paths', 'backup_path="/var/backups" label',
        'Internal paths in metrics',
    ),
    AttackExtra17Probe(
        'ae17-003', 'key_label', 'api_key="sk-..." as label value',
        'Secret in label value',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("label_pii", "internal_paths", "key_label")
    if attack not in known:
        return False
    low = observed.lower()
    if "@" in observed and "{" in observed:
        return True
    return "/var/" in observed or "sk-" in low


def run_probe(probe: AttackExtra17Probe, check_fn: Callable[[AttackExtra17Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra17Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_17 OK")


POSITIVE = 'http_requests_total{user="alice@example.com"} 42'


if __name__ == "__main__":
    main()
