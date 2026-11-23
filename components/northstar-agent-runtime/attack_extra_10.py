"""Subdomain takeover for webhooks (attack_extra_10), Simulated.

A webhook points at a subdomain whose DNS dangles to an unclaimed service (Heroku, S3, Pages). Whoever claims it receives the webhooks.

What this IS: red-team validation for dangling webhook subdomains.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_10_VERSION = "attack-extra-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-10.v1"


class AttackExtra10Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra10Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra10Probe] = [
    AttackExtra10Probe(
        'ae10-001', 'dangling_cname', 'hooks.example.com CNAME evil.herokuapp.com',
        'Dangling CNAME to Heroku',
    ),
    AttackExtra10Probe(
        'ae10-002', 'expired_s3', 'CNAME to deleted S3 bucket',
        'Expired S3 bucket claim',
    ),
    AttackExtra10Probe(
        'ae10-003', 'unclaimed_pages', 'CNAME to unclaimed github.io',
        'Unclaimed Pages site',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    text = observed.lower()
    known = ("dangling_cname", "expired_s3", "unclaimed_pages")
    if attack not in known:
        return False
    if "cname" not in text:
        return False
    claimable = ("herokuapp.com", "s3.amazonaws.com", "github.io", "azurewebsites.net", "nxdomain", "unclaimed")
    return any(c in text for c in claimable)


def run_probe(probe: AttackExtra10Probe, check_fn: Callable[[AttackExtra10Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra10Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_10 OK")


POSITIVE = 'cname hooks.example.com -> evil-user.herokuapp.com (nxdomain, unclaimed)'


if __name__ == "__main__":
    main()
