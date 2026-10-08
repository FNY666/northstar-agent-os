"""JWT confusion attacks (attack_extra_11), Simulated.

alg=none, RS256-verified-as-HS256 with the public key, and kid path traversal. The verifier must pin alg and key per issuer.

What this IS: red-team validation for algorithm and key confusion in JWT verification.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_11_VERSION = "attack-extra-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-11.v1"


class AttackExtra11Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra11Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra11Probe] = [
    AttackExtra11Probe(
        'ae11-001', 'alg_none', 'header {"alg":"none"}',
        'alg=none bypass',
    ),
    AttackExtra11Probe(
        'ae11-002', 'rs_to_hs', 'RS256 token verified as HS256 with public key',
        'RS256->HS256 confusion',
    ),
    AttackExtra11Probe(
        'ae11-003', 'kid_injection', 'kid: "../../etc/passwd"',
        'kid path traversal',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("alg_none", "rs_to_hs", "kid_injection")
    if attack not in known:
        return False
    low = observed.lower()
    if '"alg":"none"' in low or '"alg": "none"' in low:
        return True
    if "rs256" in low and "hs256" in low:
        return True
    return "kid" in low and ("../" in observed or "..\\" in observed)


def run_probe(probe: AttackExtra11Probe, check_fn: Callable[[AttackExtra11Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra11Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_11 OK")


POSITIVE = 'token header {"alg":"none","kid":"../../etc/passwd"} accepted'


if __name__ == "__main__":
    main()
