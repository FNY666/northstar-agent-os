"" "API key leakage via error messages (attack_extra_13), Simulated.

400 bodies, tracebacks, and logs echo back the secret that was just rejected. Errors must never reflect credentials.

What this IS: red-team validation for secrets echoed in error responses.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_13_VERSION = "attack-extra-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-13.v1"


class AttackExtra13Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra13Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra13Probe] = [
    AttackExtra13Probe(
        'ae13-001', 'key_in_400', '400 body echoes api_key value',
        'Key echoed in 400 response',
    ),
    AttackExtra13Probe(
        'ae13-002', 'key_in_traceback', 'traceback prints SECRET_KEY',
        'Key in stack traceback',
    ),
    AttackExtra13Probe(
        'ae13-003', 'key_in_log', 'log line includes token=',
        'Key written to logs',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("key_in_400", "key_in_traceback", "key_in_log")
    if attack not in known:
        return False
    low = observed.lower()
    secret = ("sk-live-", "sk-test-", "api_key=", "secret_key=", "token=")
    if not any(m in low for m in secret):
        return False
    ctx = ("400", "traceback", "error", "log", "exception")
    return any(c in low for c in ctx)


def run_probe(probe: AttackExtra13Probe, check_fn: Callable[[AttackExtra13Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra13Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_13 OK")


POSITIVE = '400 Bad Request: invalid api_key=sk-live-abc123'


if __name__ == "__main__":
    main()
