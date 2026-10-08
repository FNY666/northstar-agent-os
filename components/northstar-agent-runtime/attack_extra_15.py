"""Debug endpoint exposure (attack_extra_15), Simulated.

Werkzeug debugger, Django debug toolbar, or DEBUG=True in production gives interactive code execution to anyone who finds it.

What this IS: red-team validation for debug consoles reachable in production.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_15_VERSION = "attack-extra-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-15.v1"


class AttackExtra15Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra15Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra15Probe] = [
    AttackExtra15Probe(
        'ae15-001', 'flask_debugger', 'Werkzeug debugger PIN page exposed',
        'Flask/Werkzeug debugger',
    ),
    AttackExtra15Probe(
        'ae15-002', 'django_toolbar', 'django-debug-toolbar in prod response',
        'Django debug toolbar',
    ),
    AttackExtra15Probe(
        'ae15-003', 'debug_true', 'DEBUG = True disclosed',
        'Debug mode flag exposed',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("flask_debugger", "django_toolbar", "debug_true")
    if attack not in known:
        return False
    low = observed.lower()
    markers = ("werkzeug", "debugger pin", "django-debug-toolbar", "debug = true", "__debug__")
    return any(m in low for m in markers)


def run_probe(probe: AttackExtra15Probe, check_fn: Callable[[AttackExtra15Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra15Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_15 OK")


POSITIVE = 'Werkzeug Debugger PIN: 123-456-789'


if __name__ == "__main__":
    main()
