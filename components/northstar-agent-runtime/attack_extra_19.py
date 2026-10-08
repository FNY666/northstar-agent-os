"" "GraphQL introspection abuse (attack_extra_19), Simulated.

Introspection queries dump the full schema in production, guiding targeted field-level attacks. Field suggestions leak names too.

What this IS: red-team validation for introspection enabled in production.

What this IS NOT:
* Not live exploits -- static probes.
* The gate is host-provided.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List

#: Module version.
ATTACK_EXTRA_19_VERSION = "attack-extra-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.attack-extra-19.v1"


class AttackExtra19Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AttackExtra19Probe:
    """One attack probe."""

    probe_id: str
    attack: str
    payload: str
    description: str


PROBES: List[AttackExtra19Probe] = [
    AttackExtra19Probe(
        'ae19-001', 'introspection_query', '{ __schema { queryType { name } } }',
        'Introspection query',
    ),
    AttackExtra19Probe(
        'ae19-002', 'schema_dump', 'full schema returned in prod',
        'Full schema dump',
    ),
    AttackExtra19Probe(
        'ae19-003', 'field_suggest', 'did-you-mean leaks field names',
        'Field-name leakage via suggestions',
    ),
]


def detect(attack: str, observed: str) -> bool:
    """Return True if the attack is detected/blocked from ``observed`` text."""
    known = ("introspection_query", "schema_dump", "field_suggest")
    if attack not in known:
        return False
    low = observed.lower()
    return ("__schema" in observed or "__type" in observed or "querytype" in low or "did you mean" in low)


def run_probe(probe: AttackExtra19Probe, check_fn: Callable[[AttackExtra19Probe], bool]) -> tuple:
    """Run one probe. Returns (blocked, reason)."""
    try:
        blocked = check_fn(probe)
    except Exception:
        return True, "check exception -> fail-closed"
    return bool(blocked), "check decision"


def run_all(check_fn: Callable[[AttackExtra19Probe], bool]) -> Dict[str, Any]:
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
    print("attack_extra_19 OK")


POSITIVE = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'


if __name__ == "__main__":
    main()
