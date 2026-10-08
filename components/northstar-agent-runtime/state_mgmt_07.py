"""State 07: version migration v1 -> v2, Simulated.

v1 state: {"seq": int, "tool": str}
v2 state: {"seq": int, "tool": str, "policy_version": str, "tags": list}

migrate_v1_to_v2 applies additive defaults and validates.
Migration is idempotent: migrating v2 returns it unchanged.

Fail-closed: unknown version, missing required v1 fields raise.
"""

from __future__ import annotations

import ast
from typing import Any, Dict

MODULE_VERSION = "state-mgmt-07.v1"
SCHEMA_PIN = "northstar.state-mgmt-07.v1"
V1 = "northstar-checkpoint.v1"
V2 = "northstar-checkpoint.v2"


class MigrationError(Exception):
    pass


def migrate(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate a versioned checkpoint doc to the latest (v2)."""
    if not isinstance(doc, dict):
        raise MigrationError("doc must be dict")
    ver = doc.get("format_version")
    if ver == V2:
        return doc  # idempotent
    if ver != V1:
        raise MigrationError(f"unsupported format_version {ver!r}")
    state = doc.get("state")
    if not isinstance(state, dict):
        raise MigrationError("state missing or not dict")
    if not isinstance(state.get("seq"), int):
        raise MigrationError("v1.state.seq must be int")
    if not isinstance(state.get("tool"), str):
        raise MigrationError("v1.state.tool must be str")
    new_state = dict(state)
    new_state.setdefault("policy_version", "unknown")
    new_state.setdefault("tags", [])
    return {
        "format_version": V2,
        "created_at": doc.get("created_at", ""),
        "state": new_state,
        "migrated_from": V1,
    }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    v1 = {"format_version": V1, "created_at": "t", "state": {"seq": 1, "tool": "read"}}
    v2 = migrate(v1)
    assert v2["format_version"] == V2
    assert v2["state"]["policy_version"] == "unknown"
    assert v2["state"]["tags"] == []
    assert v2["migrated_from"] == V1
    # Idempotent
    assert migrate(v2) is v2
    # Preserves explicit values
    v1b = {"format_version": V1, "state": {"seq": 2, "tool": "w", "policy_version": "p3"}}
    assert migrate(v1b)["state"]["policy_version"] == "p3"
    # Bad version
    try:
        migrate({"format_version": "v9", "state": {}})
        raise AssertionError("should raise")
    except MigrationError:
        pass
    # Missing seq
    try:
        migrate({"format_version": V1, "state": {"tool": "x"}})
        raise AssertionError("should raise")
    except MigrationError:
        pass
    assert stdlib_only()
    print("state_mgmt_07 OK: v1->v2 migration, idempotent, fail-closed")


if __name__ == "__main__":
    main()
