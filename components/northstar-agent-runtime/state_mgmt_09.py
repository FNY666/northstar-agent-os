"""State 09: backward compatibility (read old formats), Simulated.

The reader supports v1 and v2.  Older writers' output must always
remain readable: parse version, dispatch to the right reader, upgrade
to current in memory.

Fail-closed: unknown version or corrupt payload raises (never guess).
"""

from __future__ import annotations

import ast
from typing import Any, Dict

MODULE_VERSION = "state-mgmt-09.v1"
SCHEMA_PIN = "northstar.state-mgmt-09.v1"
CURRENT = "v2"


class CompatError(Exception):
    pass


def read_v1(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(doc.get("seq"), int):
        raise CompatError("v1.seq must be int")
    return {"seq": doc["seq"], "tool": str(doc.get("tool", ""))}


def read_v2(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(doc.get("seq"), int):
        raise CompatError("v2.seq must be int")
    return {
        "seq": doc["seq"],
        "tool": str(doc.get("tool", "")),
        "policy_version": str(doc.get("policy_version", "unknown")),
    }


_READERS = {"v1": read_v1, "v2": read_v2}


def read(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Read any supported version into the current shape."""
    if not isinstance(doc, dict):
        raise CompatError("doc must be dict")
    ver = doc.get("format_version", "v1")  # default: oldest
    reader = _READERS.get(ver)
    if reader is None:
        raise CompatError(f"unsupported format_version {ver!r}")
    state = reader(doc)
    # Upgrade in memory to current shape.
    state.setdefault("policy_version", "unknown")
    return state


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
    # Old v1 doc, no version field at all.
    assert read({"seq": 1, "tool": "read"})["policy_version"] == "unknown"
    # Explicit v1.
    v1 = read({"format_version": "v1", "seq": 2, "tool": "w"})
    assert v1["seq"] == 2
    # v2 passes through.
    v2 = read({"format_version": "v2", "seq": 3, "tool": "x", "policy_version": "p9"})
    assert v2["policy_version"] == "p9"
    # Unknown version -> fail-closed.
    try:
        read({"format_version": "v99", "seq": 1})
        raise AssertionError("should raise")
    except CompatError:
        pass
    # Corrupt v1.
    try:
        read({"format_version": "v1", "seq": "not-int"})
        raise AssertionError("should raise")
    except CompatError:
        pass
    assert stdlib_only()
    print("state_mgmt_09 OK: reads v1+v2, upgrades, fail-closed")


if __name__ == "__main__":
    main()
