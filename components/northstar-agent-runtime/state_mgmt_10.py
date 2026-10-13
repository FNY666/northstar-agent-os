"""State 10: forward compatibility (ignore unknown fields), Simulated.

Newer writers may emit fields this reader doesn't know.  The reader
must ignore unknown fields and never fail on them — but it must NOT
silently accept unknown REQUIRED semantics.

Rule: unknown fields are dropped with a logged warning list; known
fields are validated strictly.

Fail-closed: known fields with bad types still raise.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Tuple

MODULE_VERSION = "state-mgmt-10.v1"
SCHEMA_PIN = "northstar.state-mgmt-10.v1"

KNOWN: Dict[str, type] = {"seq": int, "tool": str, "policy_version": str}


class ForwardCompatError(Exception):
    pass


def read(doc: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Read doc, dropping unknown fields.

    Returns (known_state, dropped_field_names).
    """
    if not isinstance(doc, dict):
        raise ForwardCompatError("doc must be dict")
    known: Dict[str, Any] = {}
    dropped: List[str] = []
    for k, v in doc.items():
        if k in KNOWN:
            exp = KNOWN[k]
            if exp is int and isinstance(v, bool):
                raise ForwardCompatError(f"{k!r} must be int, not bool")
            if not isinstance(v, exp):
                raise ForwardCompatError(f"{k!r} must be {exp.__name__}")
            known[k] = v
        else:
            dropped.append(k)
    if "seq" not in known:
        raise ForwardCompatError("missing required field 'seq'")
    return known, dropped


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
    # Newer writer added fields this reader doesn't know.
    doc = {"seq": 5, "tool": "r", "future_field": [1, 2], "another": {"x": 1}}
    known, dropped = read(doc)
    assert known == {"seq": 5, "tool": "r"}
    assert sorted(dropped) == ["another", "future_field"]
    # Known field with bad type still fails.
    try:
        read({"seq": "five"})
        raise AssertionError("should raise")
    except ForwardCompatError:
        pass
    # Missing required.
    try:
        read({"tool": "x"})
        raise AssertionError("should raise")
    except ForwardCompatError:
        pass
    assert stdlib_only()
    print("state_mgmt_10 OK: ignores unknown, strict on known, fail-closed")


if __name__ == "__main__":
    main()
