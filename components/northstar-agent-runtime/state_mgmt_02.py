"""State 02: incremental checkpoints (diff-based), Simulated.

Full checkpoints are expensive.  Store a base plus a list of diffs
(op: set/delete on dotted paths).  Replay diffs to reconstruct state.

Fail-closed: invalid ops, bad paths, or replay of a corrupted diff raises.
"""

from __future__ import annotations

import ast
import copy
from dataclasses import dataclass
from typing import Any, Dict, List

MODULE_VERSION = "state-mgmt-02.v1"
SCHEMA_PIN = "northstar.state-mgmt-02.v1"

VALID_OPS = ("set", "delete")


class IncrementalError(Exception):
    pass


@dataclass(frozen=True)
class Diff:
    op: str  # "set" | "delete"
    path: str  # dotted, e.g. "a.b.c"
    value: Any = None  # required for set


def _split_path(path: str) -> List[str]:
    if not isinstance(path, str) or not path.strip():
        raise IncrementalError("path must be non-empty str")
    parts = path.split(".")
    if any(not p for p in parts):
        raise IncrementalError(f"bad path {path!r}")
    return parts


def diff(old: Dict[str, Any], new: Dict[str, Any], prefix: str = "") -> List[Diff]:
    """Compute diffs from old -> new (nested dicts)."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        raise IncrementalError("old/new must be dicts")
    out: List[Diff] = []
    for key in sorted(set(old) | set(new)):
        p = f"{prefix}.{key}" if prefix else key
        if key not in old:
            out.append(Diff("set", p, new[key]))
        elif key not in new:
            out.append(Diff("delete", p))
        else:
            ov, nv = old[key], new[key]
            if isinstance(ov, dict) and isinstance(nv, dict):
                out.extend(diff(ov, nv, p))
            elif ov != nv:
                out.append(Diff("set", p, nv))
    return out


def apply(state: Dict[str, Any], diffs: List[Diff]) -> Dict[str, Any]:
    """Apply diffs to a base state. Returns new state (base untouched)."""
    result = copy.deepcopy(state)
    for d in diffs:
        if d.op not in VALID_OPS:
            raise IncrementalError(f"bad op {d.op!r}")
        parts = _split_path(d.path)
        node = result
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                raise IncrementalError(f"cannot traverse {d.path!r}")
            node = child
        last = parts[-1]
        if d.op == "set":
            node[last] = copy.deepcopy(d.value)
        else:
            node.pop(last, None)
    return result


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "copy", "dataclasses", "pathlib", "typing"}
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
    base = {"a": 1, "nested": {"x": 1, "y": 2}, "gone": True}
    new = {"a": 2, "nested": {"x": 1, "y": 3}}
    ds = diff(base, new)
    assert apply(base, ds) == new
    assert base["a"] == 1  # base untouched
    # Round-trip identity
    assert apply(new, diff(new, new)) == new
    # Bad op
    try:
        apply({}, [Diff("explode", "a")])
        raise AssertionError("should raise")
    except IncrementalError:
        pass
    assert stdlib_only()
    print("state_mgmt_02 OK: diff, apply, fail-closed")


if __name__ == "__main__":
    main()
