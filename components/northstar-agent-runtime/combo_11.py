"""Replayable audit, Integrated.

Combines: task_snapshot + interleaved_thinking + provenance_tagging.
Each recorded action requires reasoning, carries a provenance tag, and lands in a hash-sealed task snapshot.

What this IS: an audit trail where every step is justified and sourced.
What this IS NOT: a tamper-proof log without external anchoring.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_11_VERSION = "combo-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-11.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


ts = _load("task_snapshot")
it = _load("interleaved_thinking")
pt = _load("provenance_tagging")


class ReplayableAudit:
    """Require reasoning -> tag provenance -> snapshot."""

    def __init__(self, snapshot_id: str = "audit-11", prompt: str = "") -> None:
        self._snapshot = ts.TaskSnapshot(snapshot_id, prompt, {})
        self._tags: List[Any] = []

    def record(
        self,
        reasoning: Optional[str],
        tool_id: str,
        args: Dict[str, Any],
        result: Any,
        gate_decision: str,
    ) -> Dict[str, Any]:
        action = it.require_reasoning(reasoning, tool_id, args)
        tagged = pt.tag_tool_output(result, tool_id)
        self._tags.append(tagged)
        self._snapshot.add_tool_call(tool_id, args, result, gate_decision)
        return {
            "action": action,
            "tagged": tagged,
            "snapshot_hash": self._snapshot.snapshot_hash(),
            "calls": len(self._snapshot.tool_calls),
        }

    def combined_provenance(self) -> Any:
        if not self._tags:
            raise ComboError("nothing recorded")
        return pt.combine(*self._tags)

    @property
    def snapshot(self) -> Any:
        return self._snapshot


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "collections", "dataclasses", "hashlib",
        "importlib", "json", "pathlib", "re", "sys", "typing",
    }
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
    audit = ReplayableAudit()
    r = audit.record("need data", "read", {"p": "/x"}, "content", "allow")
    assert r["calls"] == 1
    assert r["snapshot_hash"].startswith("sha256:")
    audit.record("need more", "read", {"p": "/y"}, "more", "allow")
    combined = audit.combined_provenance()
    assert "read" in set(combined.deps)
    try:
        audit.record(None, "read", {}, "x", "allow")
    except it.InterleavedError:
        pass
    else:
        raise AssertionError("missing reasoning should fail")
    assert stdlib_only()
    print("combo-11 OK: reason, tag, snapshot")



if __name__ == "__main__":
    main()
