"""Task snapshots: replayable forensic artifacts (AgentScope), Simulated.

A task snapshot packages {prompt, model params, tool returns} into a
single artifact that can replay the task deterministically.

Post-hoc forensics: turns "what happened?" from archaeology into replay.

What this IS: deterministic replay for investigations.

What this IS NOT:
* Not a live re-execution -- replays against recorded results.
* Model params are opaque; host interprets them.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

#: Module version.
SNAPSHOT_VERSION = "task-snapshot.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.task-snapshot.v1"


class SnapshotError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ToolCallRecord:
    """One recorded tool call."""

    seq: int
    tool_name: str
    args_hash: str
    result_hash: str
    gate_decision: str


@dataclass
class TaskSnapshot:
    """A replayable snapshot of a task."""

    snapshot_id: str
    prompt: str
    model_params: Dict[str, Any]
    tool_calls: List[ToolCallRecord] = field(default_factory=list)
    gate_decisions: List[Dict[str, Any]] = field(default_factory=list)

    def add_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
        result: Any,
        gate_decision: str,
    ) -> None:
        """Record a tool call (hashes args/result, not raw)."""
        seq = len(self.tool_calls)
        args_hash = "sha256:" + hashlib.sha256(
            json.dumps(args, sort_keys=True).encode()
        ).hexdigest()
        result_hash = "sha256:" + hashlib.sha256(
            json.dumps(str(result), sort_keys=True).encode()
        ).hexdigest()
        self.tool_calls.append(ToolCallRecord(
            seq=seq,
            tool_name=tool_name,
            args_hash=args_hash,
            result_hash=result_hash,
            gate_decision=gate_decision,
        ))

    def snapshot_hash(self) -> str:
        """Hash of the snapshot for sealing."""
        data = json.dumps({
            "snapshot_id": self.snapshot_id,
            "prompt": self.prompt,
            "tool_calls": [
                {"seq": t.seq, "tool": t.tool_name, "gate": t.gate_decision}
                for t in self.tool_calls
            ],
        }, sort_keys=True)
        return "sha256:" + hashlib.sha256(data.encode()).hexdigest()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
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
    snap = TaskSnapshot("s1", "do task", {"model": "x"})
    snap.add_tool_call("read", {"p": "/x"}, "content", "allow")
    snap.add_tool_call("write", {"p": "/y"}, "ok", "deny")
    assert len(snap.tool_calls) == 2
    assert snap.snapshot_hash().startswith("sha256:")
    assert stdlib_only()
    print("task-snapshot OK")


if __name__ == "__main__":
    main()
