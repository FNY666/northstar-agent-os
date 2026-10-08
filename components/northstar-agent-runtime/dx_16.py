"""DX-16: Code actions (mock), Simulated.

IDE code actions (quickfix/refactor/source) offered at a file+line.
`actions_for(file, line)` returns registered actions whose range covers
the position; unknown action kinds and duplicate ids raise.

What this IS: an explicit action catalog keyed by line range.
What this IS NOT: not a real language server.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List

#: Module version.
DX16_ACTIONS_VERSION = "dx-code-actions.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-code-actions.v1"

#: Known action kinds.
KNOWN_KINDS = frozenset({"quickfix", "refactor", "source", "suggest"})


class CodeActionsError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class CodeAction:
    action_id: str
    kind: str
    title: str
    file: str
    line_start: int
    line_end: int

    def covers(self, line: int) -> bool:
        return self.line_start <= line <= self.line_end


class ActionCatalog:
    """Explicit code-action catalog."""

    def __init__(self) -> None:
        self._actions: Dict[str, CodeAction] = {}

    def register(self, action: CodeAction) -> None:
        if not action.action_id or not action.action_id.strip():
            raise CodeActionsError("action_id required")
        if action.kind not in KNOWN_KINDS:
            raise CodeActionsError(f"unknown kind '{action.kind}'")
        if not action.file:
            raise CodeActionsError("file required")
        if action.line_start < 1 or action.line_end < action.line_start:
            raise CodeActionsError("invalid line range")
        if action.action_id in self._actions:
            raise CodeActionsError(f"duplicate action_id '{action.action_id}'")
        self._actions[action.action_id] = action

    def actions_for(self, file: str, line: int) -> List[CodeAction]:
        if not file:
            raise CodeActionsError("file required")
        if line < 1:
            raise CodeActionsError("line must be >= 1")
        return sorted(
            (a for a in self._actions.values()
             if a.file == file and a.covers(line)),
            key=lambda a: a.action_id,
        )

    def kinds(self) -> List[str]:
        return sorted(KNOWN_KINDS)

    @property
    def count(self) -> int:
        return len(self._actions)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    cat = ActionCatalog()
    cat.register(CodeAction("q1", "quickfix", "Add import", "a.py", 1, 3))
    cat.register(CodeAction("r1", "refactor", "Extract fn", "a.py", 2, 5))
    acts = cat.actions_for("a.py", 2)
    assert [a.action_id for a in acts] == ["q1", "r1"]
    assert cat.actions_for("a.py", 10) == []
    assert cat.actions_for("b.py", 2) == []
    assert cat.count == 2
    try:
        cat.register(CodeAction("bad", "nope", "X", "a.py", 1, 1))
        raise AssertionError("should raise")
    except CodeActionsError:
        pass
    try:
        cat.register(CodeAction("q1", "quickfix", "dup", "a.py", 1, 1))
        raise AssertionError("should raise")
    except CodeActionsError:
        pass
    assert stdlib_only()
    print("dx_16 OK: catalog, range filter, kind/dupe validation")


if __name__ == "__main__":
    main()
