"""DX-06: Interactive tutorials (mock), Simulated.

Step-based tutorials: each step has an instruction, an expected
answer (checked by a predicate), and a hint.  The learner advances
only when the checker accepts the answer; wrong answers return the
hint and do not advance.

Fail-closed: answering a finished tutorial raises; empty steps raise
at construction.

What this IS: scripted, checkable learning steps with progress.
What this IS NOT: not a real interactive UI.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

#: Module version.
DX06_TUTORIAL_VERSION = "dx-tutorial.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-tutorial.v1"


class TutorialError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Step:
    title: str
    instruction: str
    hint: str = ""


@dataclass(frozen=True)
class StepResult:
    step: int
    correct: bool
    message: str
    done: bool


class Tutorial:
    """A checkable interactive tutorial."""

    def __init__(
        self,
        name: str,
        steps: List[Step],
        checkers: List[Callable[[str], bool]],
    ) -> None:
        if not name or not name.strip():
            raise TutorialError("name required")
        if not steps:
            raise TutorialError("steps must be non-empty")
        if len(steps) != len(checkers):
            raise TutorialError("steps and checkers must align")
        self._name = name
        self._steps = list(steps)
        self._checkers = list(checkers)
        self._pos = 0
        self._attempts: List[int] = [0] * len(steps)

    @property
    def name(self) -> str:
        return self._name

    @property
    def current_step(self) -> Optional[Step]:
        return self._steps[self._pos] if self._pos < len(self._steps) else None

    @property
    def progress(self) -> Dict[str, int]:
        return {"done": self._pos, "total": len(self._steps)}

    def answer(self, text: str) -> StepResult:
        """Submit an answer for the current step."""
        if self._pos >= len(self._steps):
            raise TutorialError("tutorial already complete")
        self._attempts[self._pos] += 1
        try:
            ok = bool(self._checkers[self._pos](text))
        except Exception:
            ok = False
        if ok:
            self._pos += 1
            done = self._pos >= len(self._steps)
            return StepResult(step=self._pos, correct=True,
                              message="correct!", done=done)
        step = self._steps[self._pos]
        hint = f" hint: {step.hint}" if step.hint else ""
        return StepResult(step=self._pos, correct=False,
                          message=f"not quite.{hint}", done=False)

    @property
    def attempts(self) -> List[int]:
        return list(self._attempts)


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
    tut = Tutorial(
        "gates 101",
        [Step("allow", "type 'allow'", "the word allow"),
         Step("deny", "type 'deny'", "the word deny")],
        [lambda t: t.strip() == "allow", lambda t: t.strip() == "deny"],
    )
    r = tut.answer("nope")
    assert not r.correct and not r.done and "hint" in r.message
    assert tut.progress == {"done": 0, "total": 2}
    r = tut.answer("allow")
    assert r.correct and not r.done
    r = tut.answer("deny")
    assert r.correct and r.done
    try:
        tut.answer("deny")
        raise AssertionError("should raise")
    except TutorialError:
        pass
    assert tut.attempts == [2, 1]
    assert stdlib_only()
    print("dx_06 OK: steps, checkers, hints, progress, fail-closed")


if __name__ == "__main__":
    main()
