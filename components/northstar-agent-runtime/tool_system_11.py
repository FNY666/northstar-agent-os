"""Tool transactions: mock 2PC, Simulated.

Two-phase commit across participants:
- Phase 1 (prepare): all participants vote yes/no.
- Phase 2 (commit/abort): if all yes, commit; else abort.

All in-memory; participants are callables.  Fail-closed: any
prepare failure or exception aborts the transaction.

What this IS: atomic multi-tool commit protocol (mock).

What this IS NOT:
* Not durable -- no write-ahead log, no crash recovery.
* Participants must be idempotent for real use.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List

#: Module version.
TOOL_SYSTEM_11_VERSION = "tool-system-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-11.v1"


class ToolSystem11Error(Exception):
    """Fail-closed."""


class Vote(Enum):
    YES = "yes"
    NO = "no"


@dataclass
class Participant:
    """One 2PC participant."""

    name: str
    prepare: Callable[[], bool]  # True = vote YES
    commit: Callable[[], None]
    abort: Callable[[], None]


@dataclass
class TxnResult:
    committed: bool
    votes: Dict[str, str] = field(default_factory=dict)
    reason: str = ""


def run_2pc(participants: List[Participant]) -> TxnResult:
    """Run two-phase commit.  Returns TxnResult."""
    if not participants:
        raise ToolSystem11Error("no participants")
    votes: Dict[str, str] = {}
    # Phase 1: prepare.
    for p in participants:
        try:
            yes = p.prepare()
        except Exception:
            yes = False  # exception = NO vote
        votes[p.name] = Vote.YES.value if yes else Vote.NO.value
    # Phase 2.
    if all(v == Vote.YES.value for v in votes.values()):
        for p in participants:
            try:
                p.commit()
            except Exception as e:
                # Commit failure after all-YES: best effort abort others.
                for q in participants:
                    try:
                        q.abort()
                    except Exception:
                        pass
                return TxnResult(
                    committed=False, votes=votes,
                    reason=f"commit failed at {p.name}: {type(e).__name__}",
                )
        return TxnResult(committed=True, votes=votes, reason="all committed")
    # Abort path.
    for p in participants:
        try:
            p.abort()
        except Exception:
            pass
    return TxnResult(committed=False, votes=votes, reason="aborted: not all YES")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "enum", "pathlib", "typing"}
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
    log: List[str] = []

    def mk(name: str, yes: bool = True) -> Participant:
        return Participant(
            name=name,
            prepare=lambda: (log.append(f"{name}:prepare"), yes)[1],
            commit=lambda: log.append(f"{name}:commit"),
            abort=lambda: log.append(f"{name}:abort"),
        )

    # All yes -> commit.
    r = run_2pc([mk("a"), mk("b")])
    assert r.committed is True
    assert log == ["a:prepare", "b:prepare", "a:commit", "b:commit"]

    # One no -> abort.
    log.clear()
    r = run_2pc([mk("a"), mk("b", yes=False)])
    assert r.committed is False
    assert "a:abort" in log and "b:abort" in log
    assert "a:commit" not in log

    # Prepare raises -> treated as NO.
    log.clear()
    bad = Participant(
        name="bad",
        prepare=lambda: 1 / 0,  # type: ignore
        commit=lambda: None,
        abort=lambda: log.append("bad:abort"),
    )
    r = run_2pc([mk("a"), bad])
    assert r.committed is False
    assert stdlib_only()
    print("tool_system_11 OK: 2PC, abort, exception-as-no")


if __name__ == "__main__":
    main()
