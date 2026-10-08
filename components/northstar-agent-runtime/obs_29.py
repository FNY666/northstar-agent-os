"""obs_29: Game days (mock), Simulated.

GameDay(name, participants, injects): schedule() returns injects
sorted by minute; record_response() logs a participant's response to
an inject; score() reports injects resolved/total, average response
delay, and participant count.  Mock: injects are schedule entries,
no live orchestration.

Fail-closed: duplicate participant or out-of-range inject index raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Tuple

OBS29_VERSION = "obs-29.v1"
SCHEMA_PIN = "northstar.obs-29.v1"


class Obs29Error(Exception):
    """Fail-closed."""


class GameDay:
    """Mock game-day session with failure injects."""

    def __init__(
        self,
        name: str,
        participants: List[str],
        injects: List[Tuple[int, str, str]],
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise Obs29Error("name must be a non-empty string")
        if not isinstance(participants, list) or not participants:
            raise Obs29Error("participants must be a non-empty list")
        seen = set()
        for p in participants:
            if not isinstance(p, str) or not p.strip():
                raise Obs29Error("participants must be non-empty strings")
            if p in seen:
                raise Obs29Error(f"duplicate participant '{p}'")
            seen.add(p)
        if not isinstance(injects, list) or not injects:
            raise Obs29Error("injects must be a non-empty list of (at_minute, description, expected_action)")
        for inj in injects:
            if not isinstance(inj, (list, tuple)) or len(inj) != 3:
                raise Obs29Error("each inject must be (at_minute, description, expected_action)")
            at_minute, description, expected_action = inj
            if not isinstance(at_minute, int) or at_minute < 0:
                raise Obs29Error("at_minute must be a non-negative int")
            if not isinstance(description, str) or not description.strip():
                raise Obs29Error("inject description must be a non-empty string")
            if not isinstance(expected_action, str) or not expected_action.strip():
                raise Obs29Error("inject expected_action must be a non-empty string")
        self.name = name
        self.participants = list(participants)
        self.injects = list(injects)
        self._responses: List[Dict[str, Any]] = []

    def schedule(self) -> List[Dict[str, Any]]:
        """Return injects sorted by minute."""
        return [
            {
                "index": i,
                "at_minute": at_minute,
                "description": description,
                "expected_action": expected_action,
            }
            for i, (at_minute, description, expected_action) in enumerate(
                sorted(self.injects, key=lambda inj: inj[0])
            )
        ]

    def record_response(
        self,
        at_minute: int,
        inject_idx: int,
        action_taken: str,
        resolved: bool,
        participant: str = "",
    ) -> None:
        """Log a response to an inject (inject_idx refers to the sorted schedule)."""
        if not isinstance(inject_idx, int) or inject_idx < 0 or inject_idx >= len(self.injects):
            raise Obs29Error(f"inject_idx {inject_idx} out of range")
        if not isinstance(at_minute, int) or at_minute < 0:
            raise Obs29Error("at_minute must be a non-negative int")
        if not isinstance(action_taken, str) or not action_taken.strip():
            raise Obs29Error("action_taken must be a non-empty string")
        if not isinstance(resolved, bool):
            raise Obs29Error("resolved must be bool")
        scheduled = sorted(self.injects, key=lambda inj: inj[0])
        inject_at = scheduled[inject_idx][0]
        if at_minute < inject_at:
            raise Obs29Error("response cannot be recorded before the inject fires")
        if participant and participant not in self.participants:
            raise Obs29Error(f"unknown participant '{participant}'")
        self._responses.append(
            {
                "inject_idx": inject_idx,
                "at_minute": at_minute,
                "action_taken": action_taken,
                "resolved": resolved,
                "participant": participant,
                "delay": at_minute - inject_at,
            }
        )

    def score(self) -> Dict[str, Any]:
        """Score the game day: resolved/total, avg delay, participant count."""
        total = len(self.injects)
        resolved_idxs = {r["inject_idx"] for r in self._responses if r["resolved"]}
        delays = [r["delay"] for r in self._responses]
        avg_delay = sum(delays) / len(delays) if delays else None
        return {
            "name": self.name,
            "injects_total": total,
            "injects_resolved": len(resolved_idxs),
            "responses": len(self._responses),
            "avg_response_delay_min": avg_delay,
            "participants": len(self.participants),
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
    gd = GameDay(
        "payments-gameday",
        ["alice", "bob"],
        [(30, "db primary down", "promote replica"), (10, "cache poisoned", "flush cache")],
    )
    sched = gd.schedule()
    assert [s["at_minute"] for s in sched] == [10, 30]
    # sorted order: idx 0 = cache (min 10), idx 1 = db (min 30)
    gd.record_response(12, 0, "flushed cache", True, participant="alice")
    gd.record_response(40, 1, "replica promoted", False, participant="bob")
    sc = gd.score()
    assert sc["injects_total"] == 2 and sc["injects_resolved"] == 1
    assert sc["avg_response_delay_min"] == (2 + 10) / 2
    assert sc["participants"] == 2

    try:
        GameDay("g", ["alice", "alice"], [(5, "x", "y")])
        raise AssertionError("should raise")
    except Obs29Error:
        pass
    try:
        gd.record_response(15, 7, "x", True)
        raise AssertionError("should raise")
    except Obs29Error:
        pass
    try:
        gd.record_response(5, 0, "x", True)
        raise AssertionError("should raise")
    except Obs29Error:
        pass
    try:
        gd.record_response(12, 0, "x", True, participant="carol")
        raise AssertionError("should raise")
    except Obs29Error:
        pass
    try:
        GameDay("", ["a"], [(5, "x", "y")])
        raise AssertionError("should raise")
    except Obs29Error:
        pass
    assert stdlib_only()
    print("obs_29 OK")


if __name__ == "__main__":
    main()
