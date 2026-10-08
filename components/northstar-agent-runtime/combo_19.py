"""Multi-turn immune, Integrated.

Combines: crescendo_probe + stateful_veto + confidence_gate.
Each turn is gated on confidence, violations feed the stateful veto, and the trajectory score catches slow escalations.

What this IS: multi-turn defense: per-turn gate plus trajectory judgment.
What this IS NOT: a model-level refusal mechanism.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_19_VERSION = "combo-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-19.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


cp = _load("crescendo_probe")
sv = _load("stateful_veto")
cg = _load("confidence_gate")


class MultiTurnImmune:
    """Per-turn confidence gate -> stateful risk -> trajectory score."""

    def __init__(
        self,
        trajectory_threshold: float = 0.7,
        session_id: str = "sess-19",
    ) -> None:
        self._stateful = sv.StatefulVeto()
        self._gate = cg.ConfidenceGate()
        self._threshold = trajectory_threshold
        self._session = session_id

    def run_turns(
        self,
        script: Any,
        turn_gate: Callable[[str], bool],
        trajectory_scorer: Callable[[List[str]], float],
        confidences: List[int] = None,
    ) -> Dict[str, Any]:
        stopped_turn: Optional[int] = None
        stop_reason = ""
        for i, turn in enumerate(script.turns):
            try:
                blocked = bool(turn_gate(turn.prompt))
            except Exception:
                blocked = True
            conf = confidences[i] if confidences and i < len(confidences) else 50
            verdict = self._gate.check(conf, "medium")
            if blocked or verdict.action == "deny":
                self._stateful.record_deny(self._session, f"turn-{turn.turn}")
                limited, _ = self._stateful.should_rate_limit(
                    self._session, "crescendo"
                )
                stopped_turn = turn.turn
                stop_reason = "rate_limited" if limited else "turn_blocked"
                break
        scored = (
            script.turns[:stopped_turn] if stopped_turn else script.turns
        )
        trajectory = cp.score_trajectory(scored, trajectory_scorer)
        trajectory_blocked = trajectory >= self._threshold
        if trajectory_blocked and stopped_turn is None:
            stop_reason = "trajectory"
        return {
            "stopped": stopped_turn is not None or trajectory_blocked,
            "stopped_turn": stopped_turn,
            "stop_reason": stop_reason,
            "trajectory": trajectory,
            "risk": self._stateful.risk_score(self._session),
        }


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
    immune = MultiTurnImmune()
    script = cp.SCRIPTS[0]
    # Trajectory-only defense: per-turn gates pass, scorer flags escalation.
    r = immune.run_turns(
        script,
        lambda prompt: False,
        lambda prompts: 0.95,
        [90, 90, 90, 90, 90],
    )
    assert r["stopped"] is True and r["stop_reason"] == "trajectory"
    # Per-turn block records risk.
    immune2 = MultiTurnImmune()
    r2 = immune2.run_turns(
        script, lambda prompt: "verbatim" in prompt, lambda prompts: 0.0, [90] * 5
    )
    assert r2["stopped"] is True and r2["risk"] > 0
    # Benign conversation passes.
    immune3 = MultiTurnImmune()
    r3 = immune3.run_turns(
        script, lambda prompt: False, lambda prompts: 0.1, [95] * 5
    )
    assert r3["stopped"] is False
    assert stdlib_only()
    print("combo-19 OK: per-turn gate, risk, trajectory")



if __name__ == "__main__":
    main()
