"""Layered injection defense, Integrated.

Combines: spotlighting + injection_probe + confidence_gate.
Spotlight delimiters mark untrusted data, the injection probe suite calibrates the gate, and the confidence gate makes the final call.

What this IS: defense in depth against prompt injection: mark, measure, decide.
What this IS NOT: a guarantee against novel injection techniques.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_03_VERSION = "combo-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-03.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


sp = _load("spotlighting")
ip = _load("injection_probe")
cg = _load("confidence_gate")


class LayeredInjectionDefense:
    """Mark data, calibrate with probes, gate on confidence."""

    def __init__(self, min_confidence: int = 70) -> None:
        self._gate = cg.ConfidenceGate()
        self._min_confidence = min_confidence

    def mark(self, tool_output: str) -> Dict[str, str]:
        marked, nonce = sp.spotlight(tool_output)
        return {"marked": marked, "nonce": nonce}

    def calibrate(self, gate_fn: Callable[..., bool]) -> Dict[str, Any]:
        return ip.run_all_probes(gate_fn)

    def decide(
        self, confidence: int, tool_risk: str = "low"
    ) -> Dict[str, Any]:
        verdict = self._gate.check(confidence, tool_risk)
        allowed = verdict.action == "allow" and confidence >= self._min_confidence
        return {"verdict": verdict, "allowed": allowed}


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
    defense = LayeredInjectionDefense()
    marked = defense.mark("result from tool")
    assert marked["nonce"] in marked["marked"]
    cal = defense.calibrate(lambda *a: True)
    assert cal["block_rate"] == 1.0
    cal2 = defense.calibrate(lambda *a: False)
    assert cal2["block_rate"] == 0.0
    ok = defense.decide(95, "low")
    assert ok["allowed"] is True
    bad = defense.decide(20, "high")
    assert bad["allowed"] is False
    assert stdlib_only()
    print("combo-03 OK: mark, calibrate, decide")



if __name__ == "__main__":
    main()
