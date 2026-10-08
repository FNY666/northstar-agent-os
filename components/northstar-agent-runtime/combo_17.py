"""Confidence-calibrated output, Integrated.

Combines: confidence_gate + structured_output + pii_vault.
Output is released only if confidence clears the gate, then schema-validated, then PII-scrubbed.

What this IS: calibrated, validated, scrubbed output.
What this IS NOT: a fix for an overconfident model.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_17_VERSION = "combo-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-17.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


cg = _load("confidence_gate")
so = _load("structured_output")
pv = _load("pii_vault")


class ConfidenceCalibratedOutput:
    """Confidence -> schema -> PII scrub."""

    def __init__(self, schema: Any, run_id: str = "run-17") -> None:
        self._gate = cg.ConfidenceGate()
        self._schema = schema
        self._vault = pv.Vault()
        self._run_id = run_id

    def produce(
        self, output: Dict[str, Any], confidence: int, tool_risk: str = "low"
    ) -> Dict[str, Any]:
        verdict = self._gate.check(confidence, tool_risk)
        if verdict.action == "deny":
            raise ComboError(f"confidence denied: {verdict.reason}")
        validated = so.validate(output, self._schema)
        scrubbed: Dict[str, Any] = {}
        for key, value in validated.items():
            if isinstance(value, str):
                masked, _tokens = self._vault.mask(value, self._run_id)
                scrubbed[key] = masked
            else:
                scrubbed[key] = value
        return {"verdict": verdict, "output": scrubbed}


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



def _schema():
    return so.VerdictSchema(
        "c17", [so.FieldSpec("answer", "str", True), so.FieldSpec("note", "str", False)]
    )


def main() -> None:
    prod = ConfidenceCalibratedOutput(_schema())
    r = prod.produce({"answer": "yes", "note": "mail bob@example.com"}, 95, "low")
    assert r["output"]["answer"] == "yes"
    assert "bob@example.com" not in r["output"]["note"]
    try:
        prod.produce({"answer": "yes"}, 5, "high")
    except ComboError:
        pass
    else:
        raise AssertionError("low confidence should fail")
    try:
        prod.produce({"wrong": 1}, 95, "low")
    except Exception:
        pass
    else:
        raise AssertionError("bad schema should fail")
    assert stdlib_only()
    print("combo-17 OK: confidence, schema, scrub")



if __name__ == "__main__":
    main()
