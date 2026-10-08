"""Safe gated output, Integrated.

Combines: tripwire_guardrails + pii_vault + structured_output.
Tripwire screens the action, PII is masked, then the output is schema-validated before release.

What this IS: a three-stage output pipeline: screen, scrub, validate.
What this IS NOT: a replacement for any of the three stages.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Module version.
COMBO_01_VERSION = "combo-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.combo-01.v1"


class ComboError(Exception):
    """Fail-closed integration error."""


def _load(name: str):
    path = Path(__file__).resolve().parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


tw = _load("tripwire_guardrails")
pv = _load("pii_vault")
so = _load("structured_output")


class SafeGatedOutput:
    """Screen -> scrub PII -> validate schema."""

    def __init__(
        self,
        tripwire: Any,
        schema: Any,
        run_id: str = "run-01",
    ) -> None:
        self._tw = tripwire
        self._vault = pv.Vault()
        self._schema = schema
        self._run_id = run_id

    def emit(
        self, tool_name: str, args: Dict[str, Any], output: Dict[str, Any]
    ) -> Dict[str, Any]:
        result = self._tw.check(tool_name, args)
        if result.outcome == tw.TripwireOutcome.HALT:
            raise ComboError(f"tripwire halted {tool_name}")
        scrubbed: Dict[str, Any] = {}
        for key, value in output.items():
            if isinstance(value, str):
                masked, _tokens = self._vault.mask(value, self._run_id)
                scrubbed[key] = masked
            else:
                scrubbed[key] = value
        return so.validate(scrubbed, self._schema)


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



def _test_schema() -> Any:
    return so.VerdictSchema(
        "combo01",
        [
            so.FieldSpec("verdict", "str", True, ["allow", "deny"]),
            so.FieldSpec("note", "str", False),
        ],
    )


def main() -> None:
    tripwire = tw.TripwireGuard(
        "combo01", lambda tool, args: "evil" in str(args).lower()
    )
    pipe = SafeGatedOutput(tripwire, _test_schema())
    out = pipe.emit(
        "summarize",
        {"q": "hello"},
        {"verdict": "allow", "note": "contact alice@example.com"},
    )
    assert out["verdict"] == "allow"
    assert "alice@example.com" not in out["note"]
    try:
        pipe.emit("run", {"q": "evil payload"}, {"verdict": "allow"})
    except ComboError:
        pass
    else:
        raise AssertionError("tripwire should halt")
    assert stdlib_only()
    print("combo-01 OK: screen, scrub, validate")



if __name__ == "__main__":
    main()
