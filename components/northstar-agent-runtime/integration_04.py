"""Integration I-004: PII vault + structured output (vault-aware output), Simulated.

Gate verdicts must be schema-valid AND PII-masked before crossing the
trust boundary.  emit() masks every string field in the verdict, then
validates against the schema.  demask() restores on return.

What this IS: schema + masking in one call.
What this IS NOT: not the NER -- regex patterns from pii_vault.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Module version.
INTEGRATION_04_VERSION = "integration-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-04.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_pii = _load("pii_vault")
_structured = _load("structured_output")


class IntegrationError(Exception):
    """Fail-closed."""


class VaultAwareOutput:
    """Emits schema-valid, PII-masked verdicts."""

    def __init__(self, vault: Any, run_id: str) -> None:
        if vault is None:
            raise IntegrationError("vault required")
        if not run_id:
            raise IntegrationError("run_id required")
        self._vault = vault
        self._run_id = run_id

    def emit(
        self, verdict: Dict[str, Any], schema: Any
    ) -> Dict[str, Any]:
        """Mask PII in string fields, then validate the schema."""
        if not isinstance(verdict, dict):
            raise IntegrationError("verdict must be dict")
        masked: Dict[str, Any] = {}
        for key, value in verdict.items():
            if isinstance(value, str):
                m, _ = self._vault.mask(value, self._run_id)
                masked[key] = m
            else:
                masked[key] = value
        return _structured.validate(masked, schema)

    def demask(
        self, text: str, allowed_types: Optional[List[str]] = None
    ) -> str:
        """Restore masked tokens (viewer-permission scoped)."""
        return self._vault.demask(text, self._run_id, allowed_types)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
        "typing",
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
    """Self-check."""
    out = VaultAwareOutput(_pii.Vault(), "run1")
    v = out.emit(
        {
            "verdict": "allow",
            "reason": "sent to john@example.com",
            "tool": "send",
        },
        _structured.GATE_VERDICT_SCHEMA,
    )
    assert "john@example.com" not in v["reason"]
    assert "[EMAIL_0]" in v["reason"]
    assert v["verdict"] == "allow"

    # Schema violations still fail-closed.
    try:
        out.emit(
            {"verdict": "allow", "reason": "x"},
            _structured.GATE_VERDICT_SCHEMA,
        )
        raise AssertionError("should raise")
    except _structured.StructuredOutputError:
        pass

    # Demask restores.
    assert "john@example.com" in out.demask(v["reason"])

    assert stdlib_only()
    print("integration-04 OK: vault-aware output, schema, stdlib")


if __name__ == "__main__":
    main()
