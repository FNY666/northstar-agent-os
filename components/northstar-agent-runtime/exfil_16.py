"""Blockchain exfiltration detection (mock) (blockchain-mock), Simulated.

Mock detector for chain-based exfiltration: flags oversized OP_RETURN data and sensitive patterns in transaction memos.

What this IS: a mock transaction data-field checker.

What this IS NOT:
* MOCK: analyzes provided tx dicts, no chain access.
* 80-byte OP_RETURN limit is Bitcoin-standard heuristic.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_16_VERSION = "exfil-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-16.v1"


class Exfil16Error(Exception):
    """Fail-closed."""


def detect_blockchain_exfil(tx: Dict[str, Any]) -> tuple:
    """Detect blockchain exfil. tx: {op_return, memo}. Returns (suspicious, reason)."""
    if not isinstance(tx, dict):
        raise Exfil16Error("tx must be dict")
    opret = tx.get("op_return", b"")
    if isinstance(opret, str):
        opret = opret.encode()
    if len(opret) > 80:
        return True, "OP_RETURN %d bytes exceeds 80" % len(opret)
    memo = tx.get("memo", "")
    if isinstance(memo, str):
        for pat, label in [(r"sk-[A-Za-z0-9]{16,}", "API key"), (r"\b\d{3}-\d{2}-\d{4}\b", "SSN")]:
            if re.search(pat, memo):
                return True, "sensitive in memo: %s" % label
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "re"}
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
    ok, _ = detect_blockchain_exfil({"op_return": b"hello", "memo": ""})
    assert ok is False
    ok, _ = detect_blockchain_exfil({"op_return": b"x" * 100})
    assert ok is True
    ok, _ = detect_blockchain_exfil({"memo": "ssn 123-45-6789"})
    assert ok is True
    assert stdlib_only()
    print("exfil-16 OK: mock blockchain, fail-closed")


if __name__ == "__main__":
    main()
