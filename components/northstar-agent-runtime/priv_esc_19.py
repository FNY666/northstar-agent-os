"""Priv-esc probe 19: vm-escape, Simulated.

Mock VM-escape detector: simulates a hypervisor boundary check that flags hypercall-like escape attempts. Fully mocked; no real VM or hypervisor interaction.

Detection-only probe. NOT an exploit. Used to test whether gates block
privilege-escalation attempts of this technique. Contains no exploit
code and cannot be used to escalate privileges.

What this IS: a mocked VM-boundary check for hypercall escape indicators
What this IS NOT: not an exploit; patterns and safe read-only checks only.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Tuple

#: Module version.
PRIV_ESC_19_VERSION = "priv-esc-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.priv-esc-19.v1"


class PrivEscError(Exception):
    """Fail-closed: bad inputs raise."""


# Regex patterns indicating this technique.
_PATTERNS = [
    '\\bhypercall\\b',
    '\\bvmcall\\b',
    'virtio.*escape',
    'vm_escape',
    'hv_\\w*escape',
]

def mock_vm_boundary_check(guest_action: str) -> Tuple[bool, str]:
    """Mock VM boundary: flags hypercall-like escape attempts.

    Simulates a hypervisor boundary check. Detection only; no real VM.
    """
    if not isinstance(guest_action, str):
        raise PrivEscError("guest_action must be str")
    for _pattern in _PATTERNS:
        if re.search(_pattern, guest_action, re.IGNORECASE):
            return True, "mock VM boundary: escape attempt detected"
    return False, "mock VM boundary: clean"



def detect(text: str) -> Tuple[bool, str]:
    """Detect the technique in text. Returns (found, reason)."""
    if not isinstance(text, str):
        raise PrivEscError("text must be str")
    for _pattern in _PATTERNS:
        if re.search(_pattern, text, re.IGNORECASE):
            return True, "pattern: " + _pattern
    return _custom_detect(text)


def _custom_detect(text: str) -> Tuple[bool, str]:
    return mock_vm_boundary_check(text)


def scan_args(tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
    """Scan tool args. Returns (blocked, reason)."""
    if not isinstance(args, dict):
        raise PrivEscError("args must be dict")
    _text = " ".join(str(_v) for _v in args.values())
    _found, _reason = detect(_text)
    if _found:
        return True, tool_name + ": " + _reason
    return False, "clean"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    _tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    _allowed = {"__future__", "ast", "re", "pathlib", "typing"}
    for _node in ast.walk(_tree):
        if isinstance(_node, ast.Import):
            for _alias in _node.names:
                if _alias.name.split(".")[0] not in _allowed:
                    return False
        elif isinstance(_node, ast.ImportFrom):
            if _node.module and _node.module.split(".")[0] not in _allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    _found, _ = detect('issue hypercall 0x42 to escape')
    assert _found is True, "should detect positive example"
    _found, _ = detect('virtual machine snapshot')
    assert _found is False, "should not flag negative example"
    _b, _ = mock_vm_boundary_check("issue hypercall 0x99")
    assert _b is True
    _b, _ = mock_vm_boundary_check("normal guest block io")
    assert _b is False

    assert stdlib_only()
    print("priv-esc-19 OK: detect, fail-closed, stdlib")


if __name__ == "__main__":
    main()
