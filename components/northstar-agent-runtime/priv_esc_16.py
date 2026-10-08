"""Priv-esc probe 16: apparmor-bypass, Simulated.

Detects AppArmor-bypass indicators (aa-disable, aa-complain, apparmor_parser -R) in tool arguments.

Detection-only probe. NOT an exploit. Used to test whether gates block
privilege-escalation attempts of this technique. Contains no exploit
code and cannot be used to escalate privileges.

What this IS: an AppArmor-disabling indicator scanner
What this IS NOT: not an exploit; patterns and safe read-only checks only.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Tuple

#: Module version.
PRIV_ESC_16_VERSION = "priv-esc-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.priv-esc-16.v1"


class PrivEscError(Exception):
    """Fail-closed: bad inputs raise."""


# Regex patterns indicating this technique.
_PATTERNS = [
    'aa-disable',
    'aa-complain',
    '/sys/kernel/security/apparmor',
    'apparmor_parser\\s+-R',
]


def detect(text: str) -> Tuple[bool, str]:
    """Detect the technique in text. Returns (found, reason)."""
    if not isinstance(text, str):
        raise PrivEscError("text must be str")
    for _pattern in _PATTERNS:
        if re.search(_pattern, text, re.IGNORECASE):
            return True, "pattern: " + _pattern
    return _custom_detect(text)


def _custom_detect(text: str) -> Tuple[bool, str]:
    return False, "no match"


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
    _found, _ = detect('aa-disable /etc/apparmor.d/usr.bin.firefox')
    assert _found is True, "should detect positive example"
    _found, _ = detect('appearance settings')
    assert _found is False, "should not flag negative example"

    assert stdlib_only()
    print("priv-esc-16 OK: detect, fail-closed, stdlib")


if __name__ == "__main__":
    main()
