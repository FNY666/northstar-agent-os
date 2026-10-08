"""Priv-esc probe 04: toctou-race, Simulated.

Mock TOCTOU detector: simulates check-then-use with an attacker swap in between. Flags when file identity differs between check time and use time. Fully mocked; no real files.

Detection-only probe. NOT an exploit. Used to test whether gates block
privilege-escalation attempts of this technique. Contains no exploit
code and cannot be used to escalate privileges.

What this IS: a mocked check/use race simulator for TOCTOU education and gate testing
What this IS NOT: not an exploit; patterns and safe read-only checks only.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Tuple

#: Module version.
PRIV_ESC_04_VERSION = "priv-esc-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.priv-esc-04.v1"


class PrivEscError(Exception):
    """Fail-closed: bad inputs raise."""


# Regex patterns indicating this technique.
_PATTERNS = [
    '\\btoctou\\b',
    'time.of.check.*time.of.use',
]

class MockCheckedFile:
    """Mock TOCTOU: simulates check-then-use with an attacker swap in between.

    No real files are touched. Detection logic only.
    """

    def __init__(self) -> None:
        self._check_sig: str | None = None
        self._use_sig: str = "sig-ok"

    def attacker_swap(self, new_sig: str) -> None:
        """Mock attacker changes the file between check and use."""
        self._use_sig = new_sig

    def check(self) -> str:
        """Record the file identity at check time."""
        self._check_sig = self._use_sig
        return self._check_sig

    def use(self) -> Tuple[bool, str]:
        """Use the file; detect whether it changed since check."""
        if self._check_sig is None:
            raise PrivEscError("use() before check()")
        if self._check_sig != self._use_sig:
            return True, "TOCTOU race: file changed between check and use"
        return False, "no race detected"



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
    _found, _ = detect('toctou race on /tmp/f')
    assert _found is True, "should detect positive example"
    _found, _ = detect('normal file access')
    assert _found is False, "should not flag negative example"
    _f = MockCheckedFile()
    _f.check()
    _ok, _ = _f.use()
    assert _ok is False
    _f.check()
    _f.attacker_swap("sig-evil")
    _raced, _ = _f.use()
    assert _raced is True

    assert stdlib_only()
    print("priv-esc-04 OK: detect, fail-closed, stdlib")


if __name__ == "__main__":
    main()
