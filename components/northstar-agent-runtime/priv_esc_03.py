"""Priv-esc probe 03: symlink-attack, Simulated.

Detects symlink-attack indicators (ln -s, symlink()) and provides a safe read-only is_symlink() check for TOCTOU-safe path validation.

Detection-only probe. NOT an exploit. Used to test whether gates block
privilege-escalation attempts of this technique. Contains no exploit
code and cannot be used to escalate privileges.

What this IS: symlink indicator patterns plus a read-only islink check
What this IS NOT: not an exploit; patterns and safe read-only checks only.
"""

from __future__ import annotations

import ast
import re
import os
from typing import Any, Dict, List, Tuple

#: Module version.
PRIV_ESC_03_VERSION = "priv-esc-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.priv-esc-03.v1"


class PrivEscError(Exception):
    """Fail-closed: bad inputs raise."""


# Regex patterns indicating this technique.
_PATTERNS = [
    '\\bln\\s+-s',
    'symlink\\s*\\(',
    'readlink',
]

import os


def is_symlink(path: str) -> bool:
    """Safe read-only check: True if path is a symlink."""
    try:
        return os.path.islink(path)
    except OSError:
        return False



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
    _allowed = {"__future__", "ast", "re", "pathlib", "typing", "os", "tempfile"}
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
    _found, _ = detect('ln -s /etc/passwd /tmp/x')
    assert _found is True, "should detect positive example"
    _found, _ = detect('ln /a /b')
    assert _found is False, "should not flag negative example"
    import os as _os
    import tempfile as _tf

    with _tf.TemporaryDirectory() as _d:
        _t = _os.path.join(_d, "t")
        _l = _os.path.join(_d, "l")
        open(_t, "w").write("x")
        _os.symlink(_t, _l)
        assert is_symlink(_l) is True
        assert is_symlink(_t) is False

    assert stdlib_only()
    print("priv-esc-03 OK: detect, fail-closed, stdlib")


if __name__ == "__main__":
    main()
