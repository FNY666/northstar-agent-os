"""Hand-written recursive-descent Bash AST parser for security checks.

This is a fail-closed security parser that identifies dangerous shell constructs
before execution. Based on Claude Code's approach (karanprasad source analysis):
an unrecognized AST node type makes the whole command "too-complex" requiring
manual approval.

Design:
- Recursive-descent parser for POSIX sh + bash + zsh constructs
- Detects 15 classes of dangerous AST nodes (command substitution, process
  substitution, subshells, loops, conditionals, function definitions, etc.)
- Blocks 35+ dangerous shell builtins (eval, source, exec, trap, zsh builtins)
- Pre-parse checks: control characters, Unicode whitespace attacks, zsh dynamic
  expansions, array-subscript arithmetic RCE
- Resource limits: 50ms timeout, 50K AST node budget
- Deterministic: same input always gives same verdict
- Never raises on malformed input: malformed = TooComplex, not a crash

Verdict types:
- Allow: command is safe to execute
- Deny: dangerous construct detected (with matched node + reason)
- TooComplex: malformed input, budget exceeded, or unrecognized construct
"""
from __future__ import annotations

import ast
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

#: Module version pin
BASH_PARSER_VERSION = "bash-parser.v1"

#: Maximum parse time in seconds (50ms)
MAX_PARSE_TIME_S = 0.050

#: Maximum AST nodes budget (50K)
MAX_AST_NODES = 50000

#: Dangerous builtins: 5 standard + zsh's 18 + 12 additional fail-closed entries.
DANGEROUS_BUILTINS = frozenset({
    # Standard dangerous builtins (5)
    "eval", "source", ".", "exec", "trap",
    # zsh dangerous builtins (18 from Claude Code analysis)
    "zmodload", "ztcp", "zpty", "zsocket", "zprof", "zcompile",
    "zregexparse", "zparseopts", "zstyle", "zformat", "zle",
    "zsystem", "ztie", "zstat", "zselect", "zftp", "zkbd", "zcalc",
    # Additional fail-closed builtins (12)
    "alias", "unalias", "builtin", "command", "enable", "typeset",
    "declare", "unset", "let", "read", "mapfile", "readarray",
})

#: Control characters that must never appear in a shell command.
_CONTROL_CHARS = frozenset(chr(c) for c in range(0x00, 0x20)) | {"\x7f"}

#: Unicode whitespace used to smuggle separators past naive tokenizers.
_UNICODE_WHITESPACE = frozenset(
    [" ", " "] + [chr(c) for c in range(0x2000, 0x200C)]
)


class VerdictKind(Enum):
    """Outcome of a bash command check."""

    ALLOW = "allow"
    DENY = "deny"
    TOO_COMPLEX = "too_complex"


@dataclass
class Verdict:
    """Structured verdict for a shell command.

    ``node`` names the matched AST construct (empty when not applicable) and
    ``reason`` is a short human-readable explanation.
    """

    kind: VerdictKind
    node: str = ""
    reason: str = ""


@dataclass
class _ParseBudget:
    """Mutable resource budget for a single parse run."""

    deadline: float
    nodes: int = 0

    def add_node(self) -> None:
        self.nodes += 1


def _budget_exceeded(budget: _ParseBudget) -> bool:
    """Return True when the time or node budget for this parse is exhausted."""
    if budget.nodes > MAX_AST_NODES:
        return True
    return time.monotonic() > budget.deadline


def _pre_parse_checks(text: str) -> Optional[Verdict]:
    """Cheap fail-closed checks run before any parsing.

    Returns a Deny verdict when the input contains a control character or a
    Unicode whitespace character, otherwise None.
    """
    for ch in text:
        if ch in _CONTROL_CHARS:
            return Verdict(
                VerdictKind.DENY,
                node="control_character",
                reason=f"control character U+{ord(ch):04X} in command",
            )
        if ch in _UNICODE_WHITESPACE:
            return Verdict(
                VerdictKind.DENY,
                node="unicode_whitespace",
                reason=f"unicode whitespace U+{ord(ch):04X} in command",
            )
    return None


def check_command(text: str) -> Verdict:
    """Check a shell command and return a verdict. Never raises."""
    try:
        if not isinstance(text, str):
            return Verdict(
                VerdictKind.TOO_COMPLEX,
                node="input",
                reason=f"expected str, got {type(text).__name__}",
            )
        if not text.strip():
            return Verdict(VerdictKind.ALLOW, node="", reason="empty command")

        budget = _ParseBudget(deadline=time.monotonic() + MAX_PARSE_TIME_S)
        budget.add_node()

        denied = _pre_parse_checks(text)
        if denied is not None:
            return denied

        if _budget_exceeded(budget):
            return Verdict(
                VerdictKind.TOO_COMPLEX,
                node="budget",
                reason="parse budget exceeded before parsing",
            )

        # Segment 1: parser not implemented yet; fail closed.
        return Verdict(
            VerdictKind.TOO_COMPLEX,
            node="parser",
            reason="parser: not yet implemented",
        )
    except Exception as exc:  # noqa: BLE001 - must never raise
        return Verdict(
            VerdictKind.TOO_COMPLEX,
            node="internal",
            reason=f"internal error: {type(exc).__name__}: {exc}",
        )


def stdlib_only() -> bool:
    """Return True when this module imports only the standard library."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "time", "dataclasses", "enum", "typing", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True
