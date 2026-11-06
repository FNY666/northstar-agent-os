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

Implementation segments:
- Segment 1: verdict types, pre-parse checks, budgets (done)
- Segment 2: tokenizer + simple commands (done) -- this segment recognizes a
  single simple command only: leading VAR=value assignments, a command word,
  arguments, and literal > >> < 2> redirections. Every other construct
  (pipelines, lists, subshells, command/process/arithmetic expansion,
  non-plain parameter expansion) is TooComplex, never Allow.
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


# ---------------------------------------------------------------------------
# Segment 2: tokenizer
# ---------------------------------------------------------------------------

#: Characters that terminate a word and start an operator token.
_OP_CHARS = frozenset("|&;<>()")

#: Redirection operators this segment understands.
_REDIRECT_OPS = frozenset({"<", ">", ">>", "2>"})

#: Multi-character operators, matched longest-first.
_MULTI_OPS = ("||", "&&", ">>", "|&", ";;", "&>", "<&", ">&", "<>", "<<")


def _is_name(text: str) -> bool:
    """Return True when *text* is a plain ASCII shell identifier."""
    if not text:
        return False
    first = text[0]
    if not (first == "_" or "a" <= first <= "z" or "A" <= first <= "Z"):
        return False
    for ch in text[1:]:
        if not (
            ch == "_"
            or "a" <= ch <= "z"
            or "A" <= ch <= "Z"
            or "0" <= ch <= "9"
        ):
            return False
    return True


class _Reject(Exception):
    """Internal fail-closed signal; converted to TooComplex at the boundary."""

    def __init__(self, node: str, reason: str) -> None:
        super().__init__(reason)
        self.node = node
        self.reason = reason


@dataclass(frozen=True)
class _Token:
    """A single lexical token.

    ``kind`` is ``"word"`` or ``"op"``. ``plain`` is True when the word had no
    quoting, escapes or expansions (required for redirection targets).
    ``assign_name`` is the literal text before the first unquoted ``=`` in the
    word, or None when the word is not in assignment form.
    """

    kind: str
    value: str
    plain: bool = True
    assign_name: Optional[str] = None


def _scan_dollar(text: str, i: int, buf: list[str]) -> int:
    """Consume a ``$`` form starting at *i*; append its literal text to *buf*.

    Only ``$VAR`` and ``${VAR}`` with plain names are accepted. Every other
    dollar form is deferred to a later segment and rejected as TooComplex.
    Returns the index just past the consumed text.
    """
    n = len(text)
    if i + 1 >= n:
        raise _Reject("dollar", "dangling $ at end of command")
    nxt = text[i + 1]
    if nxt == "(":
        if text.startswith("$((", i):
            raise _Reject("arithmetic_expansion", "$(( )) arithmetic expansion")
        raise _Reject("command_substitution", "$( ) command substitution")
    if nxt == "{":
        close = text.find("}", i + 2)
        if close < 0:
            raise _Reject("parameter_expansion", "unbalanced ${")
        name = text[i + 2:close]
        if not _is_name(name):
            raise _Reject(
                "parameter_expansion", f"non-plain ${{{name}}} expansion"
            )
        buf.append("$" + name)
        return close + 1
    if _is_name(nxt):
        j = i + 1
        while j < n:
            ch = text[j]
            if not (ch == "_" or ch.isascii() and ch.isalnum()):
                break
            j += 1
        name = text[i + 1:j]
        buf.append("$" + name)
        return j
    raise _Reject("dollar", f"unsupported $ form ${nxt}")


def _scan_double(text: str, i: int, buf: list[str], budget: _ParseBudget) -> int:
    """Consume a double-quoted string starting at *i* into *buf*.

    Returns the index just past the closing quote; raises _Reject when the
    quote is unbalanced or hides an expansion this segment cannot parse.
    """
    n = len(text)
    j = i + 1
    while j < n:
        if _budget_exceeded(budget):
            raise _Reject("budget", "parse budget exceeded in double quotes")
        ch = text[j]
        if ch == '"':
            return j + 1
        if ch == "`":
            raise _Reject("command_substitution", "backtick command substitution")
        if ch == "\\":
            if j + 1 >= n:
                raise _Reject("escape", "trailing backslash in double quotes")
            buf.append(text[j + 1])
            j += 2
            continue
        if ch == "$":
            j = _scan_dollar(text, j, buf)
            continue
        buf.append(ch)
        j += 1
    raise _Reject("quote", "unbalanced double quote")


def _tokenize(text: str, budget: _ParseBudget) -> list[_Token]:
    """Split *text* into word and operator tokens.

    Raises _Reject (fail-closed) for any construct outside this segment.
    """
    tokens: list[_Token] = []
    i, n = 0, len(text)
    while i < n:
        if _budget_exceeded(budget):
            raise _Reject("budget", "parse budget exceeded while tokenizing")
        ch = text[i]
        if ch in " \t":
            i += 1
            continue
        if ch == "`":
            raise _Reject("command_substitution", "backtick command substitution")
        if text.startswith("<(", i) or text.startswith(">(", i):
            raise _Reject(
                "process_substitution", f"process substitution {text[i:i + 2]}"
            )
        if ch in "()":
            raise _Reject("subshell", "subshell or grouping parenthesis")
        if ch.isdigit():
            j = i
            while j < n and text[j].isdigit():
                j += 1
            if j < n and text[j] in "<>":
                digits = text[i:j]
                if digits != "2" or text[j] != ">" or text.startswith("2>>", i):
                    raise _Reject(
                        "redirection", f"unsupported fd redirection {text[i:j + 1]}"
                    )
                tokens.append(_Token("op", "2>"))
                budget.add_node()
                i = j + 1
                continue
        if ch in _OP_CHARS:
            for op in _MULTI_OPS:
                if text.startswith(op, i):
                    tokens.append(_Token("op", op))
                    budget.add_node()
                    i += len(op)
                    break
            else:
                tokens.append(_Token("op", ch))
                budget.add_node()
                i += 1
            continue

        # ---- word ----
        buf: list[str] = []
        plain = True
        prefix_literal = True
        eq_at: Optional[int] = None
        while i < n:
            ch = text[i]
            if ch in " \t" or ch in _OP_CHARS:
                break
            if _budget_exceeded(budget):
                raise _Reject("budget", "parse budget exceeded in word")
            if ch == "`":
                raise _Reject(
                    "command_substitution", "backtick command substitution"
                )
            if ch == "\\":
                plain = False
                prefix_literal = False
                if i + 1 >= n:
                    raise _Reject("escape", "trailing backslash")
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == "'":
                plain = False
                prefix_literal = False
                close = text.find("'", i + 1)
                if close < 0:
                    raise _Reject("quote", "unbalanced single quote")
                buf.append(text[i + 1:close])
                i = close + 1
                continue
            if ch == '"':
                plain = False
                prefix_literal = False
                i = _scan_double(text, i, buf, budget)
                continue
            if ch == "$":
                plain = False
                prefix_literal = False
                i = _scan_dollar(text, i, buf)
                continue
            if ch == "=" and eq_at is None and prefix_literal:
                eq_at = len(buf)
            buf.append(ch)
            i += 1

        value = "".join(buf)
        if not value:
            raise _Reject("word", "empty word")
        if value.startswith("~") and value != "~" and not value.startswith("~/"):
            raise _Reject("tilde_expansion", f"zsh-style tilde expansion {value!r}")
        if value.startswith("="):
            raise _Reject("equals_expansion", f"zsh-style equals expansion {value!r}")
        assign_name = None if eq_at is None else "".join(buf[:eq_at])
        tokens.append(
            _Token("word", value, plain=plain, assign_name=assign_name)
        )
        budget.add_node()
    return tokens


# ---------------------------------------------------------------------------
# Segment 2: simple commands
# ---------------------------------------------------------------------------


def _parse_simple_command(tokens: list[_Token], budget: _ParseBudget) -> Verdict:
    """Parse one simple command: assignments, command word, args, redirections.

    Raises _Reject for anything that is not a single simple command.
    """
    argv: list[str] = []
    redirections: list[tuple[str, str]] = []
    i, n = 0, len(tokens)
    while i < n:
        if _budget_exceeded(budget):
            raise _Reject("budget", "parse budget exceeded while parsing")
        budget.add_node()
        tok = tokens[i]
        if tok.kind == "op":
            if tok.value in _REDIRECT_OPS:
                if i + 1 >= n:
                    raise _Reject(
                        "redirection", f"missing target after {tok.value!r}"
                    )
                target = tokens[i + 1]
                if target.kind != "word" or not target.plain or not target.value:
                    raise _Reject(
                        "redirection",
                        f"non-literal target after {tok.value!r}",
                    )
                redirections.append((tok.value, target.value))
                i += 2
                continue
            raise _Reject("operator", f"unsupported operator {tok.value!r}")

        if not argv and tok.assign_name is not None:
            if not _is_name(tok.assign_name):
                raise _Reject(
                    "assignment",
                    f"invalid env assignment name {tok.assign_name!r}",
                )
            i += 1
            continue

        argv.append(tok.value)
        i += 1

    if argv and argv[0] in DANGEROUS_BUILTINS:
        return Verdict(
            VerdictKind.DENY,
            node=argv[0],
            reason=f"dangerous builtin {argv[0]!r}",
        )
    return Verdict(
        VerdictKind.ALLOW,
        node="simple_command",
        reason="simple command",
    )


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

        tokens = _tokenize(text, budget)
        if not tokens:
            return Verdict(VerdictKind.ALLOW, node="", reason="empty command")
        return _parse_simple_command(tokens, budget)
    except _Reject as reject:
        return Verdict(
            VerdictKind.TOO_COMPLEX,
            node=reject.node,
            reason=reject.reason,
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
