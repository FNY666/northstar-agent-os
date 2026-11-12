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
- Two caps: wrapper nesting depth and a resolved-argv budget, the latter
  measured after the wrapper layers are stripped
- Deterministic: same input always gives same verdict
- Never raises on malformed input: malformed = TooComplex, not a crash

Verdict types:
- Allow: command is safe to execute
- Deny: dangerous construct detected (with matched node + reason)
- TooComplex: malformed input, budget exceeded, or unrecognized construct

Implementation segments:
- Segment 1: verdict types, pre-parse checks, budgets (done)
- Segment 2: tokenizer + simple commands (done)
- Segment 3: command lists/pipelines, substitution and subshell Deny (done)
- Segment 4: loops, conditionals, function definitions, arithmetic, brace and
  zsh expansions, array-subscript arithmetic, variable indirection (done)
- Segment 7: wrapper unwrapping (sudo and friends) and the two caps --
  wrapper depth plus a resolved-argv budget measured after the unwrap;
  anything unresolvable is denied, never passed
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

#: External commands that are dangerous when passed unquoted variable expansions.
#: Derived from DEFAULT_SHELL_DENYLIST in permissions.py (catastrophic-only patterns).
#: Only actual command names are included here; patterns like ":(){", "of=/dev/",
#: "| sh", etc. are lexical shapes, not command names.
DANGEROUS_EXTERNAL_COMMANDS = frozenset({
    "rm",    # rm -rf / variants in denylist
    "mkfs",  # filesystem formatting
})

#: All dangerous commands: builtins + external commands where unquoted variable
#: expansion in argument position is denied (word-splitting can inject flags).
DANGEROUS_COMMANDS = DANGEROUS_BUILTINS | DANGEROUS_EXTERNAL_COMMANDS

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
    argv_words: int = 0

    def add_node(self) -> None:
        self.nodes += 1

    def charge_argv(self, words: int) -> None:
        """Charge *words* against the resolved-argv budget."""
        self.argv_words += words


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

#: Operators that separate elements of a top-level command list.
_LIST_OPS = frozenset({";", "&", "&&", "||", "|", "|&"})

#: Reserved words that introduce a compound command, mapped to the Deny node.
_KEYWORD_NODES = {
    "for": "loop",
    "while": "loop",
    "until": "loop",
    "if": "conditional",
    "then": "conditional",
    "elif": "conditional",
    "else": "conditional",
    "fi": "conditional",
    "case": "conditional",
    "esac": "conditional",
    "[[": "conditional",
    "]]": "conditional",
    "function": "function_definition",
}


# ---------------------------------------------------------------------------
# Segment 7: wrapper unwrapping and the two caps
# ---------------------------------------------------------------------------
# A depth cap on its own is a sieve: a wide command slips under it, and a
# semicolon chain never enters an unwrap loop at all.  The parser therefore
# enforces two caps at the same time:
#
#   * MAX_WRAPPER_DEPTH -- nesting depth of the wrapper layers
#   * MAX_ARGV_BUDGET  -- charged argv words of the whole command
#
# The budget is computed *after* unwrapping, because stripping a wrapper
# changes the count: a budget measured before the unwrap measures the wrong
# command.  When the command cannot be resolved (unknown wrapper option,
# unresolved command word, unbounded argument source) the verdict is DENY --
# never ALLOW, and never a "presume safe" pass.

#: Maximum nesting depth of wrapper layers around a command.
MAX_WRAPPER_DEPTH = 4

#: Maximum charged argv words for one command (all list elements summed).
MAX_ARGV_BUDGET = 512

#: Words charged for a word whose runtime shape is unknown: an unquoted
#: expansion or a glob can turn one parsed word into many runtime words.
MAX_UNRESOLVED_WORDS = 32

#: Commands that only decorate another command.  They are stripped before any
#: command-shape check, so the budget measures the command that really runs.
#: "command" and "exec" are deliberately absent: both are denied builtins.
#: The set mirrors permissions.py::_SHELL_COMMAND_WRAPPERS.
UNWRAP_WRAPPERS = frozenset({
    "sudo", "doas", "env", "nice", "nohup", "stdbuf", "time", "timeout",
    "xargs",
})

#: Wrapper options that take no value.
_WRAPPER_FLAGS = {
    "sudo": frozenset({
        "-n", "--non-interactive", "-H", "--set-home", "-b", "--background",
        "-E", "--preserve-env", "-k", "--remove-timestamp", "-r", "--chroot",
        "-s", "--shell", "-l", "--login", "-A", "--askpass", "-S", "--stdin",
        "-v", "--validate", "-V", "--version", "--help",
    }),
    "doas": frozenset({
        "-n", "--non-interactive", "-L", "--loose", "-s", "--shell",
        "--help", "--version",
    }),
    "env": frozenset({
        "-i", "--ignore-environment", "-0", "--null", "-v", "--debug",
        "--help", "--version",
    }),
    "nice": frozenset({"--help", "--version"}),
    "nohup": frozenset({"--help", "--version"}),
    "stdbuf": frozenset({"--help", "--version"}),
    "time": frozenset({
        "-p", "--portability", "-q", "--quiet", "-v", "--verbose",
        "--help", "--version",
    }),
    "timeout": frozenset({
        "-f", "--foreground", "--preserve-status", "-v", "--verbose",
        "--help", "--version",
    }),
    "xargs": frozenset({
        "-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose",
        "--help", "--version",
    }),
}

#: Wrapper options that take a value (short letters and long names).
_WRAPPER_VALUE_OPTIONS = {
    "sudo": frozenset({
        "-u", "-g", "-h", "-p", "-C", "-T", "-R", "-D",
        "--user", "--group", "--host", "--prompt",
    }),
    "doas": frozenset({"-u", "--user"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "nohup": frozenset(),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "time": frozenset({"-o", "--output", "-f", "--format"}),
    "timeout": frozenset({"-k", "--kill-after", "-s", "--signal"}),
    "xargs": frozenset({
        "-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file",
        "--delimiter", "--eof", "--replace", "--max-lines", "--max-args",
        "--max-procs", "--max-chars",
    }),
}

#: Glob metacharacters: a word containing one may expand to many words.
_GLOB_CHARS = "*?["

#: Wrapper options that run shell source rather than a command; never resolvable.
_WRAPPER_DENY_OPTIONS = {
    "env": frozenset({"-S", "--split-string"}),
}


def _is_negative_number(word: str) -> bool:
    """Return True for option-looking words that are really negative numbers."""
    body = word[1:]
    if not body:
        return False
    if body[0] in "0123456789":
        return True
    return body[0] == "." and body[1:].isdigit()


def _classify_wrapper_option(wrapper: str, word: str) -> str:
    """Classify a wrapper option as ``flag``, ``value`` or ``value-inline``.

    ``value`` means the option consumes the following word, ``value-inline``
    means the value is attached to the option (``--user=root``, ``-uroot``).
    An option that is not in the wrapper's known tables is ``unknown``: we
    cannot tell whether it takes a value, so the command word cannot be
    resolved.
    """
    flags = _WRAPPER_FLAGS.get(wrapper, frozenset())
    value_opts = _WRAPPER_VALUE_OPTIONS.get(wrapper, frozenset())
    if word.startswith("--"):
        name = word.split("=", 1)[0]
        if name in value_opts:
            return "value-inline" if "=" in word else "value"
        if name in flags:
            return "flag"
        return "unknown"
    body = word[1:]
    for position, ch in enumerate(body):
        option = "-" + ch
        if option in value_opts:
            return "value-inline" if position + 1 < len(body) else "value"
        if option in flags:
            continue
        return "unknown"
    return "flag"


def _strip_wrapper(
    wrapper: str, rest: list[tuple[str, _Token]]
) -> Optional[list[tuple[str, _Token]]]:
    """Return the words that follow *wrapper*'s own options and its command.

    ``rest`` is the word list after the wrapper name.  Returns the words
    that follow the wrapped command word, or None when the wrapper is
    itself the command (``env`` with no target).  Raises _Deny when the
    wrapper cannot be resolved to a single command word.
    """
    deny_opts = _WRAPPER_DENY_OPTIONS.get(wrapper, frozenset())
    index = 0
    total = len(rest)
    while index < total:
        word, token = rest[index]
        if word == "--":
            index += 1
            break
        if word.startswith("-") and len(word) > 1:
            if wrapper == "nice" and _is_negative_number(word):
                index += 1
                continue
            if not _is_negative_number(word):
                if token.unquoted_expansion or "$" in word:
                    raise _Deny(
                        "unresolved_wrapper",
                        f"unresolved option {word!r} in {wrapper}",
                    )
                if token.has_glob:
                    raise _Deny(
                        "unresolved_wrapper",
                        f"unresolved option {word!r} in {wrapper}",
                    )
                if word in deny_opts or word.split("=", 1)[0] in deny_opts:
                    raise _Deny(
                        "unresolved_wrapper",
                        f"option {word!r} in {wrapper} runs shell source",
                    )
                kind = _classify_wrapper_option(wrapper, word)
                if kind == "unknown":
                    raise _Deny(
                        "unresolved_wrapper",
                        f"unknown option {word!r} in {wrapper}",
                    )
                if kind == "value":
                    index += 1
                    if index >= total:
                        raise _Deny(
                            "unresolved_wrapper",
                            f"option {word!r} in {wrapper} has no value",
                        )
                    value_word, value_token = rest[index]
                    if value_token.unquoted_expansion or "$" in value_word:
                        raise _Deny(
                            "unresolved_wrapper",
                            f"unresolved value {value_word!r} for option "
                            f"{word!r} in {wrapper}",
                        )
                    if value_token.has_glob:
                        raise _Deny(
                            "unresolved_wrapper",
                            f"unresolved value {value_word!r} for option "
                            f"{word!r} in {wrapper}",
                        )
                index += 1
                continue
        break

    # Leading assignments set environment variables, they are not the command.
    while index < total and rest[index][1].assign_name is not None:
        index += 1

    if wrapper == "timeout":
        # The first positional argument of timeout is always the duration.
        if index >= total:
            raise _Deny("unresolved_wrapper", "timeout without a command")
        index += 1
    if wrapper == "xargs":
        # xargs appends an unbounded number of words read from stdin, so the
        # final argv is not bounded by what the command text shows.
        raise _Deny(
            "unresolved_wrapper",
            "xargs appends an unbounded number of words from stdin",
        )
    if index >= total:
        if wrapper == "env":
            # `env` with no target only prints the environment.
            return None
        raise _Deny("unresolved_wrapper", f"{wrapper} without a command")
    return rest[index:]


def _unwrap_command(
    argv: list[str], argv_tokens: list[_Token]
) -> tuple[list[str], list[_Token], int]:
    """Strip wrapper layers and return the command that really runs.

    Returns ``(argv, tokens, depth)`` for the resolved command.  Raises
    _Deny when the wrapper stack is deeper than the cap or when the command
    word cannot be resolved.
    """
    words = list(zip(argv, argv_tokens))
    depth = 0
    while words:
        head_value, head_token = words[0]
        if head_value not in UNWRAP_WRAPPERS:
            break
        depth += 1
        if depth > MAX_WRAPPER_DEPTH:
            raise _Deny(
                "wrapper_depth",
                f"wrapper nesting depth {depth} exceeds cap {MAX_WRAPPER_DEPTH}",
            )
        tail = _strip_wrapper(head_value, words[1:])
        if tail is None:
            words = [(head_value, head_token)]
            break
        words = tail
    if not words:
        raise _Deny("unresolved_command", "no command word after unwrapping")
    command_value = words[0][0]
    command_token = words[0][1]
    if command_token.unquoted_expansion or "$" in command_value:
        raise _Deny(
            "unresolved_command",
            f"command word {command_value!r} contains an expansion",
        )
    if command_token.has_glob:
        raise _Deny(
            "unresolved_command",
            f"command word {command_value!r} contains a glob",
        )
    resolved_argv = [value for value, _ in words]
    resolved_tokens = [token for _, token in words]
    return resolved_argv, resolved_tokens, depth


def _charge_word(token: _Token) -> int:
    """Charge the argv budget for one resolved word.

    A word whose runtime shape is unknown (an unquoted expansion or a glob)
    is charged the maximum width it could expand to, so a wide command
    hidden behind one expansion cannot slip under the cap.
    """
    if token.unquoted_expansion:
        return MAX_UNRESOLVED_WORDS
    if token.has_glob:
        return MAX_UNRESOLVED_WORDS
    return 1


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


class _Deny(Exception):
    """Internal dangerous-node signal; converted to Deny at the boundary."""

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
    ``unquoted_expansion`` is True when the word contains a variable expansion
    that was not inside quotes (word-splitting applies at runtime).
    ``has_glob`` is True when the word contains an unquoted glob metacharacter,
    so it may expand to many runtime words.
    """

    kind: str
    value: str
    plain: bool = True
    assign_name: Optional[str] = None
    unquoted_expansion: bool = False
    has_glob: bool = False


def _scan_dollar(text: str, i: int, buf: list[str]) -> int:
    """Consume a ``$`` form starting at *i*; append its literal text to *buf*.

    ``$VAR`` and ``${VAR}`` with plain names are accepted. Arithmetic
    expansion, array-subscript arithmetic and indirect expansion are Denied;
    every other dollar form is rejected as TooComplex.
    Returns the index just past the consumed text.
    """
    n = len(text)
    if i + 1 >= n:
        raise _Reject("dollar", "dangling $ at end of command")
    nxt = text[i + 1]
    if nxt == "(":
        if text.startswith("$((", i):
            if _find_matching(text, i + 1) < 0:
                raise _Reject(
                    "arithmetic_expansion", "unbalanced $(( expansion"
                )
            raise _Deny("arithmetic_expansion", "$(( )) arithmetic expansion")
        if text.find(")", i + 2) < 0:
            raise _Reject("command_substitution", "unbalanced $( substitution")
        raise _Deny("command_substitution", "$( ) command substitution")
    if nxt == "{":
        close = text.find("}", i + 2)
        if close < 0:
            raise _Reject("parameter_expansion", "unbalanced ${")
        name = text[i + 2:close]
        if name.startswith("!"):
            raise _Deny(
                "variable_indirection", f"indirect expansion ${{{name}}}"
            )
        if "[" in name and ("$(" in name or "`" in name):
            raise _Deny(
                "array_subscript_arithmetic",
                f"array-subscript arithmetic in ${{{name}}}",
            )
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


def _check_quoted_content(content: str) -> None:
    """Deny dangerous constructs hidden inside a quoted string.

    Array subscripts containing a command substitution are an RCE vector
    (``test -v 'a[$(id)]'``); quoted brace expansion is a fail-closed deny.
    """
    if "[" in content and ("$(" in content or "`" in content):
        raise _Deny(
            "array_subscript_arithmetic",
            f"array-subscript arithmetic in quoted text {content!r}",
        )
    if "{" in content and "}" in content and ("," in content or ".." in content):
        raise _Deny(
            "brace_expansion", f"quoted brace expansion {content!r}"
        )


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
            if text.find("`", j + 1) < 0:
                raise _Reject("command_substitution", "unbalanced backtick")
            raise _Deny("command_substitution", "backtick command substitution")
        if ch == "\\":
            if j + 1 >= n:
                raise _Reject("escape", "trailing backslash in double quotes")
            buf.append(text[j + 1])
            j += 2
            continue
        if ch == "$":
            j = _scan_dollar(text, j, buf)
            continue
        if ch == "{":
            close = text.find("}", j + 1)
            if close >= 0:
                inner = text[j + 1:close]
                if "," in inner or ".." in inner:
                    raise _Deny(
                        "brace_expansion",
                        f"quoted brace expansion {{{inner}}}",
                    )
        buf.append(ch)
        j += 1
    raise _Reject("quote", "unbalanced double quote")


def _find_matching(text: str, i: int) -> int:
    """Return the index of the ``)`` matching the ``(`` at *i*, else -1."""
    depth = 0
    for j in range(i, len(text)):
        ch = text[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return j
    return -1


def _tokenize(text: str, budget: _ParseBudget) -> list[_Token]:
    """Split *text* into word and operator tokens.

    Raises _Reject (fail-closed) for any construct outside this segment.
    """
    tokens: list[_Token] = []
    i, n = 0, len(text)
    cmd_start = True
    while i < n:
        if _budget_exceeded(budget):
            raise _Reject("budget", "parse budget exceeded while tokenizing")
        ch = text[i]
        if ch in " \t":
            i += 1
            continue
        if ch == "\n":
            if not tokens or (
                tokens[-1].kind == "op" and tokens[-1].value in _LIST_OPS
            ):
                i += 1
                continue
            tokens.append(_Token("op", ";"))
            budget.add_node()
            i += 1
            continue
        if ch == "`":
            if text.find("`", i + 1) < 0:
                raise _Reject("command_substitution", "unbalanced backtick")
            raise _Deny("command_substitution", "backtick command substitution")
        if text.startswith("<(", i) or text.startswith(">(", i):
            if _find_matching(text, i + 1) < 0:
                raise _Reject(
                    "process_substitution",
                    f"unbalanced process substitution {text[i:i + 2]}",
                )
            raise _Deny(
                "process_substitution", f"process substitution {text[i:i + 2]}"
            )
        if ch in "()":
            if (
                ch == "("
                and tokens
                and tokens[-1].kind == "word"
                and text.startswith("()", i)
            ):
                raise _Deny(
                    "function_definition",
                    f"function definition {tokens[-1].value!r}",
                )
            if ch == ")" or _find_matching(text, i) < 0:
                raise _Reject("subshell", "unbalanced parenthesis")
            raise _Deny("subshell", "subshell or grouping parenthesis")
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
                    cmd_start = op in _LIST_OPS
                    i += len(op)
                    break
            else:
                tokens.append(_Token("op", ch))
                budget.add_node()
                i += 1
                cmd_start = ch in ";|&"
            continue

        # ---- word ----
        buf_start = i
        buf: list[str] = []
        plain = True
        prefix_literal = True
        has_unquoted_expansion = False
        has_glob = False
        eq_at: Optional[int] = None
        while i < n:
            ch = text[i]
            if ch in " \t\n" or ch in _OP_CHARS:
                break
            if _budget_exceeded(budget):
                raise _Reject("budget", "parse budget exceeded in word")
            if ch == "`":
                if text.find("`", i + 1) < 0:
                    raise _Reject("command_substitution", "unbalanced backtick")
                raise _Deny(
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
                inner = text[i + 1:close]
                _check_quoted_content(inner)
                buf.append(inner)
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
                has_unquoted_expansion = True
                i = _scan_dollar(text, i, buf)
                continue
            if ch in _GLOB_CHARS:
                has_glob = True
            if ch == "=" and eq_at is None and prefix_literal:
                eq_at = len(buf)
            if ch == "{":
                close = text.find("}", i + 1)
                if close >= 0:
                    inner = text[i + 1:close]
                    if "," in inner or ".." in inner:
                        raise _Deny(
                            "brace_expansion",
                            f"brace expansion {{{inner}}}",
                        )
            buf.append(ch)
            i += 1

        value = "".join(buf)
        if not value:
            raise _Reject("word", "empty word")
        if value.startswith("~[") or (
            value.startswith("~") and value != "~" and not value.startswith("~/")
        ):
            raise _Deny(
                "zsh_tilde_expansion", f"zsh-style tilde expansion {value!r}"
            )
        if value.startswith("="):
            raise _Deny(
                "zsh_equals_expansion", f"zsh-style equals expansion {value!r}"
            )
        if not buf or text[buf_start] in "\"'":
            _check_quoted_content(value)
        is_cmd_word = cmd_start and plain
        if is_cmd_word and value in _KEYWORD_NODES:
            raise _Deny(
                _KEYWORD_NODES[value], f"shell keyword {value!r}"
            )
        if cmd_start and text[buf_start] == "$" and value.startswith("$"):
            raise _Deny(
                "variable_indirection",
                f"variable expansion in command position {value!r}",
            )
        if is_cmd_word and "(" in value:
            raise _Deny(
                "function_definition", f"function definition {value!r}"
            )
        assign_name = None if eq_at is None else "".join(buf[:eq_at])
        tokens.append(
            _Token(
                "word",
                value,
                plain=plain,
                assign_name=assign_name,
                unquoted_expansion=has_unquoted_expansion,
                has_glob=has_glob,
            )
        )
        budget.add_node()
        cmd_start = False
    return tokens


# ---------------------------------------------------------------------------
# Segment 2: simple commands
# ---------------------------------------------------------------------------


def _parse_simple_command(tokens: list[_Token], budget: _ParseBudget) -> Verdict:
    """Parse one simple command: assignments, command word, args, redirections.

    Raises _Reject for anything that is not a single simple command.
    """
    argv: list[str] = []
    argv_tokens: list[_Token] = []
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
        argv_tokens.append(tok)
        i += 1

    if argv and argv[0] in DANGEROUS_BUILTINS:
        return Verdict(
            VerdictKind.DENY,
            node=argv[0],
            reason=f"dangerous builtin {argv[0]!r}",
        )

    # Segment 7: unwrap wrapper layers *before* any command-shape check, so
    # the budget measures the command that really runs.  `sudo rm $VAR` has
    # argv[0] == "sudo", which no argv[0] check can see.
    resolved_argv, resolved_tokens, _depth = _unwrap_command(argv, argv_tokens)

    # A dangerous builtin hidden behind a wrapper is still a dangerous
    # builtin: `sudo eval x` must not slip through the argv[0] check.
    if resolved_argv and resolved_argv[0] in DANGEROUS_BUILTINS:
        return Verdict(
            VerdictKind.DENY,
            node=resolved_argv[0],
            reason=f"dangerous builtin {resolved_argv[0]!r}",
        )

    # Charge the resolved argv against the budget.  A word whose runtime
    # shape is unknown is charged its maximum width, so a wide command
    # hidden behind one expansion cannot slip under the cap.
    charged = sum(_charge_word(token) for token in resolved_tokens)
    budget.charge_argv(charged)
    if budget.argv_words > MAX_ARGV_BUDGET:
        raise _Deny(
            "argv_budget",
            f"resolved argv budget {budget.argv_words} exceeds cap "
            f"{MAX_ARGV_BUDGET}",
        )

    # Check for unquoted variable expansion in arguments to dangerous commands.
    # argv[0] is the command word; argv[1:] are the arguments.
    if resolved_argv and resolved_argv[0] in DANGEROUS_COMMANDS:
        for arg_tok in resolved_tokens[1:]:
            if arg_tok.unquoted_expansion:
                return Verdict(
                    VerdictKind.DENY,
                    node="unquoted_expansion",
                    reason=(
                        "unquoted variable expansion in argument to "
                        f"{resolved_argv[0]!r}: {arg_tok.value!r}"
                    ),
                )

    return Verdict(
        VerdictKind.ALLOW,
        node="simple_command",
        reason="simple command",
    )


def _parse_list(tokens: list[_Token], budget: _ParseBudget) -> Verdict:
    """Split a token stream on list operators and parse each element.

    Every element must be a safe simple command for the list to be Allow.
    A dangerous element denies the whole list with that element's verdict.
    """
    elements: list[list[_Token]] = [[]]
    for tok in tokens:
        if tok.kind == "op" and tok.value in _LIST_OPS:
            if not elements[-1]:
                raise _Reject("list", "empty list element")
            elements.append([])
            continue
        elements[-1].append(tok)
    if not elements[-1]:
        raise _Reject("list", "trailing list operator")

    saw_pipeline = any(
        tok.kind == "op" and tok.value in ("|", "|&") for tok in tokens
    )
    for element in elements:
        if _budget_exceeded(budget):
            raise _Reject("budget", "parse budget exceeded while parsing list")
        verdict = _parse_simple_command(element, budget)
        if verdict.kind is VerdictKind.DENY:
            return verdict

    node = "pipeline" if saw_pipeline else "list"
    return Verdict(
        VerdictKind.ALLOW,
        node=node,
        reason="pipeline of simple commands" if saw_pipeline else "command list",
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
        return _parse_list(tokens, budget)
    except _Deny as deny:
        return Verdict(
            VerdictKind.DENY,
            node=deny.node,
            reason=deny.reason,
        )
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
