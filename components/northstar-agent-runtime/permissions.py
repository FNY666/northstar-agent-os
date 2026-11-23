"""Three-layer permission gate: ``disallowed_tools`` → ``allowed_tools`` → mode.

The order is not negotiable, and the first layer always wins: a tool listed in
``disallowed_tools`` is denied even under ``bypassPermissions`` and even if a
hook would have approved it. The second layer auto-approves. The third layer is
``permission_mode`` plus, when the host supplied one, the ``can_use_tool``
approval callback.

Approval decisions are never cached and never replayed: every gated call
re-invokes the host callback with the exact call identity (``call_id`` plus a
``sha256`` digest of the canonical arguments), so a "yes" is scoped to exactly
one tool call and can never authorize a later call or different arguments.
This is the same structural rule as byquexo/agent-approval-gate's
``ApprovalGate`` ("the gate holds no state between calls", ``gate.ts``): no
``approveAll``, no session cache, no "remember my choice".

Safety direction: whenever the gate cannot reach a decision - unknown tool, no
host approval callback in ``default`` mode, a callback that raises - the answer
is **deny**, not "go ahead". Denying work is recoverable; executing work the
host never approved is not.

``Task`` is deliberately not treated as a mutating tool. Blanket-denying it by
name would mean no subagent is ever created, and the error would blame a tool
that was never the problem. Delegation is instead gated per tool inside the
subagent's declared tool set (:meth:`PermissionEngine.check_delegation`).

An optional structured *decision-model* path
(:mod:`decision_model`, SystemOne-style: state + typed questions ->
options + probabilities) can adjudicate the calls that would otherwise reach
the host callback: model ``allow``/``deny`` decides the call, model
``escalate`` or a model error falls through to the host callback. With no
model configured the gate is exactly the deterministic three layers above.
Every model-path verdict carries its full input -> output -> verdict chain
in ``PermissionDecision.decision_model_audit``.
Optional layer 0 — pre-trade risk checks, SEC Rule 15c3-5 style. When the host
supplies a :class:`PreTradeRiskConfig`, every call first passes four
*independent* rejection conditions modelled on 17 CFR 240.15c3-5(c)(1)(ii):
price/value, size, rate ("over a short period of time"), and duplicates —
plus structural validation that fails closed *before* any limit comparison
(a malformed fact is a rejection, not an exception and not a pass). The
checks embody the rule's paragraph (d), "direct and exclusive control": they
read only host-owned configuration, host-supplied fact extractors, and
engine-measured facts (digests, timestamps). Model-supplied claims —
``PermissionRequestContext.data``, ``reason_hint``, prompt text — can never
move them, exactly as a broker-dealer may not delegate its risk controls to
the customer. Every denial is reported to the host's ``audit_sink``
synchronously with its condition code, the (c)(2)(iv)-style surveillance
trail. This is a *mechanism* borrowing, not a compliance claim: the rule
prescribes no numeric limits, binds broker-dealers (not agents), and this
gate implements only the pre-trade erroneous-order limb.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import shlex
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Literal, Sequence, TYPE_CHECKING

if TYPE_CHECKING:  # stdlib-only module; annotation-only to avoid any import cycle
    from dataflow_policy import SessionDataflow, SinkVerdict

from decision_model import (
    DecisionModel,
    DecisionModelResult,
    DecisionPolicy,
    adjudicate,
    approval_questions,
    build_decision_audit,
    build_decision_state,
)
from multisig import MultisigGate, MultisigPolicy, MultisigSignature

PermissionMode = Literal["default", "acceptEdits", "plan", "bypassPermissions"]

PERMISSION_MODES: tuple[PermissionMode, ...] = (
    "default",
    "acceptEdits",
    "plan",
    "bypassPermissions",
)

ToolKind = Literal["read", "edit", "exec", "task", "network", "other"]

#: Kinds that can change state outside the conversation.
MUTATING_KINDS: frozenset[str] = frozenset({"edit", "exec", "network", "other"})

#: Tool-name patterns for offensive security tooling. These are deny-by-default:
#: port scanners, exploit frameworks, credential-stuffing tools, and similar
#: dual-use offensive software. The Spain AEPD incident (Sept 2026) -- an agent
#: autonomously running vuln scans -- is the motivating case. Hosts can
#: explicitly allowlist via ``offensive_allowlist`` in PermissionConfig.
#: Tool-name matching is a case-insensitive substring after presentation
#: normalization; Shell matching uses exact executable basenames in the
#: command positions recognized by ``offensive_shell_commands``.
OFFENSIVE_TOOL_PATTERNS: tuple[str, ...] = (
    "nmap",
    "masscan",
    "zmap",
    "metasploit",
    "msfconsole",
    "sqlmap",
    "hydra",
    "john",
    "hashcat",
    "burpsuite",
    "nessus",
    "openvas",
    "nikto",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "aircrack",
    "wireshark",
    "tcpdump",
    "netcat",
    "ncrack",
    "medusa",
    "patator",
    "crowbar",
    "responder",
    "mimikatz",
    "bloodhound",
    "sharphound",
    "covenant",
    "empire",
    "cobaltstrike",
)

_OFFENSIVE_CONFUSABLES = str.maketrans({
    # Common Cyrillic and Greek lookalikes found in Latin tool identifiers.
    "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "к": "k", "м": "m", "т": "t", "в": "b",
    "н": "h", "ѕ": "s", "ӏ": "l",
    "А": "A", "Е": "E", "І": "I", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "У": "Y", "К": "K", "М": "M", "Т": "T", "В": "B",
    "Н": "H", "Ѕ": "S", "Ӏ": "I",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "μ": "m",
    "ν": "n", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
})


def _offensive_tool_identity(tool_name: str) -> str:
    """Fold presentation obfuscation before matching or allowlisting names."""
    normalized = unicodedata.normalize("NFKC", tool_name)
    normalized = "".join(char for char in normalized if unicodedata.category(char) != "Cf")
    return normalized.translate(_OFFENSIVE_CONFUSABLES).strip().casefold()


def is_offensive_tool(tool_name: str) -> bool:
    """Check whether a tool name matches offensive-security tooling patterns."""
    if not tool_name:
        return False
    lowered = _offensive_tool_identity(tool_name)
    return any(pattern in lowered for pattern in OFFENSIVE_TOOL_PATTERNS)


_SHELL_COMMAND_WRAPPERS = frozenset({
    "command", "exec", "env", "nice", "nohup", "stdbuf", "sudo", "doas", "time", "timeout", "xargs",
})
_SHELL_RESERVED_PREFIXES = frozenset({
    "!", "builtin", "coproc", "do", "elif", "else", "if", "then", "until", "while",
})
_SHELL_COMMAND_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "(", ")"})
_SHELL_INTERPRETER_NAMES = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash"})
_SHELL_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*\Z", re.S)
_OFFENSIVE_EXECUTABLES = frozenset(OFFENSIVE_TOOL_PATTERNS)
_OFFENSIVE_SCAN_INCOMPLETE = "<shell-scan-incomplete>"
_WRAPPER_VALUE_OPTIONS = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-T", "-R", "-D", "--user", "--group", "--host", "--prompt"}),
    "doas": frozenset({"-u"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "timeout": frozenset({"-k", "--kill-after", "-s", "--signal"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "exec": frozenset({"-a"}),
    "xargs": frozenset({"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--eof", "--replace", "--max-lines", "--max-args", "--max-procs", "--max-chars"}),
}


def _shell_substitution_bodies(command: str) -> tuple[str, ...]:
    """Extract simple active command/process substitutions with quote awareness.

    This remains a bounded tripwire, not a full shell grammar. It handles
    balanced ``$(...)``, process substitutions, and backticks while ignoring
    the same text inside single quotes or behind an escape.
    """
    bodies: list[str] = []

    def backtick_end(start: int) -> int | None:
        index = start + 1
        while index < len(command):
            if command[index] == "\\":
                index += 2
            elif command[index] == "`":
                return index
            else:
                index += 1
        return None

    def paren_end(open_index: int) -> int | None:
        depth = 1
        quote: str | None = None
        index = open_index + 1
        while index < len(command):
            char = command[index]
            if quote == "'":
                if char == "'":
                    quote = None
                index += 1
                continue
            if char == "\\":
                index += 2
                continue
            if quote == '"':
                if char == '"':
                    quote = None
                elif char == "`":
                    end = backtick_end(index)
                    if end is None:
                        return None
                    index = end + 1
                    continue
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "`":
                end = backtick_end(index)
                if end is None:
                    return None
                index = end + 1
                continue
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    quote: str | None = None
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
            if char == "`":
                end = backtick_end(index)
                if end is None:
                    break
                bodies.append(command[index + 1:end])
                index = end + 1
                continue
            if command.startswith("$(", index) and not command.startswith("$((", index):
                end = paren_end(index + 1)
                if end is None:
                    break
                bodies.append(command[index + 2:end])
                index = end + 1
                continue
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "`":
            end = backtick_end(index)
            if end is None:
                break
            bodies.append(command[index + 1:end])
            index = end + 1
            continue
        if command.startswith("$(", index) and not command.startswith("$((", index):
            end = paren_end(index + 1)
            if end is None:
                break
            bodies.append(command[index + 2:end])
            index = end + 1
            continue
        if char in "<>" and index + 1 < len(command) and command[index + 1] == "(":
            end = paren_end(index + 1)
            if end is None:
                break
            bodies.append(command[index + 2:end])
            index = end + 1
            continue
        index += 1
    return tuple(bodies)


def _shell_brace_group_bodies(command: str) -> tuple[tuple[str, ...], bool]:
    """Extract active ``{ list; }`` bodies, excluding quotes and ``${}`` expansions."""
    bodies: list[str] = []
    quote: str | None = None
    depth = 0
    body_start = 0
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if quote == '"':
            if char == '"':
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "`":
            # Substitution bodies are scanned separately. Skip them here so
            # braces inside a substitution cannot unbalance an outer group.
            end = index + 1
            while end < len(command):
                if command[end] == "\\":
                    end += 2
                elif command[end] == "`":
                    break
                else:
                    end += 1
            if end >= len(command):
                return tuple(bodies), True
            index = end + 1
            continue
        if char == "{":
            previous = command[index - 1] if index else " "
            following = command[index + 1] if index + 1 < len(command) else ""
            # Grouping braces are standalone words. This excludes ${name} and
            # brace expansion such as {one,two}.
            if previous != "$" and (index == 0 or previous.isspace() or previous in ";|&()") and following.isspace():
                if depth == 0:
                    body_start = index + 1
                depth += 1
            index += 1
            continue
        if char == "}" and depth:
            previous = command[index - 1] if index else ""
            following = command[index + 1] if index + 1 < len(command) else " "
            if (previous.isspace() or previous in ";|&()") and (
                index + 1 == len(command) or following.isspace() or following in ";|&()"
            ):
                depth -= 1
                if depth == 0:
                    bodies.append(command[body_start:index])
            index += 1
            continue
        index += 1
    return tuple(bodies), depth != 0


def offensive_shell_commands(command: str, *, _depth: int = 0) -> tuple[str, ...]:
    """Find direct offensive executable invocations in simple shell syntax.

    This is a pre-approval tripwire for obvious direct launches, not a shell
    parser or execution sandbox. Dynamic command words, ``eval`` and alias
    rewriting are refused as incomplete syntax; interpreter-mediated launches
    and other unrecognized forms must still be contained by host controls.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        tokens = tuple(lexer)
    except ValueError:
        # An unterminated quote or escape is not evidence that the command is
        # harmless; do not let a parser failure silently bypass the tripwire.
        return (_OFFENSIVE_SCAN_INCOMPLETE,)

    found: list[str] = []
    substitutions = _shell_substitution_bodies(command)
    brace_groups, incomplete_braces = _shell_brace_group_bodies(command)
    if incomplete_braces:
        found.append(_OFFENSIVE_SCAN_INCOMPLETE)
    if _depth < 4:
        # shlex treats quoted command substitutions as ordinary data; inspect
        # active substitutions separately, preserving single-quote literals.
        for body in substitutions:
            found.extend(offensive_shell_commands(body, _depth=_depth + 1))
        for body in brace_groups:
            found.extend(offensive_shell_commands(body, _depth=_depth + 1))
    elif substitutions or brace_groups:
        # Stop hostile nesting from turning the bounded scanner into an
        # unbounded parser; report uncertainty as a deny condition.
        found.append(_OFFENSIVE_SCAN_INCOMPLETE)
    expect_command = True
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _SHELL_COMMAND_SEPARATORS:
            expect_command = True
            index += 1
            continue
        if not expect_command:
            index += 1
            continue
        lowered = token.casefold()
        if lowered in {"eval", "alias"}:
            # eval reparses shell source, while alias rewrites later command
            # names. Neither can be resolved safely by this bounded scanner.
            found.append(_OFFENSIVE_SCAN_INCOMPLETE)
            break
        if lowered in _SHELL_RESERVED_PREFIXES or _SHELL_ASSIGNMENT_RE.fullmatch(token):
            index += 1
            continue
        if lowered in _SHELL_COMMAND_WRAPPERS:
            index += 1
            options_with_values = _WRAPPER_VALUE_OPTIONS.get(lowered, frozenset())
            if lowered == "timeout":
                # timeout's first positional value is always the duration.
                while index < len(tokens) and tokens[index].startswith("-"):
                    option = tokens[index]
                    index += 1
                    if option in options_with_values and index < len(tokens):
                        index += 1
                if index < len(tokens) and not tokens[index] in _SHELL_COMMAND_SEPARATORS:
                    index += 1
            else:
                while index < len(tokens):
                    option = tokens[index]
                    if option == "--":
                        index += 1
                        break
                    if option in _SHELL_COMMAND_SEPARATORS or not option.startswith("-"):
                        break
                    if lowered == "env" and (option in {"-S", "--split-string"} or option.startswith("--split-string=")):
                        if option.startswith("--split-string="):
                            split_command = option.split("=", 1)[1]
                            index += 1
                        elif index + 1 < len(tokens):
                            split_command = tokens[index + 1]
                            index += 2
                        else:
                            index += 1
                            continue
                        found.extend(offensive_shell_commands(split_command, _depth=_depth + 1))
                        index = len(tokens)
                        break
                    if lowered == "command" and option in {"-v", "-V"}:
                        # `command -v nmap` only resolves a name; it does not
                        # invoke the offensive executable.
                        index = len(tokens)
                        break
                    index += 1
                    if option in options_with_values and index < len(tokens):
                        index += 1
                while lowered == "env" and index < len(tokens):
                    if _SHELL_ASSIGNMENT_RE.fullmatch(tokens[index]):
                        index += 1
                    else:
                        break
            # `nice 10 command` is the historical adjustment syntax.
            if lowered == "nice" and index < len(tokens) and re.fullmatch(r"[+-]?\d+", tokens[index]):
                index += 1
            if lowered == "time" and index < len(tokens) and tokens[index] == "-p":
                index += 1
            expect_command = True
            continue
        if token.startswith("-"):
            index += 1
            continue
        if token not in {"{", "}"} and any(marker in token for marker in ("$", "`", "*", "?", "[", "{", "}")):
            # At command position, expansion, globbing or brace generation can
            # select an executable that is not visible in the lexical token.
            found.append(_OFFENSIVE_SCAN_INCOMPLETE)
            break
        basename = token.rsplit("/", 1)[-1].casefold()
        if basename in _OFFENSIVE_EXECUTABLES:
            found.append(basename)
        if basename in _SHELL_INTERPRETER_NAMES:
            # Shells accept combined options such as `bash -lc SCRIPT`; inspect
            # the inline command string instead of treating it as inert argv.
            argument = index + 1
            while argument < len(tokens) and tokens[argument] not in _SHELL_COMMAND_SEPARATORS:
                option = tokens[argument]
                if option == "--":
                    break
                if option == "-c" or option == "--command" or (
                    option.startswith("-") and not option.startswith("--") and "c" in option[1:]
                ):
                    if argument + 1 < len(tokens) and tokens[argument + 1] not in _SHELL_COMMAND_SEPARATORS:
                        if _depth < 4:
                            found.extend(offensive_shell_commands(tokens[argument + 1], _depth=_depth + 1))
                        else:
                            found.append(_OFFENSIVE_SCAN_INCOMPLETE)
                    break
                argument += 1
        if basename == "find" and _depth < 4:
            # `find -exec[dir] PROGRAM ... \;` embeds a second command list
            # inside find's arguments, outside the outer shell separators.
            end = index + 1
            while end < len(tokens) and tokens[end] not in _SHELL_COMMAND_SEPARATORS:
                if tokens[end] in {"-exec", "-execdir"}:
                    start = end + 1
                    stop = start
                    while stop < len(tokens) and tokens[stop] not in {";", "+"}:
                        stop += 1
                    if stop > start:
                        found.extend(offensive_shell_commands(" ".join(tokens[start:stop]), _depth=_depth + 1))
                    end = stop
                end += 1
        expect_command = False
        index += 1
    return tuple(dict.fromkeys(found))


def _shell_scan_source(payload: dict[str, Any]) -> str | None:
    """Return a scanner input matching Shell's supported command shapes.

    ``Shell`` accepts command text under ``command`` or its ``cmd`` alias, as
    well as direct ``argv`` execution. Quote argv elements as inert words so
    the same bounded scanner can inspect executable positions and known
    wrappers without interpreting argument metacharacters as shell syntax.
    Invalid shapes are rejected by the Shell handler before spawn.
    """
    if "argv" in payload and payload.get("argv") is not None:
        argv = payload.get("argv")
        if (
            isinstance(argv, (list, tuple))
            and bool(argv)
            and all(isinstance(item, str) and item for item in argv)
        ):
            return shlex.join(argv)
        return None
    command = payload.get("command", payload.get("cmd"))
    return command if isinstance(command, str) else None

DecisionSource = Literal[
    "disallowed_tools",
    "allowed_tools",
    "mode",
    "host_callback",
    "decision_model",
    "multisig",
    "unknown_tool",
    "delegation_gate",
    "invalid_mode",
    "pretrade",
    "scope",
    "composition",
    "offensive",
    "argument",
    "audit",
]


@dataclass(frozen=True)
class PermissionDecision:
    """The gate's verdict for one tool call."""

    allowed: bool
    source: DecisionSource = "mode"
    reason: str = ""
    rule: str = ""
    tool: str = ""
    #: Machine-readable denial code in a dotted namespace, e.g.
    #: ``denial.host_callback.error``. Derived from ``rule`` for denials
    #: when not set explicitly; empty for allows. Lets audit consumers
    #: classify denials without parsing free-text reasons.
    deny_code: str = ""
    #: Set only when the verdict came from the decision-model path: the full
    #: input -> output -> verdict chain (state, questions, probabilities,
    #: thresholds), ready to append to the audit feed.
    decision_model_audit: dict[str, Any] | None = None
    #: Extra structured material for the audit chain. Carries the multisig
    #: verdict (approver ids + signature hexes) when the multisig tier
    #: decided; empty otherwise, and omitted from ``as_dict()`` when empty so
    #: existing outputs are byte-identical.
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.reason or ("allowed" if self.allowed else "denied")

    def __post_init__(self) -> None:
        # Denials always carry a machine-readable code: derive it from the
        # already-structured rule namespace when the construction site did
        # not set one explicitly. Allows keep an empty code.
        if not self.allowed and not self.deny_code and self.rule:
            object.__setattr__(
                self, "deny_code", "denial." + self.rule.replace(":", ".")
            )

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "tool": self.tool,
            "allowed": self.allowed,
            "source": self.source,
            "reason": self.reason,
            "rule": self.rule,
        }
        if self.deny_code:
            payload["deny_code"] = self.deny_code
        if self.decision_model_audit is not None:
            payload["decision_model_audit"] = self.decision_model_audit
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass(frozen=True)
class PermissionRequestContext:
    """What the host approval callback gets to see.

    ``call_id`` and ``arguments_digest`` pin the approval to the exact call:
    the host decides on this (tool, call id, arguments) triple and the
    decision is consumed for that call only. The engine never caches a
    decision, so reusing an old approval for new arguments fails closed by
    construction — the callback is simply asked again.
    """

    session_id: str = ""
    agent: str = "main"
    depth: int = 0
    turn_index: int = 0
    workspace: str = ""
    mode: str = "default"
    reason_hint: str = ""
    call_id: str = ""
    arguments_digest: str = ""
    #: Signatures presented for the multisig tier. The host collects these
    #: out of band (m approvers each sign the exact ``(call_id,
    #: arguments_digest)`` pair) and attaches them to the request; the
    #: engine verifies them itself and never trusts the callback's word.
    multisig_signatures: tuple[MultisigSignature, ...] = ()
    #: Scope (epoch) this request belongs to. When set and the scope is
    #: closed via ScopeManager, the request is denied -- this is the
    #: permission-lifetime mechanism (PORTICO-style): approvals don't
    #: linger past their subgoal. Empty means unscoped (current behavior).
    scope_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CompositionRule:
    """A forbidden action sequence (composition closure, APC-style).

    Each call is evaluated individually by the gate, but some *sequences*
    are unsafe even when every step is allowed alone -- the canonical
    shape is ``read sensitive data`` then ``send externally``
    (exfiltration). ``sequence`` lists action categories in order; when
    the recent call history ends with this sequence, the current call is
    denied.

    Categories are host-defined labels (e.g. "read_sensitive",
    "external_send"); the engine maps tool names to categories via the
    ``tool_categories`` mapping. Unmapped tools carry no category and
    never match a rule.
    """

    sequence: tuple[str, ...]
    description: str = ""

    def __post_init__(self) -> None:
        if len(self.sequence) < 2:
            raise ValueError("composition rule needs at least 2 categories")


def trace_violates_rules(
    categories: Sequence[str],
    rules: Sequence[CompositionRule],
) -> CompositionRule | None:
    """Check whether a category trace contains a forbidden sequence.

    This is the shared contract artifact (ContrAgent-style "one spec, two
    roles"):
    - **Online**: the permission gate calls this incrementally as each
      call arrives, with history + the current call's category.
    - **Offline**: the governance bench calls this on complete traces to
      score whether the trace *would have* been stopped.

    Returns the first violated rule, or None if the trace is clean.
    A rule matches when its sequence appears as a contiguous subsequence
    ending at the last category.
    """
    if not categories or not rules:
        return None
    for rule in rules:
        seq = rule.sequence
        if len(categories) < len(seq):
            continue
        if tuple(categories[-len(seq):]) == seq:
            return rule
    return None


@dataclass
class ScopeManager:
    """Tracks permission scopes (epochs) and their lifetime.

    A scope groups approvals for one task phase. When the phase ends,
    ``close_scope`` revokes the scope: subsequent permission checks with
    that ``scope_id`` are denied. This closes the "lingering authority"
    gap where a subgoal's permissions remain usable after the subgoal ends.

    Scopes are identified by string IDs; the manager is deliberately
    simple (no persistence) -- the runtime creates scopes for task phases
    and closes them on phase transitions.

    Authority ceiling (arXiv:2607.23586): when a scope is opened with a
    ``capabilities`` set, that set becomes the immutable ceiling for the
    scope's lifetime. Within an open scope, authority may contract freely
    but expand only through explicit host approval (gated ascent) -- no
    runtime signal can raise the ceiling; only a fresh scope (fresh grant)
    sets a new one. This answers "the agent acquired a new tool mid-task".
    """

    _open: dict[str, str] = field(default_factory=dict)  # scope_id -> description
    _closed: set[str] = field(default_factory=set)
    _ceilings: dict[str, frozenset[str]] = field(default_factory=dict)  # scope_id -> tool ceiling

    def open_scope(
        self,
        scope_id: str,
        description: str = "",
        capabilities: Iterable[str] | None = None,
    ) -> None:
        """Open a scope. Reopening a closed scope is an error (fail closed).

        When ``capabilities`` is given, it becomes the scope's immutable
        authority ceiling: tools outside it need explicit host approval
        even if they'd normally be auto-allowed.
        """
        if not scope_id:
            raise ValueError("scope_id must not be empty")
        if scope_id in self._closed:
            raise ValueError(f"scope {scope_id!r} is closed and cannot be reopened")
        self._open[scope_id] = description
        if capabilities is not None:
            self._ceilings[scope_id] = frozenset(capabilities)

    def close_scope(self, scope_id: str) -> bool:
        """Close a scope, revoking its permissions. Returns True if it was open."""
        if scope_id in self._open:
            del self._open[scope_id]
            self._closed.add(scope_id)
            # Ceiling goes with the scope; a reopened id gets a fresh ceiling.
            self._ceilings.pop(scope_id, None)
            return True
        return False

    def is_open(self, scope_id: str) -> bool:
        """True if the scope exists and hasn't been closed."""
        return scope_id in self._open

    def was_closed(self, scope_id: str) -> bool:
        """True if the scope was explicitly closed (vs never opened)."""
        return scope_id in self._closed

    def ceiling(self, scope_id: str) -> frozenset[str] | None:
        """The scope's authority ceiling, or None if none was set."""
        return self._ceilings.get(scope_id)

    def within_ceiling(self, scope_id: str, tool_name: str) -> bool:
        """True if the tool is within the scope's ceiling (or no ceiling set).

        Compared on canonical names so spelling variants can't escape the
        ceiling.
        """
        cap = self._ceilings.get(scope_id)
        if cap is None:
            return True
        return canonical_tool_name(tool_name) in {canonical_tool_name(c) for c in cap}


def digest_arguments(arguments: Any) -> str:
    """Canonical ``sha256:<hex>`` digest of tool arguments.

    Same wire format as the durable-run approval tokens
    (``northstar.approval.v2/v3`` bind approvals to this digest), so a host
    can compare the digest it approved against the digest of the call being
    executed and refuse on any mismatch.
    """
    try:
        encoded = json.dumps(
            arguments if isinstance(arguments, dict) else {},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("tool arguments are not JSON-serialisable") from error
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class DelegationVerdict:
    """Per-tool result of gating a subagent's declared tool set."""

    agent: str = ""
    allowed: tuple[str, ...] = ()
    denied: tuple[tuple[str, str], ...] = ()
    checked: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.denied

    @property
    def summary(self) -> str:
        if self.ok:
            return f"delegation approved for {', '.join(self.allowed) or 'no tools'}"
        parts = [f"{name} ({reason})" for name, reason in self.denied]
        return "delegation denied for: " + "; ".join(parts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "allowed": list(self.allowed),
            "denied": [{"tool": name, "reason": reason} for name, reason in self.denied],
            "checked": list(self.checked),
            "ok": self.ok,
        }


@dataclass(frozen=True)
class DelegationToken:
    """A signed, attenuating delegation token (IBCT-style).

    Minted by the gate when a delegation is approved. Each hop appends
    a token whose tool set must be a subset of its parent's -- scope can
    only shrink, never grow. The downstream verifier checks the signature
    chain independently, so the token is defense-in-depth even if the gate
    itself is bypassed.

    ``parent_hash`` is the SHA-256 of the parent token's canonical form;
    empty for a root delegation (no parent).

    ``audience`` binds the token to its intended recipient (mandatum V9):
    a token minted for agent X cannot be presented by agent Y, even if Y
    somehow obtains it. Empty means unbound (legacy behavior).

    ``depth`` is the delegation-chain depth: 0 for a root token, parent's
    depth + 1 for each child. It is part of the signed body, so a token
    cannot be re-labeled shallower than it was minted. ``verify_delegation_token``
    enforces ``max_depth`` at verification time (abaxxlabs/agents v0.12.5
    lesson: issuance-side enforcement alone is bypassable).
    """

    delegator_id: str
    delegatee_id: str
    tools: tuple[str, ...]
    issued_at: float
    expires_at: float
    parent_hash: str = ""
    signature: str = ""
    audience: str = ""
    depth: int = 0

    def _signing_body(self) -> dict[str, Any]:
        return {
            "delegator_id": self.delegator_id,
            "delegatee_id": self.delegatee_id,
            "tools": sorted(self.tools),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "parent_hash": self.parent_hash,
            "audience": self.audience,
            "depth": self.depth,
        }

    def token_hash(self) -> str:
        """SHA-256 of the canonical token (including signature)."""
        return hashlib.sha256(
            json.dumps({**self._signing_body(), "signature": self.signature}, sort_keys=True).encode()
        ).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {**self._signing_body(), "signature": self.signature}


def mint_delegation_token(
    *,
    delegator_id: str,
    delegatee_id: str,
    tools: Sequence[str],
    delegator_seed: bytes,
    ttl_seconds: float = 3600.0,
    parent_token: DelegationToken | None = None,
    issued_at: float | None = None,
    audience: str = "",
    max_depth: int | None = None,
) -> DelegationToken:
    """Mint a signed delegation token.

    ``tools`` must be a subset of the parent token's tools when a parent
    is given -- attenuation is enforced at mint time, not just verified.

    ``audience`` binds the token to its intended presenter (mandatum V9).

    ``depth`` is 0 for a root, parent.depth + 1 for a child, and is
    signature-bound. When ``max_depth`` is given, minting beyond it raises
    -- but issuance is only half the story: ``verify_delegation_token``
    enforces the same limit independently, because an issuance-side check
    alone can be bypassed (abaxxlabs/agents v0.12.5).
    """
    if not delegator_id or not delegatee_id:
        raise ValueError("delegator_id and delegatee_id must be non-empty")
    if not isinstance(delegator_seed, (bytes, bytearray)) or len(delegator_seed) != 32:
        raise ValueError("delegator_seed must be a 32-byte Ed25519 seed")
    tool_tuple = tuple(sorted(set(tools)))
    parent_hash = ""
    depth = 0
    if parent_token is not None:
        parent_tools = set(parent_token.tools)
        if not set(tool_tuple) <= parent_tools:
            raise ValueError(
                f"delegation tools {tool_tuple} exceed parent scope {parent_token.tools}: "
                "scope can only shrink"
            )
        if not isinstance(parent_token.depth, int) or parent_token.depth < 0:
            raise ValueError("parent token has malformed depth")
        parent_hash = parent_token.token_hash()
        depth = parent_token.depth + 1
    if max_depth is not None and depth > max_depth:
        raise ValueError(
            f"delegation depth {depth} exceeds max_depth {max_depth}"
        )
    ts = time.time() if issued_at is None else float(issued_at)
    unsigned = DelegationToken(
        delegator_id=delegator_id,
        delegatee_id=delegatee_id,
        tools=tool_tuple,
        issued_at=ts,
        expires_at=ts + float(ttl_seconds),
        parent_hash=parent_hash,
        audience=audience,
        depth=depth,
    )
    try:
        from ed25519 import sign as ed_sign
    except ImportError as e:
        raise RuntimeError("ed25519 module unavailable") from e
    sig = ed_sign(bytes(delegator_seed), json.dumps(unsigned._signing_body(), sort_keys=True).encode()).hex()
    return DelegationToken(**{**unsigned.__dict__, "signature": sig})


def verify_delegation_token(
    token: DelegationToken,
    delegator_public_key: bytes,
    *,
    now: float | None = None,
    expected_parent_hash: str | None = None,
    expected_audience: str | None = None,
    revocation_oracle: Callable[[DelegationToken], bool] | None = None,
    expected_root_hash: str | None = None,
    max_depth: int | None = None,
    chain_resolver: Callable[[str], DelegationToken | None] | None = None,
    public_key_for: Callable[[str], bytes | None] | None = None,
) -> bool:
    """Verify a delegation token's signature, expiry, parent binding, and more.

    Checks (mandatum V1-V9):
    - signature: Ed25519 over the canonical body (covers audience and depth)
    - time: issued_at <= now <= expires_at
    - parent binding: parent_hash matches expected_parent_hash (if given)
    - audience: token.audience matches expected_audience (if given); a token
      without audience binding passes only when no audience is expected
    - revocation: revocation_oracle(token) True means revoked (if oracle given)
    - root: token_hash() matches expected_root_hash for root tokens (if given)
    - depth: token.depth is a non-negative int; when max_depth is given,
      depth > max_depth is rejected -- the limit is enforced here at
      verification time, not only at issuance (abaxxlabs/agents v0.12.5:
      issuance-only enforcement is bypassable)

    Chain escalation: when the token carries a ``parent_hash`` and
    ``chain_resolver`` is given, verification escalates to
    ``verify_delegation_chain`` -- the whole chain leaf->root is walked and
    revocation is checked for EVERY link (cascade revocation). Ancestor
    delegator keys come from ``public_key_for`` (falling back to
    ``delegator_public_key`` for the leaf's own delegator); unknown keys
    fail closed. Without ``chain_resolver`` the legacy single-token
    behavior is preserved.

    False on any defect; never raises.
    """
    try:
        if not isinstance(delegator_public_key, (bytes, bytearray)) or len(delegator_public_key) != 32:
            return False
        if len(token.signature) != 128:  # 64 bytes hex
            return False
        signature = bytes.fromhex(token.signature)
        try:
            from ed25519 import verify as ed_verify
        except ImportError:
            return False
        body = json.dumps(token._signing_body(), sort_keys=True).encode()
        if not bool(ed_verify(bytes(delegator_public_key), body, signature)):
            return False
        # Depth is signature-bound (part of the body), so a passing signature
        # means the depth value is the minter's, not a forgery. Reject
        # malformed depths fail-closed, then enforce the verifier's limit.
        if not isinstance(token.depth, int) or isinstance(token.depth, bool) or token.depth < 0:
            return False
        if max_depth is not None and token.depth > max_depth:
            return False
        ts = time.time() if now is None else float(now)
        if not (token.issued_at <= ts <= token.expires_at):
            return False
        if expected_parent_hash is not None and token.parent_hash != expected_parent_hash:
            return False
        # Audience binding: if the verifier expects an audience, the token
        # must carry exactly that audience.
        if expected_audience is not None and token.audience != expected_audience:
            return False
        # Revocation: the oracle is authoritative.
        if revocation_oracle is not None:
            try:
                if revocation_oracle(token):
                    return False
            except Exception:
                return False  # oracle failure fails closed
        # Root consistency: for root tokens, pin the expected root hash.
        # (In chain mode the walker checks this against the true root found
        # by the walk, not the leaf.)
        if (
            expected_root_hash is not None
            and not token.parent_hash
            and token.token_hash() != expected_root_hash
        ):
            return False
        # Chain-walk escalation: when the token carries a parent link and the
        # caller supplied a chain resolver, verify the whole chain leaf->root
        # (cascade revocation) instead of stopping at the leaf. Without a
        # resolver the legacy single-token behavior is preserved.
        if token.parent_hash and chain_resolver is not None:
            def _keys_for(delegator_id: str) -> bytes | None:
                if delegator_id == token.delegator_id:
                    if isinstance(delegator_public_key, (bytes, bytearray)) and len(
                        delegator_public_key
                    ) == 32:
                        return bytes(delegator_public_key)
                    return None
                if public_key_for is not None:
                    try:
                        key = public_key_for(delegator_id)
                    except Exception:
                        return None
                    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
                        return bytes(key)
                    return None
                return None

            return verify_delegation_chain(
                token,
                public_key_for=_keys_for,
                chain_resolver=chain_resolver,
                now=now,
                expected_parent_hash=expected_parent_hash,
                expected_audience=expected_audience,
                revocation_oracle=revocation_oracle,
                expected_root_hash=expected_root_hash,
                max_depth=max_depth,
            )
        return True
    except (ValueError, TypeError):
        return False


def verify_delegation_chain(
    token: DelegationToken,
    *,
    public_key_for: Callable[[str], bytes | None],
    chain_resolver: Callable[[str], DelegationToken | None] | None = None,
    now: float | None = None,
    expected_parent_hash: str | None = None,
    expected_audience: str | None = None,
    revocation_oracle: Callable[[DelegationToken], bool] | None = None,
    expected_root_hash: str | None = None,
    max_depth: int | None = None,
) -> bool:
    """Verify a delegation chain leaf->root with cascade revocation.

    Research consensus (mandatum V8, UCAN, adtp): the verifier must walk
    from the presented token up through ``parent_hash`` links and check
    revocation for EVERY link, not just the leaf. A revoked ancestor kills
    the whole subtree -- revocation cascades.

    Per-link checks: Ed25519 signature (with that hop's delegator key from
    ``public_key_for``), ``issued_at <= now <= expires_at``, well-formed
    non-negative depth, ``max_depth`` when given, ``child.expires_at <=
    parent.expires_at`` (a child must not outlive its parent),
    ``child.depth == parent.depth + 1`` (hop continuity), and
    ``child.tools <= parent.tools`` (attenuation re-checked at verify time;
    mint already enforces it, the walk does not trust mint).

    Fail-closed rules: an unresolvable ancestor fails; a resolver that
    returns the wrong token (``token_hash()`` mismatch) fails; a cycle
    fails; an oracle error on any link fails; an unknown delegator key
    fails. The leaf's audience is checked against ``expected_audience``
    and its ``parent_hash`` against ``expected_parent_hash`` (same
    semantics as ``verify_delegation_token``); the root must have depth 0
    and match ``expected_root_hash`` when given.

    False on any defect; never raises.
    """
    try:
        ts = time.time() if now is None else float(now)
        try:
            from ed25519 import verify as ed_verify
        except ImportError:
            return False
        seen: set[str] = set()
        current = token
        child: DelegationToken | None = None
        leaf = True
        while True:
            # Cycle guard: a hash seen twice means the resolver led us in
            # a circle.
            link_hash = current.token_hash()
            if link_hash in seen:
                return False
            seen.add(link_hash)
            # This hop's delegator key; unknown key fails closed.
            try:
                pubkey = public_key_for(current.delegator_id)
            except Exception:
                return False
            if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
                return False
            # Signature over the canonical body (covers depth, audience,
            # parent_hash, tools -- the value is the minter's, not a forgery).
            if len(current.signature) != 128:
                return False
            try:
                signature = bytes.fromhex(current.signature)
            except ValueError:
                return False
            body = json.dumps(current._signing_body(), sort_keys=True).encode()
            if not bool(ed_verify(bytes(pubkey), body, signature)):
                return False
            # Depth well-formed, then the verifier's own limit.
            if (
                not isinstance(current.depth, int)
                or isinstance(current.depth, bool)
                or current.depth < 0
            ):
                return False
            if max_depth is not None and current.depth > max_depth:
                return False
            # Time window for this link.
            if not (current.issued_at <= ts <= current.expires_at):
                return False
            # Link invariants against the child we descended from.
            if child is not None:
                if child.expires_at > current.expires_at:
                    return False
                if child.depth != current.depth + 1:
                    return False
                if not set(child.tools) <= set(current.tools):
                    return False
            # Leaf-only caller assertions.
            if leaf:
                if (
                    expected_parent_hash is not None
                    and current.parent_hash != expected_parent_hash
                ):
                    return False
                if (
                    expected_audience is not None
                    and current.audience != expected_audience
                ):
                    return False
                leaf = False
            # Revocation: the oracle is authoritative for EVERY link. A
            # revoked ancestor invalidates the whole chain (cascade); an
            # oracle error fails closed rather than skipping the link.
            if revocation_oracle is not None:
                try:
                    if revocation_oracle(current):
                        return False
                except Exception:
                    return False
            # Root reached: empty parent_hash terminates the walk.
            if not current.parent_hash:
                if current.depth != 0:
                    return False
                if expected_root_hash is not None and current.token_hash() != expected_root_hash:
                    return False
                return True
            # Resolve the ancestor; unresolvable fails closed.
            if chain_resolver is None:
                return False
            try:
                ancestor = chain_resolver(current.parent_hash)
            except Exception:
                return False
            if ancestor is None:
                return False
            # The resolver must return the exact token the hash commits to.
            if ancestor.token_hash() != current.parent_hash:
                return False
            child = current
            current = ancestor
    except (ValueError, TypeError, AttributeError):
        return False


def normalise_names(values: Iterable[str] | None) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        raise TypeError("tool lists must be sequences of names, not a bare string")
    seen: list[str] = []
    for value in values:
        name = str(value).strip()
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


def subtract(allowed: Iterable[str] | None, denied: Iterable[str] | None) -> tuple[str, ...]:
    """``--deny-tool`` semantics: subtract, never co-list.

    Keeping a name in both lists would trip the "same tool allowed and
    disallowed" guard instead of doing what the operator asked, so the CLI
    computes the allow list this way before the engine ever sees it.
    """
    denied_set = set(normalise_names(denied))
    return tuple(name for name in normalise_names(allowed) if name not in denied_set)


def canonical_tool_name(name: str) -> str:
    """Canonical form of a tool name for policy matching.

    Strips whitespace and casefolds, so ``"  Bash "``, ``"bash"`` and
    ``"BASH"`` all resolve to the same identity. The gate matches policy
    (disallowed/allowed lists, kind map, argument policies) on canonical
    names: a forbidden action can't slip through via spelling variants
    (Agent Security Bench naming-sensitivity finding, ~Oct 2026:
    neutral renames raised ASR +11-13pp).
    """
    return str(name).strip().casefold()


def _normalize_argument_text(text: str) -> str:
    """Collapse trivial shell obfuscations before denylist matching.

    ``${IFS}``/``$IFS`` act as whitespace in shell, and any run of
    whitespace is equivalent to a single space for the shapes this policy
    matches (``rm  -rf /``, ``rm\\t-rf /``). Matching is still substring
    based and case-insensitive; this does not try to win an arms race
    against encoding (base64, charcode tricks) -- those are the sandbox's
    and the approval gate's job. It just closes the cheapest evasions.
    """
    lowered = text.lower()
    # POSIX shells remove an escaped newline before tokenization.
    lowered = re.sub(r"\\\r?\n", "", lowered)
    lowered = lowered.replace("${ifs}", " ").replace("$ifs", " ")
    return re.sub(r"\s+", " ", lowered)


#: Catastrophic-only default denylist for the runtime's Shell tool.
#: Applied by AgentRuntime when the host sets no argument_policies of its
#: own (and the mode is not bypassPermissions). Deliberately narrow: only
#: patterns no legitimate command needs -- wiping the root filesystem,
#: formatting block devices, fork bombs, raw writes to disk devices, and
#: the classic pipe-to-shell payload delivery. Broader blocking
#: (curl/wget alone, package installs, chmod) stays opt-in via
#: RuntimeConfig.argument_policies because those have legitimate uses.
DEFAULT_SHELL_DENYLIST: tuple[str, ...] = (
    "rm -rf /",
    "rm -rf /*",
    "rm -fr /",
    "rm -fr /*",
    # Coreutils accepts reordered options and --no-preserve-root. These
    # patterns close common lexical variants without treating general `rm`
    # use as forbidden. This remains a narrow guard, not a shell parser.
    "rm -f -r /",
    "rm -r -f /",
    "--no-preserve-root",
    "mkfs",
    ":(){",
    "of=/dev/",
    "> /dev/sd",
    ">/dev/sd",
    "| sh",
    "| bash",
    "| dash",
    "base64 -d",
    "base64 --decode",
)


@dataclass(frozen=True)
class ArgumentPolicy:
    """A policy on a critical tool argument (argument-level provenance).

    The gate checks tool *names*; this checks the *values* that matter.
    Each policy names a tool and one of its arguments, plus either a
    denylist of forbidden patterns or an allowlist of permitted ones
    (or both; denylist wins on conflict).

    Patterns are case-insensitive substrings -- simple, auditable, and
    enough for the common shapes (dangerous shell fragments, unexpected
    recipients). This is opt-in; no policies means no argument checks.

    Example: ArgumentPolicy(tool="Bash", argument="command",
             denylist=("rm -rf /", "mkfs", ":(){")) blocks obviously
    destructive shell commands at the gate, before the tool runs.
    """

    tool: str
    argument: str
    denylist: tuple[str, ...] = ()
    allowlist: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.tool or not self.argument:
            raise ValueError("argument policy needs a tool and an argument name")

    def check(self, value: Any) -> str | None:
        """Return a violation reason, or None if the value passes."""
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        normalized = _normalize_argument_text(text)
        for pattern in self.denylist:
            if _normalize_argument_text(pattern) in normalized:
                return f"argument {self.argument!r} matches denylisted pattern {pattern!r}"
        if self.allowlist:
            for pattern in self.allowlist:
                if _normalize_argument_text(pattern) in normalized:
                    return None
            return f"argument {self.argument!r} matches no allowlisted pattern"
        return None


@dataclass(frozen=True)
class PermissionConfig:
    mode: PermissionMode = "default"
    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()
    #: Explicit allowlist for offensive-security tooling. Tools matching
    #: OFFENSIVE_TOOL_PATTERNS are deny-by-default; listing a tool here
    #: re-enables it (still subject to all other gate layers).
    offensive_allowlist: tuple[str, ...] = ()
    #: Argument-level policies (opt-in). Checked in evaluate() before the
    #: normal layers; a violation denies with argument:policy_violation.
    argument_policies: tuple[ArgumentPolicy, ...] = ()
    can_use_tool: Callable[[str, dict[str, Any], PermissionRequestContext], Any] | None = None
    #: Optional structured decision model (SystemOne-style: state + typed
    #: questions -> options + probabilities). When set, mutating calls that
    #: would otherwise go to the host callback are first offered to the
    #: model; ``allow``/``deny`` decide the call, ``escalate`` (or a model
    #: error) falls through to the existing host-callback path. ``None``
    #: means the deterministic gate path, unchanged.
    decision_model: DecisionModel | None = None
    decision_policy: DecisionPolicy = field(default_factory=DecisionPolicy)
    #: When set, any mutating call that reaches the host-callback tier is
    #: additionally gated on m-of-n approver signatures. This upgrades the
    #: single-approver ASK to multisig: the host callback alone can no longer
    #: release a high-risk call, so one compromised approver is insufficient.
    multisig: MultisigPolicy | None = None
    #: Optional approver public keys for the signed-approval tier. When set,
    #: the host callback may return {"allowed": True, "approval_receipt": {...}}
    #: with an Ed25519-signed receipt; the gate verifies the signature against
    #: these keys and records the verified approver identity. Plain bool/str
    #: verdicts still work (unsigned), so this is opt-in and backward compatible.
    approver_keys: dict[str, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", validate_mode(self.mode))
        object.__setattr__(self, "allowed_tools", normalise_names(self.allowed_tools))
        object.__setattr__(self, "disallowed_tools", normalise_names(self.disallowed_tools))
        if self.can_use_tool is not None and not callable(self.can_use_tool):
            raise TypeError("can_use_tool must be callable")
        if self.decision_model is not None and not hasattr(self.decision_model, "decide"):
            raise TypeError("decision_model must provide a decide(state, questions) method")
        if not isinstance(self.decision_policy, DecisionPolicy):
            raise TypeError("decision_policy must be a DecisionPolicy")
        if self.multisig is not None and not isinstance(self.multisig, MultisigPolicy):
            raise TypeError("multisig must be a MultisigPolicy")

    @property
    def overlap(self) -> tuple[str, ...]:
        """Names present in both lists; kept for diagnostics, deny always wins.

        Compared on canonical names so ``"Bash"`` vs ``"bash"`` co-listing
        is also caught.
        """
        allowed_c = {canonical_tool_name(n) for n in self.allowed_tools}
        denied_c = {canonical_tool_name(n) for n in self.disallowed_tools}
        both = allowed_c & denied_c
        return tuple(sorted(both))


def validate_mode(mode: str) -> PermissionMode:
    if mode not in PERMISSION_MODES:
        raise ValueError(f"unknown permission mode {mode!r}; expected one of {', '.join(PERMISSION_MODES)}")
    return mode  # type: ignore[return-value]


#: Pre-trade rejection condition codes (SEC 15c3-5 (c)(1)(ii) mapping).
#: Each is an independent rejection condition: any one firing denies the
#: call, and every firing condition is reported — never just the first.
PT_PRICE = "pretrade:PT-1"  #: value/price parameter exceeded
PT_SIZE = "pretrade:PT-2"  #: size parameter exceeded
PT_RATE = "pretrade:PT-3"  #: rate over a short period of time exceeded
PT_DUPLICATE = "pretrade:PT-4"  #: duplicative call detected
PT_FACT_MISSING = "pretrade:fact_missing"  #: a fact a check needs is missing/malformed


@dataclass(frozen=True)
class PreTradeRiskConfig:
    """Host-owned pre-trade risk limits, SEC Rule 15c3-5 (c)(1)(ii) style.

    The four independent rejection conditions map onto tool-call facts:

    - **PT-1 price/value**: ``value_of(tool, payload)`` is the host's own
      valuation of the call (the broker's notional, not the model's claim).
      It must be finite and non-negative — a missing, NaN, or negative
      value is *structural* failure and denies with ``fact_missing`` rather
      than sliding under every cap. ``max_call_value`` caps a single call;
      ``reference_of`` + ``price_collar`` is the fat-finger collar: a call
      whose value strays further than ``price_collar`` from the host's
      reference is denied, and an *unusable* reference denies too (a data
      outage must not silently disarm the check).
    - **PT-2 size**: canonical-JSON payload bytes against
      ``max_payload_bytes``.
    - **PT-3 rate**: at most ``max_calls_per_window`` evaluations of one
      tool per ``window_seconds`` ("over a short period of time"). Rejected
      calls still consume burst budget — they were messages the gate had
      to handle.
    - **PT-4 duplicates**: the same ``(tool, arguments_digest)`` within
      ``dedupe_window_seconds`` is denied as duplicative. Only calls the
      gate *allowed* seed the window: a resubmission after a rejection is
      not a duplicate of anything.

    Threshold convention, applied uniformly: the configured limit is
    itself permitted; a breach requires *exceeding* it. The rule prescribes
    no numeric limits — every default here is a host calibration choice,
    documented as such.

    Direct and exclusive control (15c3-5(d)): ``value_of`` and
    ``reference_of`` are *host* callables (the broker's own feed). The
    model being gated supplies neither the limits nor the facts the checks
    compare against.
    """

    max_call_value: float | None = None
    value_of: Callable[[str, dict[str, Any]], float | None] | None = None
    reference_of: Callable[[str, dict[str, Any]], float | None] | None = None
    price_collar: float = 0.05
    max_payload_bytes: int | None = None
    max_calls_per_window: int | None = None
    window_seconds: float = 1.0
    dedupe_window_seconds: float = 60.0


class PermissionEngine:
    """Evaluates one tool call against the pre-trade checks then the three layers."""

    def __init__(
        self,
        config: PermissionConfig | None = None,
        *,
        mode: PermissionMode = "default",
        allowed_tools: Iterable[str] | None = None,
        disallowed_tools: Iterable[str] | None = None,
        can_use_tool: Callable[[str, dict[str, Any], PermissionRequestContext], Any] | None = None,
        tool_kinds: dict[str, str] | None = None,
        multisig_pubkeys: Mapping[str, bytes] | None = None,
        pretrade: PreTradeRiskConfig | None = None,
        audit_sink: Callable[[dict[str, Any]], None] | None = None,
        now: Callable[[], float] | None = None,
        scope_manager: ScopeManager | None = None,
        wall_now: Callable[[], float] | None = None,
        composition_rules: Iterable[CompositionRule] | None = None,
        tool_categories: Mapping[str, str] | None = None,
        composition_history: deque[str] | None = None,
    ) -> None:
        if config is None:
            config = PermissionConfig(
                mode=mode,
                allowed_tools=allowed_tools or (),
                disallowed_tools=disallowed_tools or (),
                can_use_tool=can_use_tool,
            )
        self.config = config
        # Canonical (casefolded, stripped) name sets for policy matching, so
        # spelling variants can't bypass the lists. The config keeps the
        # original spellings for display; matching uses these.
        self._disallowed_canonical: frozenset[str] = frozenset(
            canonical_tool_name(n) for n in config.disallowed_tools
        )
        self._allowed_canonical: frozenset[str] = frozenset(
            canonical_tool_name(n) for n in config.allowed_tools
        )
        # Fallback kind map for callers that evaluate by name only (e.g. the
        # delegation gate, where no ToolSpec object is in hand).
        self._kinds: dict[str, str] = dict(tool_kinds or {})
        # Canonical kind map: variant spellings resolve to the same kind.
        self._kinds_canonical: dict[str, str] = {
            canonical_tool_name(n): k for n, k in (tool_kinds or {}).items()
        }
        # The multisig tier needs the approver public keys to verify against.
        # A policy without keys would silently deny everything, so fail loud
        # at construction instead.
        if config.multisig is not None:
            if not multisig_pubkeys:
                raise ValueError(
                    "multisig policy is configured but no approver public keys "
                    "were supplied; refusing to build a gate that denies all"
                )
            self._multisig_gate: MultisigGate | None = MultisigGate(
                config.multisig, multisig_pubkeys
            )
        else:
            self._multisig_gate = None
        #: Approver public keys the multisig tier verifies against (None when
        #: no multisig policy is configured). Kept so hosts rebuilding the
        #: engine (e.g. to attach a late ``can_use_tool``) can carry them over.
        self._multisig_pubkeys: dict[str, bytes] | None = (
            dict(multisig_pubkeys) if multisig_pubkeys else None
        )
        #: Permission scopes (epochs) for lifetime-bound approvals. None
        #: (the default) disables scope checks: zero behaviour change.
        self.scope_manager = scope_manager
        #: Wall-clock for approval-receipt freshness checks. Separate from
        #: ``_now`` (monotonic, for durations): receipt ``decided_at`` is a
        #: wall-clock timestamp. Injectable for deterministic tests.
        self._wall_now = wall_now or time.time
        #: Composition-closure rules (APC-style): forbidden action sequences.
        #: Empty (the default) disables the check: zero behaviour change.
        self._composition_rules: tuple[CompositionRule, ...] = tuple(composition_rules or ())
        #: Maps tool names to action categories for composition rules.
        self._tool_categories: dict[str, str] = dict(tool_categories or {})
        # Canonical category map: variant spellings resolve to the same category.
        self._tool_categories_canonical: dict[str, str] = {
            canonical_tool_name(n): c for n, c in (tool_categories or {}).items()
        }
        #: Recent call history as category labels, for composition checks.
        #: Bounded; only categories (not arguments) are retained.
        if composition_history is not None and (
            not isinstance(composition_history, deque) or composition_history.maxlen != 32
        ):
            raise ValueError("composition_history must be a deque with maxlen=32")
        self._category_history: deque[str] = (
            composition_history if composition_history is not None else deque(maxlen=32)
        )
        #: Optional SEC 15c3-5-style pre-trade risk checks (layer 0). None
        #: (the default) disables them: zero behaviour change.
        self.pretrade = pretrade
        #: Host audit seam. Every *deny* is reported here synchronously,
        #: before the decision is returned, carrying its rejection condition
        #: code — the host wires this to the audit chain.
        self._audit_sink = audit_sink
        self._now = now or time.monotonic
        # Pre-trade observation state: measured facts about calls the gate
        # has seen — never approval state. Bounded and pruned on every
        # evaluation. (Approval decisions themselves are still never
        # cached: see the ``evaluate`` docstring.)
        self._pt_rate: dict[str, deque[float]] = {}
        self._pt_seen: dict[tuple[str, str], float] = {}

    @property
    def multisig_pubkeys(self) -> Mapping[str, bytes] | None:
        """Approver public keys, or None when multisig is not configured."""
        return self._multisig_pubkeys

    @property
    def audit_sink(self) -> Callable[[dict[str, Any]], None] | None:
        """Host audit seam, or None when no sink is wired.

        Kept public so hosts rebuilding the engine (child runtimes, late
        ``can_use_tool`` attachment) can carry the sink over instead of
        silently dropping denial reporting.
        """
        return self._audit_sink

    def pretrade_reset(self) -> None:
        """Clear pre-trade observation windows (rate counters, duplicate fingerprints)."""
        self._pt_rate.clear()
        self._pt_seen.clear()

    # -- layer helpers -----------------------------------------------------
    @property
    def mode(self) -> PermissionMode:
        return self.config.mode

    def knows(self, tool_name: str) -> bool:
        return tool_name in self._kinds

    @property
    def composition_enabled(self) -> bool:
        return bool(self._composition_rules)

    @property
    def composition_history(self) -> tuple[str, ...]:
        return tuple(self._category_history)

    @property
    def composition_policy_digest(self) -> str:
        """Stable identity for the sequence policy carried by checkpoints."""
        payload = {
            "rules": [
                {"sequence": list(rule.sequence), "description": rule.description}
                for rule in self._composition_rules
            ],
            "tool_categories": sorted(self._tool_categories.items()),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def restore_composition_history(self, history: Sequence[str]) -> None:
        """Restore the bounded, category-only state from a verified checkpoint."""
        if len(history) > 32 or any(not isinstance(item, str) or len(item) > 256 for item in history):
            raise ValueError("composition history must contain at most 32 category labels of at most 256 characters")
        self._category_history.clear()
        self._category_history.extend(history)

    def register_kind(self, tool_name: str, kind: str) -> None:
        self._kinds[tool_name] = kind

    def evaluate(
        self,
        tool_name: str,
        *,
        kind: str | None = None,
        mutating: bool | None = None,
        payload: dict[str, Any] | None = None,
        context: PermissionRequestContext | None = None,
        known: bool = True,
        dataflow: SessionDataflow | None = None,
        record_composition: bool = True,
    ) -> PermissionDecision:
        """Run the three layers for one call, plus the dataflow dimension.

        Every decision -- allow or deny, from any layer including the
        early-return layers (scope, argument policies, dataflow escalation)
        -- is reported to the host's ``audit_sink`` synchronously before it
        is returned.  With no sink configured this is a pure pass-through.
        """
        decision = self._evaluate_unaudited(
            tool_name,
            kind=kind,
            mutating=mutating,
            payload=payload,
            context=context,
            known=known,
            dataflow=dataflow,
            record_composition=record_composition,
        )
        if not decision.allowed:
            return self._audit_deny(decision, context)
        return self._audit_allow(decision, context)

    def _evaluate_unaudited(
        self,
        tool_name: str,
        *,
        kind: str | None = None,
        mutating: bool | None = None,
        payload: dict[str, Any] | None = None,
        context: PermissionRequestContext | None = None,
        known: bool = True,
        dataflow: SessionDataflow | None = None,
        record_composition: bool = True,
    ) -> PermissionDecision:
        """Run the three layers for one call, plus the dataflow dimension.

        ``dataflow`` is a :class:`dataflow_policy.SessionDataflow` tracking
        this session's data sensitivity (OpenAPPA-style: source ``delta``
        labels, sink ``requires`` checks, from a deterministic TOML policy).
        When ``None`` (the default) the gate behaves exactly as before.

        The dataflow layer sits *between* the allow-list and the mode layer:
        an auto-allowed sink call whose trajectory is hotter than the sink
        may receive escalates to the host approval callback (tier upgrade).
        Denials always stand — a denied call attaches no label, because a
        denied call produces no data. Escalation is skipped under
        ``bypassPermissions``: bypass means the host opted out of being
        asked, and escalation *is* asking the host.
        """
        payload = dict(payload or {})
        # Canonicalize the tool name for all policy matching: spelling
        # variants ("bash", "  Bash  ") resolve to the same identity, so a
        # forbidden action can't bypass the gate via renaming. The canonical
        # name is what the decision records.
        # Note: tool_name is NOT blanket-canonicalized here; policy matching
        # uses canonical sets (_disallowed_canonical etc.), preserving the
        # original spelling for callbacks, dataflow, and decision records.
        # Permission lifetime: if the request belongs to a scope that has
        # been closed, deny immediately. This revokes lingering authority
        # when a subgoal/phase ends (PORTICO-style).
        if (
            self.scope_manager is not None
            and context is not None
            and context.scope_id
            and not self.scope_manager.is_open(context.scope_id)
        ):
            return PermissionDecision(
                False,
                source="scope",
                reason=f"scope {context.scope_id!r} is closed; permission expired",
                rule="scope:closed",
                tool=tool_name,
            )
        # Authority ceiling (gated ascent): within an open scope that has a
        # ceiling, tools outside the ceiling need explicit host approval --
        # even if they'd normally be auto-allowed. Contraction is free;
        # expansion needs evidence.
        if (
            self.scope_manager is not None
            and context is not None
            and context.scope_id
            and not self.scope_manager.within_ceiling(context.scope_id, tool_name)
        ):
            return self._ceiling_ascent_decision(tool_name, payload, context)
        # Offensive tooling is deny-by-default (Spain AEPD, Sept 2026).
        # The host can explicitly allowlist via offensive_allowlist.
        if is_offensive_tool(tool_name):
            allowed_names = {_offensive_tool_identity(n) for n in self.config.offensive_allowlist}
            if _offensive_tool_identity(tool_name) not in allowed_names:
                return PermissionDecision(
                    False,
                    source="offensive",
                    reason=f"{tool_name} matches offensive-security tooling patterns; explicitly allowlist to enable",
                    rule="offensive:deny_by_default",
                    tool=tool_name,
                )
        shell_scan_source = _shell_scan_source(payload) if canonical_tool_name(tool_name) == "shell" else None
        if shell_scan_source is not None:
            allowed_names = {_offensive_tool_identity(n) for n in self.config.offensive_allowlist}
            for executable in offensive_shell_commands(shell_scan_source):
                if executable == _OFFENSIVE_SCAN_INCOMPLETE:
                    return PermissionDecision(
                        False,
                        source="offensive",
                        reason="Shell command syntax exceeds the scanner's safe parse boundary; refusing it",
                        rule="offensive:shell_scan_incomplete",
                        tool=tool_name,
                    )
                if _offensive_tool_identity(executable) not in allowed_names:
                    return PermissionDecision(
                        False,
                        source="offensive",
                        reason=f"Shell directly invokes offensive-security executable {executable!r}; explicitly allowlist to enable",
                        rule="offensive:shell_executable_deny_by_default",
                        tool=tool_name,
                    )
        # Argument-level policies (opt-in): check critical argument values
        # before the normal layers. A violation denies immediately.
        if self.config.argument_policies and payload:
            for policy in self.config.argument_policies:
                if canonical_tool_name(policy.tool) != canonical_tool_name(tool_name):
                    continue
                if policy.argument not in payload:
                    continue
                violation = policy.check(payload[policy.argument])
                if violation is not None:
                    return PermissionDecision(
                        False,
                        source="argument",
                        reason=violation + (f" ({policy.description})" if policy.description else ""),
                        rule="argument:policy_violation",
                        tool=tool_name,
                    )
        sink_verdict = (
            dataflow.check_sink(tool_name, payload) if dataflow is not None else None
        )
        decision = self._evaluate_base(
            tool_name,
            kind=kind,
            mutating=mutating,
            payload=payload,
            context=context,
            known=known,
        )
        # Composition closure (APC-style): an allowed call may still be
        # forbidden because of what came before it. Checked before the
        # dataflow early-return so it applies with or without dataflow.
        # Only allowed calls extend the history -- a denied call never happened.
        if decision.allowed and self._composition_rules and record_composition:
            composition_deny = self._check_composition(tool_name)
            if composition_deny is not None:
                return composition_deny
            category = self._tool_categories_canonical.get(canonical_tool_name(tool_name))
            if category:
                self._category_history.append(category)
        if dataflow is None or not decision.allowed:
            return decision
        # The call will execute: its result carries the source label, so the
        # trajectory learns it now. (A denied call produces no data and
        # attaches nothing.) Keep a content-free summary on the decision so
        # the synchronous audit sink can seal the label transition too.
        source_rule = dataflow.observe(tool_name, payload)
        dataflow_evidence: dict[str, Any] = {
            "trust": dataflow.policy.rank_name(dataflow.trust_index),
            "audience_labeled": dataflow.audience_labeled,
            "audience_unknown": dataflow.audience_unknown,
            "audience_count": len(dataflow.audience),
        }
        if source_rule is not None:
            dataflow_evidence["source_rule"] = source_rule.tool
        if (
            sink_verdict is not None
            and sink_verdict.escalate
            and self.config.mode != "bypassPermissions"
        ):
            dataflow_evidence["sink_escalated"] = True
            decision = self._apply_dataflow_escalation(
                tool_name, payload, context, sink_verdict
            )
            return replace(
                decision,
                details={**decision.details, "dataflow": dataflow_evidence},
            )
        if source_rule is not None:
            return replace(
                decision,
                details={**decision.details, "dataflow": dataflow_evidence},
            )
        return decision

    def _ceiling_ascent_decision(
        self,
        tool_name: str,
        payload: dict[str, Any],
        context: PermissionRequestContext,
    ) -> PermissionDecision:
        """Gated ascent: a tool outside the scope ceiling needs host approval.

        The host callback is consulted directly. An approval here is the
        "evidence" that justifies expansion; without a callback (or on
        denial) the call fails closed. Approvals do NOT raise the ceiling --
        the next call for the same tool will ask again.
        """
        callback = self.config.can_use_tool
        if callback is None:
            return PermissionDecision(
                False,
                source="scope",
                reason=(
                    f"{tool_name} is outside the scope {context.scope_id!r} authority "
                    "ceiling and no host approval callback is configured; failing closed"
                ),
                rule="ceiling:needs_approval",
                tool=tool_name,
            )
        try:
            verdict = callback(tool_name, copy.deepcopy(payload), context)
        except Exception as error:  # noqa: BLE001 - a broken approver must not grant access
            return PermissionDecision(
                False,
                source="host_callback",
                reason=f"host approval callback raised {type(error).__name__}; failing closed",
                rule="host_callback:error",
                tool=tool_name,
            )
        approved, note = _approval_verdict(verdict)
        if approved:
            return PermissionDecision(
                True,
                source="host_callback",
                reason=note or f"{tool_name} approved for ceiling ascent by host",
                rule="ceiling:ascent_approved",
                tool=tool_name,
            )
        return PermissionDecision(
            False,
            source="host_callback",
            reason=note or f"{tool_name} denied for ceiling ascent by host",
            rule="ceiling:ascent_denied",
            tool=tool_name,
        )

    def _check_composition(self, tool_name: str) -> PermissionDecision | None:
        """Check whether this call completes a forbidden action sequence.

        Returns a denial if the recent history plus this call's category
        matches a CompositionRule; None otherwise. Uses the shared
        trace_violates_rules() contract -- the same artifact the bench
        uses offline.
        """
        category = self._tool_categories_canonical.get(canonical_tool_name(tool_name))
        if not category:
            return None
        # The candidate trace: history + this call.
        trace = [*self._category_history, category]
        rule = trace_violates_rules(trace, self._composition_rules)
        if rule is not None:
            return PermissionDecision(
                False,
                source="composition",
                reason=(
                    f"forbidden action sequence: {' -> '.join(rule.sequence)}"
                    + (f" ({rule.description})" if rule.description else "")
                ),
                rule="composition:forbidden_sequence",
                tool=tool_name,
            )
        return None

    def _apply_dataflow_escalation(
        self,
        tool_name: str,
        payload: dict[str, Any],
        context: PermissionRequestContext | None,
        sink_verdict: SinkVerdict,
    ) -> PermissionDecision:
        """Upgrade an auto-allowed sink call to host approval (or deny)."""
        if self.config.can_use_tool is None:
            return PermissionDecision(
                False,
                source="mode",
                reason=(
                    f"{tool_name} would move labelled data to a sink that may not "
                    f"receive it ({sink_verdict.reason}), and this run has no host "
                    f"approval callback, so it is denied under "
                    f"permission_mode={self.config.mode}"
                ),
                rule=f"mode:{self.config.mode}:dataflow_no_callback",
                tool=tool_name,
            )
        request = context or PermissionRequestContext(
            mode=self.config.mode,
            reason_hint=f"{tool_name} carries labelled data to a restricted sink",
        )
        if not request.arguments_digest:
            request = replace(request, arguments_digest=digest_arguments(payload))
        try:
            verdict = self.config.can_use_tool(tool_name, copy.deepcopy(payload), request)
        except Exception as error:  # noqa: BLE001 - a broken approver must not grant access
            return PermissionDecision(
                False,
                source="host_callback",
                reason=f"host approval callback raised {type(error).__name__}; failing closed",
                rule="host_callback:error",
                tool=tool_name,
            )
        approved, note = _approval_verdict(verdict)
        if approved:
            return PermissionDecision(
                True,
                source="host_callback",
                reason=(
                    f"{tool_name} approved by host approval callback after dataflow "
                    f"escalation ({sink_verdict.reason})"
                ),
                rule="dataflow:escalation:approved",
                tool=tool_name,
            )
        return PermissionDecision(
            False,
            source="host_callback",
            reason=note
            or f"{tool_name} refused by host approval callback after dataflow escalation",
            rule="host_callback:deny",
            tool=tool_name,
        )

    def _evaluate_base(
        self,
        tool_name: str,
        *,
        kind: str | None = None,
        mutating: bool | None = None,
        payload: dict[str, Any] | None = None,
        context: PermissionRequestContext | None = None,
        known: bool = True,
    ) -> PermissionDecision:
        """Decide one tool call: pre-trade checks, then the three layers.

        ``kind``/``mutating`` normally come from the tool's own
        :class:`~tools.ToolSpec`; the delegation gate passes only names, which is
        why the engine keeps a name→kind map as well.

        The engine keeps no approval state between calls: a gated call always
        re-invokes the host callback, so an approval granted for one
        (``call_id``, ``arguments_digest``) pair can never authorize another
        call. Reusing an old approval for new arguments fails closed because
        the callback is asked again, not because a cache is consulted.

        Two post-decision duties live here, not in the layers below: an
        *allowed* call seeds the pre-trade duplicate window (a resubmission
        after a rejection is not a duplicate of anything), and every *deny*
        is reported to the host's ``audit_sink`` synchronously, before the
        decision is returned.
        """
        decision = self._evaluate_inner(
            tool_name,
            kind=kind,
            mutating=mutating,
            payload=payload,
            context=context,
            known=known,
        )
        if self.pretrade is not None and decision.allowed:
            try:
                digest = digest_arguments(payload or {})
            except ValueError:
                digest = ""
            if digest:
                self._pt_seen[(tool_name, digest)] = self._now()
        return decision

    def _evaluate_inner(
        self,
        tool_name: str,
        *,
        kind: str | None = None,
        mutating: bool | None = None,
        payload: dict[str, Any] | None = None,
        context: PermissionRequestContext | None = None,
        known: bool = True,
    ) -> PermissionDecision:
        """The three layers, preceded by the optional pre-trade checks."""
        if self.pretrade is not None:
            pretrade_decision = self._pretrade_check(tool_name, payload or {})
            if pretrade_decision is not None:
                return pretrade_decision
        resolved_kind = kind or self._kinds_canonical.get(canonical_tool_name(tool_name)) or "other"
        if resolved_kind not in {"read", "edit", "exec", "task", "network", "other"}:
            resolved_kind = "other"
        is_mutating = (resolved_kind in MUTATING_KINDS) if mutating is None else bool(mutating)

        # Canonical name for policy matching (spelling variants can't bypass).
        canonical = canonical_tool_name(tool_name)
        if canonical in self._disallowed_canonical:
            return PermissionDecision(
                False,
                source="disallowed_tools",
                reason=f"{tool_name} is listed in disallowed_tools",
                rule="disallowed_tools",
                tool=tool_name,
            )
        if not known and resolved_kind != "task":
            return PermissionDecision(
                False,
                source="unknown_tool",
                reason=f"{tool_name} is not a registered tool, so no policy applies to it",
                rule="registered_tools",
                tool=tool_name,
            )
        if canonical in self._allowed_canonical:
            return PermissionDecision(
                True,
                source="allowed_tools",
                reason=f"{tool_name} is auto-approved by allowed_tools",
                rule="allowed_tools",
                tool=tool_name,
            )
        if self.config.mode == "bypassPermissions":
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} approved under permission_mode=bypassPermissions",
                rule="mode:bypassPermissions",
                tool=tool_name,
            )
        if self.config.mode == "plan":
            if is_mutating:
                return PermissionDecision(
                    False,
                    source="mode",
                    reason=f"plan mode is read-only; {tool_name} would change state",
                    rule="mode:plan",
                    tool=tool_name,
                )
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is read-only, permitted in plan mode",
                rule="mode:plan",
                tool=tool_name,
            )
        if not is_mutating:
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is read-only, permitted in {self.config.mode} mode",
                rule=f"mode:{self.config.mode}",
                tool=tool_name,
            )
        if self.config.mode == "acceptEdits" and resolved_kind == "edit":
            return PermissionDecision(
                True,
                source="mode",
                reason=f"{tool_name} is a workspace edit, auto-approved by acceptEdits",
                rule="mode:acceptEdits",
                tool=tool_name,
            )
        request = context or PermissionRequestContext(
            mode=self.config.mode, reason_hint=f"{tool_name} is mutating"
        )
        # The approver must always see the digest of the exact arguments being
        # decided on: if the caller did not pin it, derive it here so a
        # decision can never be detached from its arguments.
        if not request.arguments_digest:
            try:
                pinned = digest_arguments(payload or {})
            except ValueError:
                return PermissionDecision(
                    False,
                    source="pretrade",
                    reason=(
                        f"{tool_name} denied: call arguments are not "
                        "JSON-serialisable, so no approval can be bound to them"
                    ),
                    rule=PT_FACT_MISSING,
                    tool=tool_name,
                )
            request = replace(request, arguments_digest=pinned)
        if self.config.decision_model is not None:
            model_decision = self._evaluate_with_decision_model(
                tool_name, resolved_kind, is_mutating, request
            )
            if model_decision is not None:
                return model_decision
            # The model escalated or failed: fall through to the existing
            # host-callback path. The model path never grants on error.
        if self.config.can_use_tool is None:
            return PermissionDecision(
                False,
                source="mode",
                reason=(
                    f"{tool_name} changes state and this run has no host approval callback, "
                    f"so it is denied under permission_mode={self.config.mode}"
                ),
                rule=f"mode:{self.config.mode}:no_callback",
                tool=tool_name,
            )
        request = context or PermissionRequestContext(
            mode=self.config.mode, reason_hint=f"{tool_name} is mutating"
        )
        # The approver must always see the digest of the exact arguments being
        # decided on: if the caller did not pin it, derive it here so a
        # decision can never be detached from its arguments. A missing fact
        # is a block, not an exception and not a pass: arguments the gate
        # cannot fingerprint cannot carry a bound approval.
        if not request.arguments_digest:
            try:
                pinned = digest_arguments(payload or {})
            except ValueError:
                return PermissionDecision(
                    False,
                    source="pretrade",
                    reason=(
                        f"{tool_name} denied: call arguments are not "
                        "JSON-serialisable, so no approval can be bound to them"
                    ),
                    rule=PT_FACT_MISSING,
                    tool=tool_name,
                )
            request = replace(request, arguments_digest=pinned)
        try:
            verdict = self.config.can_use_tool(tool_name, copy.deepcopy(payload or {}), request)
        except Exception as error:  # noqa: BLE001 - a broken approver must not grant access
            return PermissionDecision(
                False,
                source="host_callback",
                reason=f"host approval callback raised {type(error).__name__}; failing closed",
                rule="host_callback:error",
                tool=tool_name,
            )
        approved, note = _approval_verdict(verdict)
        # Signed-approval tier (opt-in): if the callback returned a signed
        # receipt and approver keys are configured, verify it. A valid
        # signature binds the approval to a verified identity.
        verified_approver: str | None = None
        if approved and isinstance(verdict, dict) and "approval_receipt" in verdict:
            verified_approver = self._verify_approval_receipt(verdict["approval_receipt"])
            if verified_approver is None and self.config.approver_keys:
                return PermissionDecision(
                    False,
                    source="host_callback",
                    reason="signed approval receipt failed verification; failing closed",
                    rule="host_callback:bad_signature",
                    tool=tool_name,
                )
        if approved:
            if self._multisig_gate is not None:
                return self._multisig_decision(tool_name, request)
            reason = note or f"{tool_name} approved by host approval callback"
            if verified_approver:
                reason = f"{tool_name} approved by verified approver {verified_approver}"
            return PermissionDecision(
                True,
                source="host_callback",
                reason=reason,
                rule="host_callback:allow",
                tool=tool_name,
            )
        return PermissionDecision(
            False,
            source="host_callback",
            reason=note or f"{tool_name} refused by host approval callback",
            rule="host_callback:deny",
            tool=tool_name,
        )

    def _verify_approval_receipt(self, receipt_dict: Any) -> str | None:
        """Verify a signed approval receipt. Returns approver_id or None.

        Returns None when no approver keys are configured (tier disabled)
        or when verification fails. Never raises.
        """
        if not self.config.approver_keys:
            return None
        try:
            from egress_enforcer import ApprovalReceipt, verify_approval_receipt

            if not isinstance(receipt_dict, dict):
                return None
            receipt = ApprovalReceipt(
                card_id=str(receipt_dict.get("card_id", "")),
                call_id=str(receipt_dict.get("call_id", "")),
                arguments_digest=str(receipt_dict.get("arguments_digest", "")),
                approver_id=str(receipt_dict.get("approver_id", "")),
                decided_at=float(receipt_dict.get("decided_at", 0)),
                body_sha256=str(receipt_dict.get("body_sha256", "")),
                signature=str(receipt_dict.get("signature", "")),
            )
            pubkey = self.config.approver_keys.get(receipt.approver_id)
            if pubkey is None:
                return None
            if verify_approval_receipt(receipt, pubkey, now=self._wall_now()):
                return receipt.approver_id
            return None
        except (ValueError, TypeError, KeyError):
            return None

    def _multisig_decision(
        self, tool_name: str, request: PermissionRequestContext
    ) -> PermissionDecision:
        """Upgrade a single-approver ASK to m-of-n multisig.

        The host callback has already said yes; that is now necessary but not
        sufficient. The presented signatures are verified here, by the gate
        itself, against the enrolled approver keys and the exact
        ``(call_id, arguments_digest)`` pair — the callback's word is never
        trusted for the signature check. Approver identities and signature
        hexes ride along in ``details`` so the audit chain records exactly
        who signed what.
        """
        gate = self._multisig_gate
        assert gate is not None  # noqa: S101 - guarded by the caller
        verdict = gate.check(
            request.call_id, request.arguments_digest, request.multisig_signatures
        )
        details = verdict.as_dict()
        details["signatures"] = [
            sig.as_dict() for sig in request.multisig_signatures or ()
        ]
        if verdict.allowed:
            return PermissionDecision(
                True,
                source="multisig",
                reason=verdict.reason,
                rule=f"multisig:{gate.policy.threshold}-of-{gate.policy.n}",
                tool=tool_name,
                details=details,
            )
        return PermissionDecision(
            False,
            source="multisig",
            reason=verdict.reason,
            rule=f"multisig:{gate.policy.threshold}-of-{gate.policy.n}:not_met",
            tool=tool_name,
            details=details,
        )

    @staticmethod
    def _pretrade_deny(tool_name: str, code: str, detail: str) -> PermissionDecision:
        return PermissionDecision(
            False,
            source="pretrade",
            reason=f"{tool_name} denied by pre-trade risk control [{code}]: {detail}",
            rule=code,
            tool=tool_name,
        )

    def _pretrade_check(
        self, tool_name: str, payload: dict[str, Any]
    ) -> PermissionDecision | None:
        """Run the four independent pre-trade conditions; first deny wins.

        Structural validation runs *before* any limit comparison: a fact a
        check needs that is missing or malformed denies with
        ``pretrade:fact_missing`` — never an exception, never a pass. When
        several conditions fire, all of their codes are reported (no
        masking). Only host-owned inputs are read here — the config, the
        host's ``value_of``/``reference_of`` extractors, and engine-measured
        facts (canonical bytes, digest, timestamps). Nothing model-supplied
        (``PermissionRequestContext.data``, ``reason_hint``, prompt claims)
        can move any of these checks: that is the 15c3-5(d) "direct and
        exclusive control" half of this design.
        """
        cfg = self.pretrade
        assert cfg is not None  # noqa: S101 - guarded by the caller
        now = self._now()

        # -- structural validation first ------------------------------------
        try:
            canonical = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        except (TypeError, ValueError):
            return self._pretrade_deny(
                tool_name,
                PT_FACT_MISSING,
                "call arguments are not JSON-serialisable; the gate cannot "
                "fingerprint the call, so it is denied",
            )
        digest = "sha256:" + hashlib.sha256(canonical).hexdigest()

        fired: list[PermissionDecision] = []

        # -- PT-1 price/value ------------------------------------------------
        if cfg.value_of is not None:
            try:
                # Extractors are host code, but they must not be able to
                # mutate the arguments that later receive approval/execution.
                value = cfg.value_of(tool_name, copy.deepcopy(payload))
            except Exception:
                return self._pretrade_deny(
                    tool_name,
                    PT_FACT_MISSING,
                    "host value extractor raised; failing closed",
                )
            if (
                value is None
                or isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                # NaN / negative / missing values defeat every comparison
                # they participate in — fail closed, not open.
                return self._pretrade_deny(
                    tool_name,
                    PT_FACT_MISSING,
                    f"call value fact is missing or malformed ({value!r}); "
                    "failing closed",
                )
            if cfg.max_call_value is not None and value > cfg.max_call_value:
                fired.append(
                    self._pretrade_deny(
                        tool_name,
                        f"{PT_PRICE}:value_exceeded",
                        f"call value {value} exceeds max_call_value "
                        f"{cfg.max_call_value}",
                    )
                )
            if cfg.reference_of is not None:
                try:
                    reference = cfg.reference_of(tool_name, copy.deepcopy(payload))
                except Exception:
                    return self._pretrade_deny(
                        tool_name,
                        PT_FACT_MISSING,
                        "host reference extractor raised; failing closed",
                    )
                if (
                    reference is None
                    or isinstance(reference, bool)
                    or not isinstance(reference, (int, float))
                    or not math.isfinite(reference)
                    or reference <= 0
                ):
                    # An unusable reference price blocks the call; it never
                    # skips the collar check (a data outage must not disarm
                    # the fat-finger control).
                    return self._pretrade_deny(
                        tool_name,
                        PT_FACT_MISSING,
                        "reference price unavailable or unusable; the collar "
                        "cannot be evaluated, so the call is denied",
                    )
                if abs(value - reference) > cfg.price_collar * reference:
                    fired.append(
                        self._pretrade_deny(
                            tool_name,
                            f"{PT_PRICE}:price_exceeded",
                            f"call value {value} strays beyond the "
                            f"{cfg.price_collar:.0%} collar around reference "
                            f"{reference}",
                        )
                    )

        # -- PT-2 size --------------------------------------------------------
        if cfg.max_payload_bytes is not None and len(canonical) > cfg.max_payload_bytes:
            fired.append(
                self._pretrade_deny(
                    tool_name,
                    f"{PT_SIZE}:size_exceeded",
                    f"payload {len(canonical)} bytes exceeds max_payload_bytes "
                    f"{cfg.max_payload_bytes}",
                )
            )

        # -- PT-3 rate ---------------------------------------------------------
        if cfg.max_calls_per_window is not None:
            window = self._pt_rate.setdefault(tool_name, deque())
            cutoff = now - cfg.window_seconds
            while window and window[0] <= cutoff:
                window.popleft()
            # A rejected call still consumed a message the gate had to
            # handle, so it counts toward the burst budget.
            window.append(now)
            if len(window) > cfg.max_calls_per_window:
                fired.append(
                    self._pretrade_deny(
                        tool_name,
                        f"{PT_RATE}:rate_exceeded",
                        f"{len(window)} calls in {cfg.window_seconds:g}s exceeds "
                        f"max_calls_per_window {cfg.max_calls_per_window}",
                    )
                )

        # -- PT-4 duplicates -----------------------------------------------------
        cutoff = now - cfg.dedupe_window_seconds
        stale = [key for key, seen_at in self._pt_seen.items() if seen_at <= cutoff]
        for key in stale:
            del self._pt_seen[key]
        if (tool_name, digest) in self._pt_seen:
            fired.append(
                self._pretrade_deny(
                    tool_name,
                    f"{PT_DUPLICATE}:duplicate",
                    "identical (tool, arguments_digest) already passed the gate "
                    f"within {cfg.dedupe_window_seconds:g}s",
                )
            )
        # NOTE: the window is seeded only for allowed calls, in evaluate().

        if not fired:
            return None
        if len(fired) == 1:
            return fired[0]
        codes = ", ".join(d.rule for d in fired[1:])
        first = fired[0]
        return replace(first, reason=f"{first.reason} (also fired: {codes})")

    def _audit_deny(
        self, decision: PermissionDecision, context: PermissionRequestContext | None
    ) -> PermissionDecision:
        """Report every deny to the host's audit sink, synchronously.

        The record carries the rejection condition code (``decision.rule``)
        so each denial traces to its rule — the surveillance-trail half of
        the 15c3-5 design ((c)(2)(iv) style). The sink runs *inside*
        ``evaluate()``, before the decision is returned: when ``evaluate()``
        hands back a deny, the record is already written. A raising sink
        cannot flip the denial — the failure is made visible in the reason
        instead of being silently swallowed.
        """
        sink = self._audit_sink
        if sink is None:
            return decision
        ctx = context if context is not None else PermissionRequestContext()
        record = {
            "event": "permission.deny",
            "tool": decision.tool,
            "source": decision.source,
            "rule": decision.rule,
            "condition": decision.rule,
            "reason": decision.reason,
            "call_id": ctx.call_id,
            "arguments_digest": ctx.arguments_digest,
            "session_id": ctx.session_id,
            "agent": ctx.agent,
            "mode": ctx.mode,
        }
        if decision.details:
            record["details"] = decision.details
        try:
            # Audit sinks are extension code. Do not let a logger's in-place
            # redaction/normalization mutate the decision object returned to
            # the runtime (notably its structured dataflow evidence).
            sink(copy.deepcopy(record))
        except Exception as error:  # noqa: BLE001 - the denial stands regardless
            return replace(
                decision,
                reason=f"{decision.reason} [audit_sink_failed:{type(error).__name__}]",
            )
        return decision

    def _audit_allow(
        self, decision: PermissionDecision, context: PermissionRequestContext | None
    ) -> PermissionDecision:
        """Report every allow to the host's audit sink, synchronously.

        Mirrors ``_audit_deny``: the record is written inside ``evaluate()``,
        before the decision is returned, so an allow always has a gate-side
        authorization record — not just the model's own request. This closes
        the EU AI Act Art. 12 gap where a crash between gate-allow and tool
        execution left the authorization state unprovable.
        """
        sink = self._audit_sink
        if sink is None:
            return decision
        ctx = context if context is not None else PermissionRequestContext()
        record = {
            "event": "permission.allow",
            "tool": decision.tool,
            "source": decision.source,
            "rule": decision.rule,
            "condition": decision.rule,
            "reason": decision.reason,
            "call_id": ctx.call_id,
            "arguments_digest": ctx.arguments_digest,
            "session_id": ctx.session_id,
            "agent": ctx.agent,
            "mode": ctx.mode,
        }
        if decision.details:
            record["details"] = decision.details
        try:
            sink(copy.deepcopy(record))
        except Exception as error:  # noqa: BLE001 - execution requires a confirmed allow record
            return PermissionDecision(
                False,
                source="audit",
                reason=(
                    f"authorization audit sink raised {type(error).__name__}; "
                    "execution is denied because the allow record could not be confirmed"
                ),
                rule="audit:write_failed",
                tool=decision.tool,
                details=decision.details,
            )
        return decision

    def evaluate_spec(
        self,
        spec: Any,
        payload: dict[str, Any] | None = None,
        *,
        context: PermissionRequestContext | None = None,
        known: bool = True,
        dataflow: SessionDataflow | None = None,
    ) -> PermissionDecision:
        return self.evaluate(
            spec.name,
            kind=spec.kind,
            mutating=spec.is_mutating,
            payload=payload,
            context=context,
            known=known,
            dataflow=dataflow,
        )

    # -- decision-model path -------------------------------------------------
    def _evaluate_with_decision_model(
        self,
        tool_name: str,
        kind: str,
        mutating: bool,
        request: PermissionRequestContext,
    ) -> PermissionDecision | None:
        """Offer the call to the structured decision model.

        Returns a decision for ``allow``/``deny`` outcomes, or ``None`` when
        the model escalates or fails -- the caller then falls through to the
        host-callback path. A broken model never grants access.
        """
        model = self.config.decision_model
        assert model is not None  # noqa: S101 - guarded by the caller
        state = build_decision_state(
            tool_name,
            kind=kind,
            mutating=mutating,
            context=request,
            payload_digest=request.arguments_digest,
        )
        questions = approval_questions()
        policy = self.config.decision_policy
        model_error: str | None = None
        try:
            result = model.decide(state, questions)
            outcome, reason = adjudicate(result, policy)
        except Exception as error:  # noqa: BLE001 - a broken model must not grant access
            result = DecisionModelResult(
                answers={}, model=getattr(model, "model_name", "")
            )
            outcome, reason = (
                "escalate",
                f"decision model raised {type(error).__name__}; "
                "deferring to host callback",
            )
            model_error = f"{type(error).__name__}: {error}"
        audit = build_decision_audit(
            state=state,
            questions=questions,
            result=result,
            policy=policy,
            outcome=outcome,
            reason=reason,
            model_error=model_error,
        )
        if outcome == "allow":
            return PermissionDecision(
                True,
                source="decision_model",
                reason=reason,
                rule="decision_model:allow",
                tool=tool_name,
                decision_model_audit=audit,
            )
        if outcome == "deny":
            return PermissionDecision(
                False,
                source="decision_model",
                reason=reason,
                rule="decision_model:deny",
                tool=tool_name,
                decision_model_audit=audit,
            )
        return None

    # -- delegation --------------------------------------------------------
    def check_delegation(
        self,
        agent: str,
        tool_names: Sequence[str],
        *,
        kinds: dict[str, str] | None = None,
        context: PermissionRequestContext | None = None,
        disallowed_extra: Iterable[str] = (),
        require_stable_identity: bool = False,
    ) -> DelegationVerdict:
        """Gate a subagent by *each tool it declared*, not by the name ``Task``.

        A delegation is approved only when every tool the subagent may reach is
        approved here. That is what makes "read-only reviewer subagent" a real
        boundary instead of a prompt-level suggestion.

        When ``require_stable_identity`` is set, the ``agent`` identifier must
        be a stable cryptographic identity (key fingerprint or DID), not a
        display name -- arXiv:2609.27624: name collisions route delegation
        to attacker-controlled peers. Off by default for backward compatibility.
        """
        if require_stable_identity and not _is_stable_agent_identity(agent):
            return DelegationVerdict(
                agent=agent,
                allowed=(),
                denied=[(t, "delegation target is not a stable cryptographic identity") for t in tool_names],
                checked=tuple(normalise_names(tool_names)),
            )
        extra = set(normalise_names(disallowed_extra))
        allowed: list[str] = []
        denied: list[tuple[str, str]] = []
        checked: list[str] = []
        for name in normalise_names(tool_names):
            checked.append(name)
            if name in extra:
                denied.append((name, "disallowed for subagents by host policy"))
                continue
            kind = (kinds or self._kinds).get(name, "other")
            # This checks the child's declared capabilities, not a tool action
            # that happened in the current session. Do not let admission
            # checks consume or trigger composition history.
            decision = self.evaluate(
                name,
                kind=kind,
                context=context,
                record_composition=False,
            )
            if decision.allowed:
                allowed.append(name)
            else:
                denied.append((name, decision.reason))
        return DelegationVerdict(agent=agent, allowed=tuple(allowed), denied=tuple(denied), checked=tuple(checked))


def _is_stable_agent_identity(agent: str) -> bool:
    """Check whether an agent identifier is a stable cryptographic identity.

    Delegation targets must be origin-bound identities (key fingerprints,
    DIDs), never human-readable display names -- arXiv:2609.27624 shows
    6/7 integrations dispatch to an attacker peer on name collision.
    Accepted shapes:
    - 64-hex Ed25519 public key (with or without 0x prefix)
    - DID (``did:<method>:...``)
    - ``key:<hex>`` prefixed fingerprints
    """
    if not isinstance(agent, str) or not agent:
        return False
    text = agent.strip()
    # DID
    if text.startswith("did:") and len(text) > 8 and ":" in text[4:]:
        return True
    # Hex fingerprint, with or without 0x.
    hexpart = text[2:] if text.lower().startswith("0x") else text
    if len(hexpart) == 64:
        try:
            bytes.fromhex(hexpart)
            return True
        except ValueError:
            pass
    # key: prefix
    if text.startswith("key:") and len(text) > 12:
        try:
            bytes.fromhex(text[4:])
            return True
        except ValueError:
            pass
    return False


def _approval_verdict(verdict: Any) -> tuple[bool, str]:
    """Accept bool / "allow" / "deny" / {"allowed": bool, "reason": ...}."""
    if isinstance(verdict, bool):
        return verdict, ""
    if isinstance(verdict, str):
        text = verdict.strip().lower()
        if text in {"allow", "approve", "approved", "yes", "true"}:
            return True, ""
        if text in {"deny", "denied", "reject", "no", "false"}:
            return False, ""
        return False, f"unrecognised approval verdict {verdict!r}"
    if isinstance(verdict, dict):
        field = "allowed" if "allowed" in verdict else "allow"
        allowed = verdict.get(field, False)
        if not isinstance(allowed, bool):
            return False, f"approval mapping field {field!r} must be a boolean"
        reason = str(verdict.get("reason", "") or "")
        return allowed, reason
    allowed = getattr(verdict, "allowed", None)
    if isinstance(allowed, bool):
        return allowed, str(getattr(verdict, "reason", "") or "")
    return False, f"unrecognised approval verdict {type(verdict).__name__}"


__all__ = [
    "DelegationVerdict",
    "MUTATING_KINDS",
    "PERMISSION_MODES",
    "PT_DUPLICATE",
    "PT_FACT_MISSING",
    "PT_PRICE",
    "PT_RATE",
    "PT_SIZE",
    "PermissionConfig",
    "PermissionDecision",
    "PermissionEngine",
    "PermissionMode",
    "PermissionRequestContext",
    "PreTradeRiskConfig",
    "ToolKind",
    "digest_arguments",
    "normalise_names",
    "subtract",
    "validate_mode",
]
