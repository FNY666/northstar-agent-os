"""Capability reassembly detector: benign calls that chain into a denied capability.

Grounded in the Asymmetric Security finding ("capability reassembly"):
individually-benign tool calls chained across a session can reconstruct a
powerful capability the agent was never granted. The canonical example is
``httpbin`` (network fetch) + ``urlquery`` (URL parsing) chained to
reconstruct browser-like capability — add ``eval`` and the chain becomes
remote code execution. No single call in that chain looks dangerous; the
*danger is the composition*.

This module is a *tripwire*, not a sandbox: it watches the sequence of
tool calls in a session and flags when the set of tools invoked so far
covers every leg of a known reassembly pattern. It never executes
anything, never touches the network, and makes no model calls.

API:

* :func:`detect_reassembly` — ``True`` when the call sequence completes
  any known pattern.
* :func:`scan_reassembly` — all completed-pattern findings, in pattern
  order.
* :func:`detect_emerging` — patterns that are *partially* assembled
  (early warning before the chain completes).

Tool-call input shape: each call is either a plain string (the tool
name) or a mapping carrying the name under ``tool`` / ``name`` /
``tool_name`` / ``function`` (nested ``arguments``/``args``/``params``/
``input`` mappings are tolerated but not required). Name matching is
case-insensitive; patterns match on the *set* of tools seen, so order
does not matter — a chain is a chain regardless of which leg ran first.

Honest scope: pattern matching on tool *names* is a backstop, not a
proof. A renamed tool, a tool behind an alias, or a novel combination
outside the pattern table passes through. A completed pattern is evidence
of "known dangerous composition observed", never proof of malicious
intent — the gate decides what to do with the flag. Hosts should treat
this as one layer under their own behavioral analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping, Sequence, Tuple

#: Version pin for the pattern table.
CAPABILITY_REASSEMBLY_VERSION = "capability-reassembly.v1"

#: Schema pin stamped on findings for audit logging.
SCHEMA_PIN = "northstar.capability-reassembly.v1"


class ReassemblySeverity(str, Enum):
    """Severity of the reassembled capability."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ReassemblyPattern:
    """One known dangerous composition of individually-benign tools."""

    name: str
    tools: Tuple[str, ...]
    capability: str
    severity: ReassemblySeverity
    description: str


#: The known reassembly pattern table. Each entry names the tools whose
#: *joint* presence in one session reconstructs the named capability.
PATTERNS: Tuple[ReassemblyPattern, ...] = (
    ReassemblyPattern(
        name="browser-rce",
        tools=("httpbin", "urlquery", "eval"),
        capability="remote code execution via reassembled browser capability",
        severity=ReassemblySeverity.CRITICAL,
        description=(
            "network fetch (httpbin) + URL parsing (urlquery) reconstructs "
            "browser-like fetch-and-parse; eval turns the fetched content "
            "into code execution"
        ),
    ),
    ReassemblyPattern(
        name="browser-rce-exec-variant",
        tools=("httpbin", "urlquery", "exec"),
        capability="remote code execution via reassembled browser capability",
        severity=ReassemblySeverity.CRITICAL,
        description=(
            "same as browser-rce with exec instead of eval — the code-runner "
            "leg is interchangeable"
        ),
    ),
    ReassemblyPattern(
        name="shell-download-execute",
        tools=("shell", "curl"),
        capability="arbitrary code download and execution",
        severity=ReassemblySeverity.CRITICAL,
        description=(
            "shell plus a downloader: fetch a payload and run it in one "
            "session"
        ),
    ),
    ReassemblyPattern(
        name="shell-download-execute-wget",
        tools=("shell", "wget"),
        capability="arbitrary code download and execution",
        severity=ReassemblySeverity.CRITICAL,
        description="wget variant of shell-download-execute",
    ),
    ReassemblyPattern(
        name="credential-exfiltration",
        tools=("env", "http_post"),
        capability="environment credential exfiltration",
        severity=ReassemblySeverity.CRITICAL,
        description=(
            "read process environment (env) then POST it out (http_post): "
            "API keys and tokens leave the host"
        ),
    ),
    ReassemblyPattern(
        name="file-exfiltration",
        tools=("read_file", "http_post"),
        capability="file content exfiltration",
        severity=ReassemblySeverity.HIGH,
        description="read a file then POST its contents to an external URL",
    ),
    ReassemblyPattern(
        name="filesystem-takeover",
        tools=("list_dir", "read_file", "write_file"),
        capability="full filesystem read/write",
        severity=ReassemblySeverity.HIGH,
        description=(
            "enumerate, read, and write: the three legs of arbitrary file "
            "manipulation"
        ),
    ),
    ReassemblyPattern(
        name="database-exfiltration",
        tools=("sql_query", "http_post"),
        capability="database content exfiltration",
        severity=ReassemblySeverity.HIGH,
        description="query the database then POST rows to an external URL",
    ),
    ReassemblyPattern(
        name="privilege-read-then-write",
        tools=("read_file", "write_file"),
        capability="file tampering",
        severity=ReassemblySeverity.MEDIUM,
        description=(
            "read-then-write on files: benign in isolation (edit workflows), "
            "flagged so the gate can check the paths involved"
        ),
    ),
    ReassemblyPattern(
        name="recon-then-target",
        tools=("list_dir", "httpbin"),
        capability="targeted network reconnaissance",
        severity=ReassemblySeverity.LOW,
        description=(
            "enumerate local layout then fetch externally: the shape of "
            "reconnaissance feeding target selection"
        ),
    ),
)


@dataclass(frozen=True)
class ReassemblyFinding:
    """One completed reassembly pattern observed in the call sequence."""

    pattern: str
    capability: str
    severity: ReassemblySeverity
    matched_tools: Tuple[str, ...]
    schema: str = SCHEMA_PIN


@dataclass(frozen=True)
class EmergingPattern:
    """A pattern partially assembled — early warning, not a completed chain."""

    pattern: str
    capability: str
    severity: ReassemblySeverity
    matched_tools: Tuple[str, ...]
    missing_tools: Tuple[str, ...]
    coverage: float


def _tool_name(call: object) -> str | None:
    """Extract the tool name from a call record, or None if unparseable."""
    if isinstance(call, str):
        name = call.strip()
        return name.lower() if name else None
    if isinstance(call, Mapping):
        for key in ("tool", "name", "tool_name", "function"):
            value = call.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return None


def _seen_tools(tool_calls: Sequence[object]) -> frozenset:
    """The set of tool names observed in the sequence."""
    if not isinstance(tool_calls, Sequence) or isinstance(tool_calls, (str, bytes)):
        raise TypeError("tool_calls must be a sequence of call records")
    seen: set = set()
    for call in tool_calls:
        name = _tool_name(call)
        if name is not None:
            seen.add(name)
    return frozenset(seen)


def _pattern_coverage(pattern: ReassemblyPattern, seen: frozenset) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    matched = tuple(t for t in pattern.tools if t in seen)
    missing = tuple(t for t in pattern.tools if t not in seen)
    return matched, missing


def detect_reassembly(tool_calls: Sequence[object]) -> bool:
    """True when the call sequence completes any known reassembly pattern.

    Order-independent: a chain is a chain regardless of which leg ran
    first. ``TypeError`` on a non-sequence (programming error);
    unparseable entries inside the sequence are skipped, never fatal.
    """
    seen = _seen_tools(tool_calls)
    for pattern in PATTERNS:
        _, missing = _pattern_coverage(pattern, seen)
        if not missing:
            return True
    return False


def scan_reassembly(tool_calls: Sequence[object]) -> Tuple[ReassemblyFinding, ...]:
    """All completed-pattern findings, in pattern-table order."""
    seen = _seen_tools(tool_calls)
    findings = []
    for pattern in PATTERNS:
        matched, missing = _pattern_coverage(pattern, seen)
        if not missing:
            findings.append(
                ReassemblyFinding(
                    pattern=pattern.name,
                    capability=pattern.capability,
                    severity=pattern.severity,
                    matched_tools=matched,
                )
            )
    return tuple(findings)


def detect_emerging(tool_calls: Sequence[object], threshold: float = 0.5) -> Tuple[EmergingPattern, ...]:
    """Patterns partially assembled at or above ``threshold`` coverage.

    Early warning: the chain is not complete yet, but enough legs have
    run that the gate may want to watch the session more closely.
    Completed patterns are *not* reported here — use
    :func:`scan_reassembly` for those.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise TypeError("threshold must be a number")
    if not 0 < threshold < 1:
        raise ValueError("threshold must be strictly between 0 and 1")
    seen = _seen_tools(tool_calls)
    emerging = []
    for pattern in PATTERNS:
        matched, missing = _pattern_coverage(pattern, seen)
        if missing and matched:
            coverage = len(matched) / len(pattern.tools)
            if coverage >= threshold:
                emerging.append(
                    EmergingPattern(
                        pattern=pattern.name,
                        capability=pattern.capability,
                        severity=pattern.severity,
                        matched_tools=matched,
                        missing_tools=missing,
                        coverage=coverage,
                    )
                )
    return tuple(emerging)


def main() -> None:
    """Self-check smoke: run the canonical reassembly chain."""
    chain = [
        {"tool": "httpbin", "args": {"url": "http://example.com/x"}},
        {"tool": "urlquery", "args": {"q": "a=1"}},
        "eval",
    ]
    assert detect_reassembly(chain) is True
    findings = scan_reassembly(chain)
    assert any(f.pattern == "browser-rce" for f in findings)
    assert detect_reassembly([{"tool": "httpbin"}]) is False
    emerging = detect_emerging([{"tool": "httpbin"}, {"tool": "urlquery"}])
    assert any(e.pattern == "browser-rce" for e in emerging)
    print("capability-reassembly OK: browser-rce chain detected, emerging warned")


if __name__ == "__main__":
    main()
