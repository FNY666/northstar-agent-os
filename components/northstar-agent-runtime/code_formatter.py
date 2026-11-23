"""Code formatter: Black-style formatting bookkeeping.

Simulated interface (Black / Prettier / gofmt lineage). This module books
code *formatting decisions* on host-reported sources: it pins sources with
``sha256:`` digests, applies a deterministic text-level normalization
(normalize line endings, strip trailing whitespace, normalize indentation,
collapse excess blank lines, enforce a final newline), and records every
decision in a frozen audit trail.

Honest scope: this is text-level normalization, not a full formatter. It
cannot parse code, so it deliberately does not wrap long lines, add or
remove magic trailing commas, or normalize string quotes — the
``loss_ledger`` on every :class:`FormatResult` declares exactly which
Black-style behaviors are *not* performed here. ``check()`` reports long
lines as findings instead of fixing them; ``diff()`` shows the text-level
delta via the stdlib ``difflib``. Pair with black / prettier / gofmt for
production formatting.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (no wall-clock), RLock-guarded, fail-closed, stdlib-only.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
CODE_FORMATTER_VERSION = "code-formatter.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.code-formatter.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned language vocabulary. Formatting rules are text-level, so the
#: language is metadata (a routing hint), not a behavior switch.
LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "go",
    "rust",
    "java",
    "c",
    "cpp",
    "csharp",
    "ruby",
    "php",
    "swift",
    "kotlin",
    "scala",
    "sql",
    "json",
    "yaml",
    "toml",
    "markdown",
    "html",
    "css",
    "shell",
    "text",
)

#: Pinned indentation options.
INDENT_STYLES = ("space4", "space2", "tab")

#: Min/max accepted line_length (Black default is 88).
MIN_LINE_LENGTH = 10
MAX_LINE_LENGTH = 240

#: Hard cap on source bytes (guardrail against absurd inputs).
MAX_SOURCE_BYTES = 1024 * 1024

#: Hard cap on registered sources (guardrail).
MAX_SOURCES = 10000

#: Black-style behaviors this module deliberately does NOT perform.
LOSS_LEDGER = (
    "line-wrapping",  # no parsing, so no reflowing over line_length
    "magic-trailing-comma",  # no AST, so no comma-driven layout
    "string-quote-normalization",  # no AST, so quotes are untouched
    "bracket-spacing",  # no token stream, so bracket padding is untouched
)

#: Finding codes emitted by check().
FINDING_CODES = (
    "trailing-whitespace",
    "tab-indentation",
    "crlf-line-ending",
    "excess-blank-lines",
    "line-too-long",
    "missing-final-newline",
)


def _sha256_hex(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _pin(obj: Any) -> str:
    return _sha256_hex(jcs_canonical_json(obj))


class CodeFormatterError(Exception):
    """Base fail-closed code-formatter error."""


class UnknownSourceError(CodeFormatterError):
    """No source registered under this id."""


class DuplicateSourceError(CodeFormatterError):
    """A source with this id is already registered."""


class UnknownLanguageError(CodeFormatterError):
    """Language is not in the pinned LANGUAGES vocabulary."""


class BadOptionError(CodeFormatterError):
    """An option (indent style, line_length) is malformed."""


class SeqOrderError(CodeFormatterError):
    """Caller seq did not strictly increase."""


class ValidationError(CodeFormatterError):
    """A parameter failed validation."""


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"seq must be >= 0, got {value}")
    return value


def _check_source_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError("source_id must be a non-empty str")
    if len(value) > 256:
        raise ValidationError("source_id too long")
    return value


def _check_line_length(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadOptionError(
            f"line_length must be an int, got {type(value).__name__}"
        )
    if not (MIN_LINE_LENGTH <= value <= MAX_LINE_LENGTH):
        raise BadOptionError(
            f"line_length must be in [{MIN_LINE_LENGTH}, {MAX_LINE_LENGTH}]"
        )
    return value


def _check_indent(value: Any) -> str:
    if not isinstance(value, str) or value not in INDENT_STYLES:
        raise BadOptionError(f"indent must be one of {INDENT_STYLES}")
    return value


def _check_language(value: Any) -> str:
    if not isinstance(value, str) or value not in LANGUAGES:
        raise UnknownLanguageError(f"unknown language: {value!r}")
    return value


def _normalize_indent(line: str, indent: str) -> str:
    """Normalize leading whitespace per the indent style."""
    stripped = line.lstrip(" \t")
    leading = line[: len(line) - len(stripped)]
    if not leading:
        return line
    if indent == "tab":
        # Convert each run of 4 leading spaces to one tab; keep real tabs.
        spaces = leading.count(" ")
        tabs = leading.count("\t")
        converted = "\t" * (spaces // 4) + " " * (spaces % 4) + "\t" * tabs
        return converted + stripped
    width = 4 if indent == "space4" else 2
    converted = leading.replace("\t", " " * width)
    return converted + stripped


def _normalize_text(source: str, indent: str) -> str:
    """Apply deterministic text-level normalization rules."""
    text = source.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    out: list = []
    blank_run = 0
    for line in lines:
        line = line.rstrip(" \t")
        line = _normalize_indent(line, indent)
        if line == "":
            blank_run += 1
        else:
            blank_run = 0
        if blank_run <= 2:
            out.append(line)
    text = "\n".join(out)
    if not text.endswith("\n"):
        text += "\n"
    return text


def _check_findings(source: str, line_length: int) -> Tuple[Dict[str, Any], ...]:
    findings: list = []
    lines = source.split("\n")
    for idx, line in enumerate(lines, start=1):
        if line != line.rstrip(" \t"):
            findings.append(
                {
                    "line_no": idx,
                    "code": "trailing-whitespace",
                    "message": "line has trailing whitespace",
                }
            )
        if line.startswith("\t"):
            findings.append(
                {
                    "line_no": idx,
                    "code": "tab-indentation",
                    "message": "line uses tab indentation",
                }
            )
        if len(line) > line_length:
            findings.append(
                {
                    "line_no": idx,
                    "code": "line-too-long",
                    "message": f"line exceeds line_length={line_length}",
                }
            )
    if "\r" in source:
        findings.append(
            {
                "line_no": 0,
                "code": "crlf-line-ending",
                "message": "source contains CR line endings",
            }
        )
    blank_run = 0
    for idx, line in enumerate(lines, start=1):
        if line.strip() == "":
            blank_run += 1
            if blank_run > 2:
                findings.append(
                    {
                        "line_no": idx,
                        "code": "excess-blank-lines",
                        "message": "more than 2 consecutive blank lines",
                    }
                )
        else:
            blank_run = 0
    if source and not source.endswith("\n"):
        findings.append(
            {
                "line_no": len(lines),
                "code": "missing-final-newline",
                "message": "file does not end with a newline",
            }
        )
    return tuple(findings)


@dataclass(frozen=True)
class SourceRecord:
    """A registered host-reported source file."""

    source_id: str
    language: str
    byte_len: int
    pin: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "language": self.language,
            "byte_len": self.byte_len,
            "pin": self.pin,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
            "version": CODE_FORMATTER_VERSION,
        }


@dataclass(frozen=True)
class FormatResult:
    """Outcome of a formatting pass."""

    source_id: str
    output: str
    changed: bool
    line_length: int
    indent: str
    loss_ledger: Tuple[str, ...]
    output_pin: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "output": self.output,
            "changed": self.changed,
            "line_length": self.line_length,
            "indent": self.indent,
            "loss_ledger": list(self.loss_ledger),
            "output_pin": self.output_pin,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
            "version": CODE_FORMATTER_VERSION,
        }

    def verify(self) -> bool:
        """Re-derive the output pin (tamper check)."""
        return self.output_pin == _pin(
            {"output": self.output, "options": [self.line_length, self.indent]}
        )


@dataclass(frozen=True)
class CheckReport:
    """Outcome of a formatting-conformance check."""

    source_id: str
    verdict: str  # "clean" | "dirty"
    findings: Tuple[Dict[str, Any], ...]
    line_length: int
    report_pin: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "verdict": self.verdict,
            "findings": list(self.findings),
            "line_length": self.line_length,
            "report_pin": self.report_pin,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
            "version": CODE_FORMATTER_VERSION,
        }


@dataclass(frozen=True)
class DiffReport:
    """Unified diff between the registered source and its formatted text."""

    source_id: str
    diff: str
    changed: bool
    hunks: int
    added_lines: int
    removed_lines: int
    diff_pin: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "diff": self.diff,
            "changed": self.changed,
            "hunks": self.hunks,
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "diff_pin": self.diff_pin,
            "seq": self.seq,
            "schema": SCHEMA_PIN,
            "version": CODE_FORMATTER_VERSION,
        }


class CodeFormatter:
    """Deterministic single-host code-formatting bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sources: Dict[str, str] = {}
        self._records: Dict[str, SourceRecord] = {}
        self._formats: Dict[str, Tuple[FormatResult, ...]] = {}
        self._last_seq = -1
        self._audit: Tuple[Dict[str, Any], ...] = ()

    def _claim_seq(self, seq: int) -> int:
        # Failed mutations consume their seq (fail-closed ledger position).
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase: {seq} <= {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _log(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        self._audit = self._audit + (
            code_formatter_audit_event(kind, seq, detail),
        )

    def register(
        self, source_id: str, source: str, seq: int, language: str = "python"
    ) -> SourceRecord:
        with self._lock:
            self._claim_seq(seq)
            _check_source_id(source_id)
            _check_language(language)
            if not isinstance(source, str):
                raise ValidationError("source must be a str")
            byte_len = len(source.encode("utf-8"))
            if byte_len > MAX_SOURCE_BYTES:
                raise ValidationError(
                    f"source exceeds {MAX_SOURCE_BYTES} bytes"
                )
            if source_id in self._sources:
                raise DuplicateSourceError(
                    f"source already registered: {source_id!r}"
                )
            if len(self._sources) >= MAX_SOURCES:
                raise ValidationError("source registry full")
            self._sources[source_id] = source
            record = SourceRecord(
                source_id=source_id,
                language=language,
                byte_len=byte_len,
                pin=_pin(
                    {
                        "source_id": source_id,
                        "language": language,
                        "source": source,
                    }
                ),
                seq=seq,
            )
            self._records[source_id] = record
            self._formats[source_id] = ()
            self._log(
                "source-registered",
                seq,
                {"source_id": source_id, "pin": record.pin},
            )
            return record

    def format(
        self,
        source_id: str,
        seq: int,
        line_length: int = 88,
        indent: str = "space4",
    ) -> FormatResult:
        with self._lock:
            self._claim_seq(seq)
            _check_source_id(source_id)
            _check_line_length(line_length)
            _check_indent(indent)
            source = self._get_source(source_id)
            output = _normalize_text(source, indent)
            changed = output != source
            result = FormatResult(
                source_id=source_id,
                output=output,
                changed=changed,
                line_length=line_length,
                indent=indent,
                loss_ledger=LOSS_LEDGER,
                output_pin=_pin(
                    {
                        "output": output,
                        "options": [line_length, indent],
                    }
                ),
                seq=seq,
            )
            self._formats[source_id] = self._formats[source_id] + (result,)
            self._log(
                "formatted",
                seq,
                {
                    "source_id": source_id,
                    "changed": changed,
                    "output_pin": result.output_pin,
                },
            )
            return result

    def check(self, source_id: str, seq: int, line_length: int = 88) -> CheckReport:
        with self._lock:
            self._claim_seq(seq)
            _check_source_id(source_id)
            _check_line_length(line_length)
            source = self._get_source(source_id)
            findings = _check_findings(source, line_length)
            verdict = "clean" if not findings else "dirty"
            report = CheckReport(
                source_id=source_id,
                verdict=verdict,
                findings=findings,
                line_length=line_length,
                report_pin=_pin(
                    {
                        "verdict": verdict,
                        "findings": [dict(f) for f in findings],
                    }
                ),
                seq=seq,
            )
            self._log(
                "checked",
                seq,
                {
                    "source_id": source_id,
                    "verdict": verdict,
                    "finding_count": len(findings),
                },
            )
            return report

    def diff(
        self,
        source_id: str,
        seq: int,
        line_length: int = 88,
        indent: str = "space4",
    ) -> DiffReport:
        with self._lock:
            self._claim_seq(seq)
            _check_source_id(source_id)
            _check_line_length(line_length)
            _check_indent(indent)
            source = self._get_source(source_id)
            output = _normalize_text(source, indent)
            changed = output != source
            diff_text = "".join(
                difflib.unified_diff(
                    source.splitlines(keepends=True),
                    output.splitlines(keepends=True),
                    fromfile="a/source",
                    tofile="b/formatted",
                )
            )
            hunks = sum(
                1 for line in diff_text.splitlines() if line.startswith("@@")
            )
            added = sum(
                1
                for line in diff_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
            )
            removed = sum(
                1
                for line in diff_text.splitlines()
                if line.startswith("-") and not line.startswith("---")
            )
            report = DiffReport(
                source_id=source_id,
                diff=diff_text,
                changed=changed,
                hunks=hunks,
                added_lines=added,
                removed_lines=removed,
                diff_pin=_pin({"diff": diff_text}),
                seq=seq,
            )
            self._log(
                "diffed",
                seq,
                {
                    "source_id": source_id,
                    "changed": changed,
                    "hunks": hunks,
                    "diff_pin": report.diff_pin,
                },
            )
            return report

    def _get_source(self, source_id: str) -> str:
        if source_id not in self._sources:
            raise UnknownSourceError(f"unknown source: {source_id!r}")
        return self._sources[source_id]

    def source(self, source_id: str) -> SourceRecord:
        with self._lock:
            if source_id not in self._records:
                raise UnknownSourceError(f"unknown source: {source_id!r}")
            return self._records[source_id]

    def source_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._records))

    def format_history(self, source_id: str) -> Tuple[FormatResult, ...]:
        with self._lock:
            if source_id not in self._formats:
                raise UnknownSourceError(f"unknown source: {source_id!r}")
            return self._formats[source_id]

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return self._audit


def code_formatter_audit_event(
    kind: str, seq: int, detail: Mapping[str, Any]
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event for code-formatting activity."""
    valid = {
        "source-registered",
        "formatted",
        "checked",
        "diffed",
        "rejected",
    }
    if kind not in valid:
        raise ValidationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {
        "kind": kind,
        "seq": seq,
        "version": CODE_FORMATTER_VERSION,
        "audit_schema": AUDIT_SCHEMA,
        "detail": dict(detail),
    }


def main() -> None:
    formatter = CodeFormatter()
    record = formatter.register("ex-1", "def f():\t \n  pass  \n\n\n", 1)
    assert record.pin.startswith("sha256:")
    result = formatter.format("ex-1", 2)
    assert result.changed
    assert result.output.endswith("\n")
    assert result.verify()
    report = formatter.check("ex-1", 3)
    assert report.verdict == "dirty"
    formatter.register("ex-2", "def f():\n    pass\n", 4)
    clean_report = formatter.check("ex-2", 5)
    assert clean_report.verdict == "clean"
    diff = formatter.diff("ex-1", 6)
    assert diff.changed and diff.hunks > 0
    event = code_formatter_audit_event(
        "formatted", 2, {"output_pin": result.output_pin}
    )
    assert event["audit_schema"] == AUDIT_SCHEMA
    print(
        "code-formatter OK: register, format, check, diff, pins, "
        f"audit ({len(formatter.audit_log())} events)"
    )


if __name__ == "__main__":
    main()
