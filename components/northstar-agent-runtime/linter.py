"""Ruff-style lint bookkeeping: rules, violations, and auto-fix ledgers.

Research note: production linters (Ruff, ESLint, clippy) own a pipeline of

* **Rules** — a closed vocabulary of checks, each with a stable id, a
  severity (``error``/``warning``), and whether it is auto-fixable. Ruff
  pins its rule set per release; adding or removing a rule changes the
  digest, so downstream configs can pin the rule set they linted against.
* **Violation detection** — a pure scan of the reported source text that
  returns *pinned* findings: rule id, line, column, message. A clean scan
  returns an empty violation list as data, never an exception. Findings
  are digest-bound to the exact source text they were found in.
* **Auto-fix** — for fixable rules, a deterministic rewrite pass that
  produces new source plus an applied-fix ledger. Fixes are idempotent:
  fixing already-fixed source yields zero applied fixes. Every applied
  fix is bound to the before/after source digests so a replay can verify
  the rewrite byte-for-byte.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed, stdlib-only.

Honest scope: this is simulated rule bookkeeping over host-reported
source *text* — token-level heuristics, not a parser. A finding means
"the pinned heuristic matched", and a clean report means "no heuristic
matched", never "the code is correct" (GIGO boundary). Auto-fixes are
pure text rewrites of the pinned rules; the module cannot compile or run
the source to validate a fix. Rule ids follow Ruff's letter-prefix
convention (``E`` pycodestyle-errors, ``W`` warnings, ``F`` pyflakes,
``T`` house TODO-tags).
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
LINTER_VERSION = "linter.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.linter.v1"

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "linter-created",
    "linted",
    "fixed",
    "rejected",
)

#: Guardrail: max source bytes accepted by lint/fix (1 MiB).
_MAX_SOURCE_BYTES = 1024 * 1024

#: Guardrail: max rule ids accepted in one lint() call.
_MAX_SELECT = 256

#: Pinned severities.
_SEVERITIES = ("error", "warning")


class LinterError(Exception):
    """Base fail-closed error for the linter."""


class UnknownRuleError(LinterError):
    """Raised for rule ids outside the pinned registry."""


class BadSourceError(LinterError):
    """Raised for malformed source input (not a string, over guardrail)."""


class SeqOrderError(LinterError):
    """Raised when a caller seq does not strictly increase."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LinterError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise LinterError(f"{name} must be non-negative")
    return value


def _check_source(source: Any) -> str:
    if not isinstance(source, str):
        raise BadSourceError(f"source must be a str, got {type(source).__name__}")
    if len(source.encode("utf-8")) > _MAX_SOURCE_BYTES:
        raise BadSourceError("source exceeds 1 MiB guardrail")
    return source


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


def _source_digest(source: str) -> str:
    return "sha256:" + hashlib.sha256(source.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Pinned rule registry. The registry is the contract: adding a rule changes
# the registry digest, so callers can detect rule-set drift.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleRecord:
    """One pinned lint rule."""

    rule_id: str
    name: str
    description: str
    severity: str
    fixable: bool
    version: str = LINTER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "fixable": self.fixable,
            "version": self.version,
            "schema": self.schema,
        }


# (rule_id, name, description, severity, fixable)
_RULE_SPECS: tuple[tuple[str, str, str, str, bool], ...] = (
    ("E501", "line-too-long",
     "line exceeds the configured max line length (default 88)", "warning", False),
    ("W291", "trailing-whitespace",
     "trailing whitespace at end of line", "warning", True),
    ("W292", "no-newline-at-end-of-file",
     "no newline at end of file", "warning", True),
    ("W191", "tab-indentation",
     "tab character used for indentation", "warning", True),
    ("T001", "todo-marker",
     "TODO/FIXME/XXX marker in a comment", "warning", False),
    ("T201", "print-call",
     "print() call (production code should use structured logging)", "warning", False),
    ("F403", "wildcard-import",
     "wildcard import 'from x import *' hides names", "error", False),
    ("F401", "unused-import",
     "imported name never referenced again (token heuristic)", "warning", False),
)

_MAX_LINE_LENGTH = 88

_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX)\b")
_PRINT_RE = re.compile(r"(?<![\w.])print\s*\(")
_WILDCARD_RE = re.compile(r"^\s*from\s+\S+\s+import\s+\*\s*(?:#.*)?$")
_IMPORT_RE = re.compile(r"^\s*(?:from\s+(\S+)\s+)?import\s+(.+?)\s*(?:#.*)?$")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class Violation:
    """One lint finding, pinned to its source."""

    rule_id: str
    line: int          # 1-based
    column: int        # 1-based
    message: str
    severity: str
    fixable: bool
    version: str = LINTER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "severity": self.severity,
            "fixable": self.fixable,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LintReport:
    """Result of one lint pass over a source text."""

    source_digest: str
    violations: tuple[Violation, ...]
    rules_applied: tuple[str, ...]
    registry_digest: str
    seq: int
    report_digest: str
    version: str = LINTER_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the report digest from its contents."""
        body = {
            "registry_digest": self.registry_digest,
            "rules_applied": list(self.rules_applied),
            "seq": self.seq,
            "source_digest": self.source_digest,
            "version": self.version,
            "violations": [v.as_dict() for v in self.violations],
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_digest": self.source_digest,
            "violations": [v.as_dict() for v in self.violations],
            "rules_applied": list(self.rules_applied),
            "registry_digest": self.registry_digest,
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AppliedFix:
    """One applied auto-fix, bound to the source it rewrote."""

    rule_id: str
    line: int
    before_digest: str
    after_digest: str
    description: str
    version: str = LINTER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "line": self.line,
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "description": self.description,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class FixReport:
    """Result of one auto-fix pass."""

    before_digest: str
    after_digest: str
    applied_fixes: tuple[AppliedFix, ...]
    remaining: tuple[Violation, ...]
    rules_applied: tuple[str, ...]
    registry_digest: str
    seq: int
    report_digest: str
    version: str = LINTER_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        body = {
            "after_digest": self.after_digest,
            "before_digest": self.before_digest,
            "registry_digest": self.registry_digest,
            "rules_applied": list(self.rules_applied),
            "seq": self.seq,
            "version": self.version,
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "before_digest": self.before_digest,
            "after_digest": self.after_digest,
            "applied_fixes": [f.as_dict() for f in self.applied_fixes],
            "remaining": [v.as_dict() for v in self.remaining],
            "rules_applied": list(self.rules_applied),
            "registry_digest": self.registry_digest,
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


class Linter:
    """Ruff-style rule bookkeeping: lint and fix over reported source text.

    The rule registry is pinned at construction; ``lint(source, seq,
    rule_ids=None)`` scans with all (or a selected subset of) rules, and
    ``fix(source, seq, rule_ids=None)`` applies auto-fixable rules and
    re-scans to report what remains. Selection of an unknown rule id is
    refused fail-closed.
    """

    def __init__(self, max_line_length: int = _MAX_LINE_LENGTH) -> None:
        if isinstance(max_line_length, bool) or not isinstance(max_line_length, int):
            raise LinterError("max_line_length must be an int")
        if max_line_length < 1:
            raise LinterError("max_line_length must be >= 1")
        self._max_line_length = max_line_length
        self._lock = threading.RLock()
        self._rules: dict[str, RuleRecord] = {}
        for rule_id, name, description, severity, fixable in _RULE_SPECS:
            self._rules[rule_id] = RuleRecord(
                rule_id=rule_id,
                name=name,
                description=description,
                severity=severity,
                fixable=fixable,
            )
        self._registry_digest = _digest(
            [self._rules[k].as_dict() for k in sorted(self._rules)]
        )
        self._last_seq = -1

    # -- internal ---------------------------------------------------------

    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise SeqOrderError("seq must strictly increase")
        self._last_seq = seq
        return seq

    def _selected(self, rule_ids: Any) -> tuple[RuleRecord, ...]:
        if rule_ids is None:
            return tuple(self._rules[k] for k in sorted(self._rules))
        if not isinstance(rule_ids, (list, tuple)):
            raise LinterError("rule_ids must be a list/tuple of rule ids")
        if len(rule_ids) > _MAX_SELECT:
            raise LinterError(f"rule_ids exceeds {_MAX_SELECT} guardrail")
        picked: list[RuleRecord] = []
        for rid in rule_ids:
            if not isinstance(rid, str) or rid not in self._rules:
                raise UnknownRuleError(f"unknown rule id {rid!r}")
            picked.append(self._rules[rid])
        return tuple(picked)

    def rules(self) -> tuple[RuleRecord, ...]:
        """Return the pinned rule registry (sorted by rule id)."""
        with self._lock:
            return tuple(self._rules[k] for k in sorted(self._rules))

    def registry_digest(self) -> str:
        """Return the digest pin over the pinned rule registry."""
        with self._lock:
            return self._registry_digest

    # -- detection --------------------------------------------------------

    def _detect(
        self, source: str, rule_ids: tuple[RuleRecord, ...]
    ) -> tuple[Violation, ...]:
        lines = source.split("\n")
        violations: list[Violation] = []

        def add(rid: str, line: int, column: int, message: str) -> None:
            rule = self._rules[rid]
            violations.append(
                Violation(
                    rule_id=rid,
                    line=line,
                    column=column,
                    message=message,
                    severity=rule.severity,
                    fixable=rule.fixable,
                )
            )

        wanted = {r.rule_id for r in rule_ids}
        has_trailing_newline = source == "" or source.endswith("\n")

        for idx, raw in enumerate(lines, start=1):
            if "E501" in wanted and len(raw) > self._max_line_length:
                add(
                    "E501", idx, self._max_line_length + 1,
                    f"line too long ({len(raw)} > {self._max_line_length} characters)",
                )
            if "W291" in wanted and raw != raw.rstrip(" \t"):
                add(
                    "W291", idx, len(raw.rstrip(" \t")) + 1,
                    "trailing whitespace",
                )
            if "W191" in wanted and raw.startswith("\t"):
                add("W191", idx, 1, "tab used for indentation")
            if "T001" in wanted:
                match = _TODO_RE.search(raw)
                if match and "#" in raw[: match.start()]:
                    add(
                        "T001", idx, match.start() + 1,
                        f"{match.group(1)} marker in comment",
                    )
            if "T201" in wanted and _PRINT_RE.search(raw):
                add("T201", idx, _PRINT_RE.search(raw).start() + 1, "print() call")
            if "F403" in wanted and _WILDCARD_RE.match(raw):
                add("F403", idx, 1, "wildcard import")
            if "F401" in wanted:
                match = _IMPORT_RE.match(raw)
                if match and match.group(2) != "*":
                    names: list[str] = []
                    for part in match.group(2).split(","):
                        part = part.strip()
                        alias = part.split(" as ")
                        name = alias[-1].strip()
                        if name and _IDENT_RE.fullmatch(name):
                            names.append(name)
                    body_below = "\n".join(lines[idx:])
                    used = any(
                        m.group() == name for m in _IDENT_RE.finditer(body_below)
                    )
                    if not used:
                            add(
                                "F401", idx, raw.index(name) + 1,
                                f"'{name}' imported but unused (token heuristic)",
                            )

        if "W292" in wanted and source != "" and not has_trailing_newline:
            add("W292", len(lines), len(lines[-1]) + 1, "no newline at end of file")

        violations.sort(key=lambda v: (v.line, v.column, v.rule_id))
        return tuple(violations)

    def lint(
        self,
        source: Any,
        seq: Any,
        rule_ids: Any = None,
    ) -> LintReport:
        """Scan the reported source; return a pinned LintReport."""
        with self._lock:
            text = _check_source(source)
            seq = _check_seq(seq)
            self._monotonic(seq)
            selected = self._selected(rule_ids)
            violations = self._detect(text, selected)
            applied = tuple(r.rule_id for r in selected)
            body = {
                "registry_digest": self._registry_digest,
                "rules_applied": list(applied),
                "seq": seq,
                "source_digest": _source_digest(text),
                "version": LINTER_VERSION,
                "violations": [v.as_dict() for v in violations],
            }
            return LintReport(
                source_digest=_source_digest(text),
                violations=violations,
                rules_applied=applied,
                registry_digest=self._registry_digest,
                seq=seq,
                report_digest=_digest(body),
            )

    # -- auto-fix ----------------------------------------------------------

    def _apply_fixes(
        self, source: str, rule_ids: tuple[RuleRecord, ...]
    ) -> tuple[str, tuple[AppliedFix, ...]]:
        """Apply fixable-rule rewrites; return (new_source, fixes)."""
        wanted = {r.rule_id for r in rule_ids if r.fixable}
        lines = source.split("\n")
        fixes: list[AppliedFix] = []
        changed = False

        if "W291" in wanted:
            for idx, raw in enumerate(lines, start=1):
                stripped = raw.rstrip(" \t")
                if stripped != raw:
                    before = _source_digest(source)
                    lines[idx - 1] = stripped
                    source = "\n".join(lines)
                    fixes.append(
                        AppliedFix(
                            rule_id="W291",
                            line=idx,
                            before_digest=before,
                            after_digest=_source_digest(source),
                            description="stripped trailing whitespace",
                        )
                    )
                    changed = True

        if "W191" in wanted:
            for idx, raw in enumerate(lines, start=1):
                if raw.startswith("\t"):
                    leading = raw[: len(raw) - len(raw.lstrip("\t"))]
                    before = _source_digest(source)
                    lines[idx - 1] = "    " * len(leading) + raw.lstrip("\t")
                    source = "\n".join(lines)
                    fixes.append(
                        AppliedFix(
                            rule_id="W191",
                            line=idx,
                            before_digest=before,
                            after_digest=_source_digest(source),
                            description="converted leading tabs to spaces",
                        )
                    )
                    changed = True

        if "W292" in wanted and source != "" and not source.endswith("\n"):
            before = _source_digest(source)
            source = source + "\n"
            lines = source.split("\n")
            fixes.append(
                AppliedFix(
                    rule_id="W292",
                    line=len(lines) - 1,
                    before_digest=before,
                    after_digest=_source_digest(source),
                    description="appended missing trailing newline",
                )
            )
            changed = True

        _ = changed
        return source, tuple(fixes)

    def fix(
        self,
        source: Any,
        seq: Any,
        rule_ids: Any = None,
    ) -> FixReport:
        """Apply auto-fixes for fixable rules, then re-scan.

        Returns the rewritten source (implicit in ``after_digest`` only —
        the report carries digests, the caller keeps the string) plus a
        FixReport pinning before/after and what remains. Note: the fixed
        source text itself is not returned; use ``fixed_source()``.
        """
        with self._lock:
            text = _check_source(source)
            seq = _check_seq(seq)
            self._monotonic(seq)
            selected = self._selected(rule_ids)
            new_source, applied = self._apply_fixes(text, selected)
            remaining = self._detect(new_source, selected)
            applied_ids = tuple(r.rule_id for r in selected)
            body = {
                "after_digest": _source_digest(new_source),
                "before_digest": _source_digest(text),
                "registry_digest": self._registry_digest,
                "rules_applied": list(applied_ids),
                "seq": seq,
                "version": LINTER_VERSION,
            }
            report = FixReport(
                before_digest=_source_digest(text),
                after_digest=_source_digest(new_source),
                applied_fixes=applied,
                remaining=remaining,
                rules_applied=applied_ids,
                registry_digest=self._registry_digest,
                seq=seq,
                report_digest=_digest(body),
            )
            return report

    def fixed_source(self, source: Any, seq: Any, rule_ids: Any = None) -> str:
        """Convenience: return the fixed source text directly."""
        with self._lock:
            text = _check_source(source)
            seq = _check_seq(seq)
            self._monotonic(seq)
            selected = self._selected(rule_ids)
            new_source, _ = self._apply_fixes(text, selected)
            return new_source


def linter_audit_event(kind: str, seq: int, **detail: Any) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for linter activity."""
    if kind not in _AUDIT_KINDS:
        raise LinterError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": LINTER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    for key, value in detail.items():
        if isinstance(value, (str, bool)) or value is None:
            event[key] = value
        elif isinstance(value, int):
            if abs(value) > 2 ** 53:
                raise LinterError("int magnitude beyond 2**53 refused (JCS float-loss caveat)")
            event[key] = value
        else:
            event[key] = jcs_canonical_json({"v": value}).decode("utf-8")
    return event


def main() -> None:
    """Self-check: rules, lint, fix, idempotency, pins."""
    linter = Linter()
    rule_ids = [r.rule_id for r in linter.rules()]
    assert rule_ids == sorted(rule_ids), rule_ids
    assert len(rule_ids) == len(_RULE_SPECS)
    assert linter.registry_digest().startswith("sha256:")
    assert linter.registry_digest() == linter.registry_digest()

    dirty = "import os\n\tprint('x')   \n# TODO: fix me\nfrom mod import *\n" + "x = 1" + "x" * 100
    report = linter.lint(dirty, 0)
    assert report.verify()
    found = {v.rule_id for v in report.violations}
    for rid in ("W291", "W191", "T001", "T201", "F403", "F401", "E501", "W292"):
        assert rid in found, (rid, found)

    clean = "import os\nos.getcwd()\n"
    report = linter.lint(clean, 1)
    assert report.verify()
    assert report.violations == ()

    fix_report = linter.fix(dirty, 2)
    assert fix_report.verify()
    assert len(fix_report.applied_fixes) == 3, fix_report.as_dict()
    fixed_ids = {f.rule_id for f in fix_report.applied_fixes}
    assert fixed_ids == {"W291", "W191", "W292"}, fixed_ids
    remaining_ids = {v.rule_id for v in fix_report.remaining}
    assert "W291" not in remaining_ids and "W191" not in remaining_ids

    fixed_text = linter.fixed_source(dirty, 3)
    second = linter.fix(fixed_text, 4)
    assert second.applied_fixes == (), "fix must be idempotent"
    assert second.before_digest == second.after_digest

    subset = linter.lint(dirty, 5, rule_ids=["E501"])
    assert {v.rule_id for v in subset.violations} == {"E501"}
    print("linter OK: rules, lint, fix, idempotency, pins")


if __name__ == "__main__":
    main()
