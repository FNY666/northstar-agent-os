"""Semgrep-style SAST bookkeeping: rules, scans, taint flows, suppressions.

Research note: static application security testing (Semgrep, CodeQL,
Bandit) owns a pipeline of

* **Rules** — a pinned vocabulary of checks, each with a stable id, a
  category (``injection``/``crypto``/``auth``/...), a severity
  (``critical``/``high``/``medium``/``low``), and a taint configuration:
  *sources* (user-controlled entry points), *sanitizers* (functions that
  cleanse tainted data), and *sinks* (dangerous operations). Semgrep pins
  its rule pack per release; adding or removing a rule changes the digest.
* **Pattern scan** — a pure scan of the reported source text that returns
  pinned findings: rule id, line, column, severity, message. A clean scan
  returns an empty finding list as data, never an exception. Findings are
  digest-bound to the exact source text they were found in.
* **Taint analysis** — line-oriented dataflow bookkeeping: variables
  assigned from a source become tainted; assignments through a sanitizer
  cleanse them; taint propagates through string-building expressions. A
  tainted variable reaching a sink yields a pinned *taint flow* finding
  carrying the source line and the sink line.
* **Suppressions** — inline ``# nosast`` comments mark individual findings
  as reviewed. Suppressed findings are still pinned in the ledger (visible,
  never invisible), so a suppression can be audited.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed, stdlib-only.

Honest scope: this is simulated taint bookkeeping over host-reported
source *text* — regex and line-level heuristics, not a parser or a real
dataflow engine. A finding means "the pinned heuristic matched", a clean
report means "no heuristic matched", never "the code is safe" (GIGO
boundary). The taint model is deliberately coarse: it cannot see across
function boundaries, through containers, or around aliasing. Rule ids are
prefixed ``PY`` (Python-pattern rules).
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
SAST_SCANNER_VERSION = "sast-scanner.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.sast-scanner.v1"

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "sast-created",
    "scanned",
    "taint-analyzed",
    "suppressed",
    "rejected",
)

#: Guardrail: max source bytes accepted by scan/taint/suppress (1 MiB).
_MAX_SOURCE_BYTES = 1024 * 1024

#: Guardrail: max rule ids accepted in one call.
_MAX_SELECT = 256

#: Pinned severities.
_SEVERITIES = ("critical", "high", "medium", "low")

#: Pinned taint categories.
_CATEGORIES = ("injection", "deserialization", "crypto", "auth", "config", "style")

#: Inline suppression marker (Semgrep uses ``# nosemgrep``).
_NOSAST_RE = re.compile(r"#\s*nosast(?::\s*(?P<ids>[A-Za-z0-9_,\s]+))?\s*$")


class SASTError(Exception):
    """Base fail-closed error for the SAST scanner."""


class UnknownRuleError(SASTError):
    """Raised for rule ids outside the pinned registry."""


class BadSourceError(SASTError):
    """Raised for malformed source input (not a string, over guardrail)."""


class SeqOrderError(SASTError):
    """Raised when a caller seq does not strictly increase."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SASTError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise SASTError(f"{name} must be non-negative")
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
    """One pinned SAST rule."""

    rule_id: str
    category: str
    severity: str
    title: str
    message: str
    version: str = SAST_SCANNER_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "version": self.version,
            "schema": self.schema,
        }


# (rule_id, category, severity, title, message, pattern)
_RULE_SPECS: tuple = (
    ("PY001", "injection", "critical", "eval/exec call",
     "dynamic code execution via eval()/exec()",
     r"\b(?:eval|exec)\s*\("),
    ("PY002", "injection", "critical", "shell command execution",
     "shell command via os.system()/os.popen() or shell=True",
     r"\bos\.(?:system|popen)\s*\(|shell\s*=\s*True"),
    ("PY003", "deserialization", "high", "unsafe deserialization",
     "unsafe deserialization via pickle.loads()/yaml.load()",
     r"\bpickle\.loads\s*\(|\byaml\.load\s*\("),
    ("PY004", "injection", "high", "SQL execution sink",
     "SQL executed through cursor.execute(); taint checked separately",
     r"\bcursor\.execute\s*\("),
    ("PY005", "auth", "medium", "hardcoded secret",
     "hardcoded credential in assignment",
     r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*=\s*['\"][^'\"]+['\"]"),
    ("PY006", "crypto", "medium", "weak hash or PRNG",
     "weak digest (md5/sha1) or non-crypto PRNG",
     r"\bhashlib\.(?:md5|sha1)\s*\(|\brandom\.(?:random|randint|choice)\s*\("),
    ("PY007", "config", "low", "assert statement",
     "assert is disabled under -O; not a runtime guard",
     r"(?m)^\s*assert\s+"),
    ("PY008", "style", "low", "bare except",
     "bare except swallows control-flow exceptions",
     r"(?m)^\s*except\s*:"),
    ("PY009", "config", "low", "request without timeout",
     "requests call without an explicit timeout",
     r"\brequests\.(?:get|post|put|delete|head|patch)\s*\("),
    ("PY010", "config", "medium", "unsafe temp file",
     "predictable temp file via mktemp()/mkstemp in /tmp",
     r"\btempfile\.mktemp\s*\(|/tmp/[A-Za-z0-9_.-]+\b"),
)

# Taint source heuristics (user-controlled entry points).
_SOURCE_PATTERNS = (
    r"\binput\s*\(",
    r"\brequest\.(?:args|form|values|cookies|data|json)\b",
    r"\bsys\.argv\b",
    r"\bos\.environ\b",
    r"\bflask\.request\b",
    r"\brequest\.GET\b",
    r"\brequest\.POST\b",
)

# Sanitizer heuristics (functions that cleanse tainted data).
_SANITIZER_PATTERNS = (
    r"\b(?:escape|sanitize|clean|quoteattr)\s*\(",
    r"\bhtml\.escape\s*\(",
    r"\bshlex\.quote\s*\(",
    r"\bre\.escape\s*\(",
    r"\bmarkupsafe\.escape\s*\(",
)

# Taint sink heuristics, each bound to the rule it reports as.
_SINK_SPECS: tuple = (
    ("PY001", r"\b(?:eval|exec)\s*\("),
    ("PY002", r"\bos\.(?:system|popen)\s*\(|subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True"),
    ("PY003", r"\bpickle\.loads\s*\("),
    ("PY004", r"\bcursor\.execute\s*\("),
)

_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
_NOSAST_ANY = re.compile(r"#\s*nosast\b")


@dataclass(frozen=True)
class Finding:
    """One pinned pattern finding."""

    rule_id: str
    line: int
    column: int
    severity: str
    message: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "line": self.line,
            "column": self.column,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(frozen=True)
class ScanReport:
    """Pinned result of scan()."""

    source_digest: str
    findings: tuple
    rules_applied: tuple
    registry_digest: str
    seq: int
    report_digest: str
    version: str = SAST_SCANNER_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the report digest from its contents."""
        body = {
            "registry_digest": self.registry_digest,
            "report_seq": self.seq,
            "rules_applied": list(self.rules_applied),
            "source_digest": self.source_digest,
            "version": self.version,
            "findings": [f.as_dict() for f in self.findings],
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict:
        return {
            "source_digest": self.source_digest,
            "findings": [f.as_dict() for f in self.findings],
            "rules_applied": list(self.rules_applied),
            "registry_digest": self.registry_digest,
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TaintFlow:
    """One pinned taint flow: tainted data reaching a sink."""

    rule_id: str
    variable: str
    source_line: int
    sink_line: int
    sink_column: int
    severity: str

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "variable": self.variable,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "sink_column": self.sink_column,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class TaintReport:
    """Pinned result of taint()."""

    source_digest: str
    flows: tuple
    rules_applied: tuple
    registry_digest: str
    seq: int
    report_digest: str
    version: str = SAST_SCANNER_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the report digest from its contents."""
        body = {
            "registry_digest": self.registry_digest,
            "report_seq": self.seq,
            "rules_applied": list(self.rules_applied),
            "source_digest": self.source_digest,
            "version": self.version,
            "flows": [f.as_dict() for f in self.flows],
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict:
        return {
            "source_digest": self.source_digest,
            "flows": [f.as_dict() for f in self.flows],
            "rules_applied": list(self.rules_applied),
            "registry_digest": self.registry_digest,
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SuppressedFinding:
    """A finding pinned alongside its suppression justification."""

    finding: Finding
    suppression_line: int
    suppression_note: str

    def as_dict(self) -> dict:
        return {
            "finding": self.finding.as_dict(),
            "suppression_line": self.suppression_line,
            "suppression_note": self.suppression_note,
        }


@dataclass(frozen=True)
class SuppressReport:
    """Pinned result of suppress(): active vs suppressed findings."""

    source_digest: str
    active: tuple
    suppressed: tuple
    seq: int
    report_digest: str
    version: str = SAST_SCANNER_VERSION
    schema: str = SCHEMA_PIN

    def verify(self) -> bool:
        """Re-derive the report digest from its contents."""
        body = {
            "report_seq": self.seq,
            "source_digest": self.source_digest,
            "version": self.version,
            "active": [f.as_dict() for f in self.active],
            "suppressed": [s.as_dict() for s in self.suppressed],
        }
        return _digest(body) == self.report_digest

    def as_dict(self) -> dict:
        return {
            "source_digest": self.source_digest,
            "active": [f.as_dict() for f in self.active],
            "suppressed": [s.as_dict() for s in self.suppressed],
            "seq": self.seq,
            "report_digest": self.report_digest,
            "version": self.version,
            "schema": self.schema,
        }


class SASTScanner:
    """Semgrep-style static security scanning over reported source text.

    ``scan()`` runs the pinned pattern rules; ``taint()`` runs the
    line-oriented source/sanitizer/sink dataflow; ``suppress()`` applies
    inline ``# nosast`` markers and pins what remains active.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._rules: tuple = tuple(
            RuleRecord(
                rule_id=rid,
                category=cat,
                severity=sev,
                title=title,
                message=msg,
            )
            for rid, cat, sev, title, msg, _ in _RULE_SPECS
        )
        self._patterns: dict = {
            rid: re.compile(pat) for rid, _, _, _, _, pat in _RULE_SPECS
        }
        self._sources: tuple = tuple(re.compile(p) for p in _SOURCE_PATTERNS)
        self._sanitizers: tuple = tuple(re.compile(p) for p in _SANITIZER_PATTERNS)
        self._sinks: tuple = tuple(
            (rid, re.compile(pat)) for rid, pat in _SINK_SPECS
        )
        self._registry_digest = _digest(
            {"rules": [r.as_dict() for r in self._rules]}
        )

    # -- views ------------------------------------------------------------

    def rules(self) -> tuple:
        """Return the pinned rule registry, sorted by rule id."""
        with self._lock:
            return tuple(sorted(self._rules, key=lambda r: r.rule_id))

    def registry_digest(self) -> str:
        """Return the digest pin of the current rule registry."""
        with self._lock:
            return self._registry_digest

    def _monotonic(self, seq: int) -> int:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _selected(self, rule_ids: Any) -> tuple:
        if rule_ids is None:
            return self._rules
        if not isinstance(rule_ids, (list, tuple)) or isinstance(rule_ids, str):
            raise UnknownRuleError("rule_ids must be a list/tuple of rule ids")
        if len(rule_ids) > _MAX_SELECT:
            raise UnknownRuleError("rule_ids exceeds selection guardrail")
        known = {r.rule_id: r for r in self._rules}
        selected = []
        for rid in rule_ids:
            if rid not in known:
                raise UnknownRuleError(f"unknown rule id {rid!r}")
            selected.append(known[rid])
        selected.sort(key=lambda r: r.rule_id)
        return tuple(selected)

    # -- pattern scan ------------------------------------------------------

    def _detect(self, text: str, selected: tuple) -> tuple:
        findings: list = []
        lines = text.split("\n")
        wanted = {r.rule_id for r in selected}
        for idx, raw in enumerate(lines, start=1):
            for rule in selected:
                if rule.rule_id not in wanted:
                    continue
                match = self._patterns[rule.rule_id].search(raw)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            line=idx,
                            column=match.start() + 1,
                            severity=rule.severity,
                            message=rule.message,
                        )
                    )
        findings.sort(key=lambda f: (f.line, f.column, f.rule_id))
        return tuple(findings)

    def scan(self, source: Any, seq: Any, rule_ids: Any = None) -> ScanReport:
        """Scan the reported source; return a pinned ScanReport."""
        with self._lock:
            text = _check_source(source)
            seq = _check_seq(seq)
            self._monotonic(seq)
            selected = self._selected(rule_ids)
            findings = self._detect(text, selected)
            applied = tuple(r.rule_id for r in selected)
            body = {
                "registry_digest": self._registry_digest,
                "report_seq": seq,
                "rules_applied": list(applied),
                "source_digest": _source_digest(text),
                "version": SAST_SCANNER_VERSION,
                "findings": [f.as_dict() for f in findings],
            }
            return ScanReport(
                source_digest=_source_digest(text),
                findings=findings,
                rules_applied=applied,
                registry_digest=self._registry_digest,
                seq=seq,
                report_digest=_digest(body),
            )

    # -- taint analysis ----------------------------------------------------

    def _has_source(self, text: str) -> bool:
        return any(p.search(text) for p in self._sources)

    def _has_sanitizer(self, text: str) -> bool:
        return any(p.search(text) for p in self._sanitizers)

    def _analyze_taint(self, text: str, selected: tuple) -> tuple:
        """Line-oriented taint flow: source -> variable -> sink.

        Deterministic heuristic: a variable assigned from a source is
        tainted; assignment through a sanitizer cleanses it; taint
        propagates through assignments that reference a tainted variable;
        a tainted variable (or a bare source) reaching a sink line is a
        flow finding with the source line pinned.
        """
        wanted = {r.rule_id for r in selected}
        lines = text.split("\n")
        tainted: dict = {}  # var -> source line (1-based)
        flows: list = []
        for idx, raw in enumerate(lines, start=1):
            code = raw.split("#", 1)[0]
            assign = _ASSIGN_RE.match(raw)
            if assign:
                name, rhs = assign.group(1), assign.group(2)
                if self._has_source(rhs):
                    tainted[name] = idx
                elif self._has_sanitizer(rhs):
                    tainted.pop(name, None)
                else:
                    refs = [
                        var
                        for var in tainted
                        if re.search(r"\b" + re.escape(var) + r"\b", rhs)
                    ]
                    if refs:
                        tainted[name] = tainted[refs[0]]
                    else:
                        tainted.pop(name, None)
            for rule_id, sink_re in self._sinks:
                if rule_id not in wanted:
                    continue
                match = sink_re.search(code)
                if not match:
                    continue
                severity = next(
                    r.severity for r in selected if r.rule_id == rule_id
                )
                hit_vars = [
                    var
                    for var in tainted
                    if re.search(r"\b" + re.escape(var) + r"\b", code)
                ]
                if self._has_source(code):
                    flows.append(
                        TaintFlow(
                            rule_id=rule_id,
                            variable="<direct-source>",
                            source_line=idx,
                            sink_line=idx,
                            sink_column=match.start() + 1,
                            severity=severity,
                        )
                    )
                for var in hit_vars:
                    flows.append(
                        TaintFlow(
                            rule_id=rule_id,
                            variable=var,
                            source_line=tainted[var],
                            sink_line=idx,
                            sink_column=match.start() + 1,
                            severity=severity,
                        )
                    )
        flows.sort(
            key=lambda f: (f.sink_line, f.sink_column, f.rule_id, f.variable)
        )
        return tuple(flows)

    def taint(self, source: Any, seq: Any, rule_ids: Any = None) -> TaintReport:
        """Run taint analysis; return a pinned TaintReport."""
        with self._lock:
            text = _check_source(source)
            seq = _check_seq(seq)
            self._monotonic(seq)
            selected = self._selected(rule_ids)
            flows = self._analyze_taint(text, selected)
            applied = tuple(r.rule_id for r in selected)
            body = {
                "registry_digest": self._registry_digest,
                "report_seq": seq,
                "rules_applied": list(applied),
                "source_digest": _source_digest(text),
                "version": SAST_SCANNER_VERSION,
                "flows": [f.as_dict() for f in flows],
            }
            return TaintReport(
                source_digest=_source_digest(text),
                flows=flows,
                rules_applied=applied,
                registry_digest=self._registry_digest,
                seq=seq,
                report_digest=_digest(body),
            )

    # -- suppressions -------------------------------------------------------

    def suppress(
        self, source: Any, seq: Any, rule_ids: Any = None
    ) -> SuppressReport:
        """Scan, then apply ``# nosast`` inline markers.

        A finding on a line carrying ``# nosast`` is suppressed; with
        ``# nosast: PY001, PY004`` only the listed rules are suppressed.
        Suppressed findings stay pinned in the ledger (visible, never
        invisible) alongside the suppression note.
        """
        with self._lock:
            text = _check_source(source)
            seq = _check_seq(seq)
            self._monotonic(seq)
            selected = self._selected(rule_ids)
            findings = self._detect(text, selected)
            lines = text.split("\n")
            active: list = []
            suppressed: list = []
            for finding in findings:
                raw = lines[finding.line - 1]
                marker = _NOSAST_RE.search(raw)
                if marker:
                    ids = marker.group("ids")
                    if ids is None or finding.rule_id in {
                        part.strip()
                        for part in ids.split(",")
                        if part.strip()
                    }:
                        note = marker.group(0).strip()
                        suppressed.append(
                            SuppressedFinding(
                                finding=finding,
                                suppression_line=finding.line,
                                suppression_note=note,
                            )
                        )
                        continue
                active.append(finding)
            body = {
                "report_seq": seq,
                "source_digest": _source_digest(text),
                "version": SAST_SCANNER_VERSION,
                "active": [f.as_dict() for f in active],
                "suppressed": [s.as_dict() for s in suppressed],
            }
            return SuppressReport(
                source_digest=_source_digest(text),
                active=tuple(active),
                suppressed=tuple(suppressed),
                seq=seq,
                report_digest=_digest(body),
            )


def sast_scanner_audit_event(kind: str, seq: int, **detail: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for SAST scanner activity."""
    if kind not in _AUDIT_KINDS:
        raise SASTError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    event: dict = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": SAST_SCANNER_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    for key, value in detail.items():
        if isinstance(value, (str, bool)) or value is None:
            event[key] = value
        elif isinstance(value, int):
            if abs(value) > 2 ** 53:
                raise SASTError(
                    "int magnitude beyond 2**53 refused (JCS float-loss caveat)"
                )
            event[key] = value
        else:
            event[key] = jcs_canonical_json({"v": value}).decode("utf-8")
    return event


def main() -> None:
    """Self-check: rules, scan, taint, suppress, pins."""
    scanner = SASTScanner()
    rule_ids = [r.rule_id for r in scanner.rules()]
    assert rule_ids == sorted(rule_ids), rule_ids
    assert len(rule_ids) == len(_RULE_SPECS)
    assert scanner.registry_digest().startswith("sha256:")
    assert scanner.registry_digest() == scanner.registry_digest()

    dirty = (
        "import os, pickle\n"
        "password = \"hunter2\"\n"
        "x = input()\n"
        "eval(x)\n"
        "os.system(\"ls \" + x)\n"
        "data = pickle.loads(blob)\n"
        "h = hashlib.md5(b\"x\")\n"
        "except:\n"
        "    pass\n"
    )
    report = scanner.scan(dirty, 0)
    assert report.verify()
    found = {f.rule_id for f in report.findings}
    for rid in ("PY001", "PY002", "PY003", "PY005", "PY006", "PY008"):
        assert rid in found, (rid, found)

    clean = "import os\nos.getcwd()\n"
    report = scanner.scan(clean, 1)
    assert report.verify()
    assert report.findings == ()

    treport = scanner.taint(dirty, 2)
    assert treport.verify()
    flow_vars = {(f.rule_id, f.variable) for f in treport.flows}
    assert ("PY001", "x") in flow_vars, flow_vars
    assert ("PY002", "x") in flow_vars, flow_vars
    # source line for x is line 3 (the input() assignment)
    for f in treport.flows:
        if f.variable == "x":
            assert f.source_line == 3, f.as_dict()

    sanitized = "x = input()\ny = escape(x)\neval(y)\n"
    treport = scanner.taint(sanitized, 3)
    assert treport.verify()
    assert treport.flows == (), [f.as_dict() for f in treport.flows]

    nosast_src = "password = \"hunter2\"  # nosast\napi_key = \"xyz\"\n"
    sreport = scanner.suppress(nosast_src, 4)
    assert sreport.verify()
    assert len(sreport.suppressed) == 1, sreport.as_dict()
    assert sreport.suppressed[0].finding.line == 1
    assert len(sreport.active) == 1, sreport.as_dict()
    assert sreport.active[0].line == 2

    try:
        scanner.scan(clean, 5, rule_ids=["NOPE"])
        raise AssertionError("unknown rule must raise")
    except UnknownRuleError:
        pass
    try:
        scanner.scan(clean, 4)
        raise AssertionError("seq rewind must raise")
    except SeqOrderError:
        pass

    ev = sast_scanner_audit_event("scanned", 6, findings=2)
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["event"] == "scanned"
    try:
        sast_scanner_audit_event("bogus", 7)
        raise AssertionError("unknown kind must raise")
    except SASTError:
        pass
    print("sast-scanner OK: rules, scan, taint, suppress, pins")


if __name__ == "__main__":
    main()
