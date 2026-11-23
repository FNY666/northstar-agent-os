"""Coverage reporter: simulated coverage.py-style measurement bookkeeping.

Simulated interface (coverage.py / Codecov lineage). This module books
line-coverage *measurement decisions* on host-reported coverage data: it
pins registered sources, measured hit sets, coverage reports, and
per-line annotations with ``sha256:`` digest pins. It performs no code
execution and no real tracing — pins bind the *reported* hit sets, and
a frozen audit trail records every mutation.

Honest scope: ``measure`` pins the host's claimed covered lines (GIGO
boundary — it cannot prove the lines actually executed); ``report``
aggregates arithmetic, not truth; ``annotate`` pins the reported
line classification. Pair with a real tracing tracer for production use.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock), RLock-guarded, fail-closed, stdlib-only.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
COVERAGE_REPORTER_VERSION = "coverage-reporter.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.coverage-reporter.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Guardrail: maximum lines a single source may declare.
MAX_LINES = 1_000_000

#: Guardrail: maximum sources retained in the ledger.
MAX_SOURCES = 10000

#: Guardrail: maximum annotation length in chars.
MAX_SOURCE_TEXT = 8_000_000


def _sha256_hex(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _pin(obj: Any) -> str:
    return _sha256_hex(jcs_canonical_json(obj))


class CoverageError(Exception):
    """Base fail-closed coverage-reporter error."""


class UnknownSourceError(CoverageError):
    """No source registered under this id."""


class DuplicateSourceError(CoverageError):
    """A source with this id is already registered."""


class BadLineError(CoverageError):
    """A line number is malformed or outside the declared source range."""


class ValidationError(CoverageError):
    """A plain input-validation refusal."""


class SeqOrderError(CoverageError):
    """Caller seq did not strictly increase."""


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"seq must be an int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"seq must be >= 0, got {value}")
    return value


def _check_line_no(value: Any, total: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadLineError(f"line number must be an int, got {type(value).__name__}")
    if value < 1 or value > total:
        raise BadLineError(f"line {value} outside source range 1..{total}")
    return value


def _pct_bp(covered: int, total: int) -> int:
    """Coverage percent in basis points (10000 = 100%), round-half-up."""
    return (covered * 10000 * 2 + total) // (2 * total) if total else 0


@dataclass(frozen=True)
class SourceRecord:
    """Pinned registration of a source file."""
    file_id: str
    lines_total: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {"file_id": self.file_id, "lines_total": self.lines_total,
                "seq": self.seq, "pin": self.pin}


@dataclass(frozen=True)
class CoverageRecord:
    """Pinned measurement of covered lines for one source."""
    file_id: str
    covered: Tuple[int, ...]
    missed: Tuple[int, ...]
    lines_total: int
    covered_count: int
    percent_bp: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {"file_id": self.file_id, "covered": list(self.covered),
                "missed": list(self.missed), "lines_total": self.lines_total,
                "covered_count": self.covered_count, "percent_bp": self.percent_bp,
                "seq": self.seq, "pin": self.pin}

    def verify(self) -> bool:
        return _pin({"file_id": self.file_id, "covered": list(self.covered),
                     "lines_total": self.lines_total, "seq": self.seq}) == self.pin


@dataclass(frozen=True)
class ReportRecord:
    """Pinned aggregate coverage report across all measured sources."""
    files: Tuple[str, ...]
    lines_total: int
    covered_total: int
    percent_bp: int
    per_file: Tuple[Dict[str, Any], ...]
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {"files": list(self.files), "lines_total": self.lines_total,
                "covered_total": self.covered_total, "percent_bp": self.percent_bp,
                "per_file": list(self.per_file), "seq": self.seq, "pin": self.pin}


@dataclass(frozen=True)
class AnnotationRecord:
    """Pinned per-line covered/uncovered annotation for one source."""
    file_id: str
    lines: Tuple[Dict[str, Any], ...]
    covered_count: int
    missed_count: int
    seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {"file_id": self.file_id, "lines": list(self.lines),
                "covered_count": self.covered_count, "missed_count": self.missed_count,
                "seq": self.seq, "pin": self.pin}

    def verify(self) -> bool:
        return _pin({"file_id": self.file_id, "lines": [dict(l) for l in self.lines],
                     "seq": self.seq}) == self.pin


def coverage_reporter_audit_event(kind: str, seq: int, detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for coverage-reporter events.

    Carries ids, counts, and digest pins only — never source text or
    line-level contents beyond the classification ledger itself.
    """
    allowed = ("source-registered", "measured", "reported", "annotated", "rejected")
    if kind not in allowed:
        raise CoverageError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise CoverageError("detail must be a mapping")
    event = {"schema": AUDIT_SCHEMA, "module": SCHEMA_PIN, "kind": kind,
             "seq": seq, "detail": dict(detail)}
    event["pin"] = _pin(event)
    return event


class CoverageReporter:
    """Deterministic single-host coverage measurement ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sources: Dict[str, SourceRecord] = {}
        self._coverage: Dict[str, CoverageRecord] = {}
        self._last_seq = -1
        self._audit: List[Dict[str, Any]] = []

    def _claim_seq(self, seq: int) -> None:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq {seq} did not strictly increase (last {self._last_seq})")
        self._last_seq = seq

    def _log(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        self._audit.append(coverage_reporter_audit_event(kind, seq, detail))

    def register_source(self, file_id: str, lines_total: int, seq: int) -> SourceRecord:
        """Register a source file with its declared line count."""
        with self._lock:
            if not isinstance(file_id, str) or not file_id:
                raise ValidationError("file_id must be a non-empty str")
            if isinstance(lines_total, bool) or not isinstance(lines_total, int):
                raise ValidationError("lines_total must be an int")
            if lines_total < 1 or lines_total > MAX_LINES:
                raise ValidationError(f"lines_total must be in 1..{MAX_LINES}")
            self._claim_seq(seq)
            if len(self._sources) >= MAX_SOURCES and file_id not in self._sources:
                raise ValidationError("source ledger is full")
            if file_id in self._sources:
                self._log("rejected", seq, {"reason": "duplicate-source", "file_id": file_id})
                raise DuplicateSourceError(f"duplicate source: {file_id!r}")
            pin = _pin({"file_id": file_id, "lines_total": lines_total, "seq": seq})
            rec = SourceRecord(file_id=file_id, lines_total=lines_total, seq=seq, pin=pin)
            self._sources[file_id] = rec
            self._log("source-registered", seq, {"file_id": file_id, "pin": pin})
            return rec

    def measure(self, file_id: str, covered_lines: Any, seq: int) -> CoverageRecord:
        """Pin the host's claimed covered-line set for a registered source."""
        with self._lock:
            if not isinstance(file_id, str) or not file_id:
                raise ValidationError("file_id must be a non-empty str")
            try:
                lines = list(covered_lines)
            except TypeError:
                raise BadLineError("covered_lines must be iterable")
            self._claim_seq(seq)
            src = self._sources.get(file_id)
            if src is None:
                self._log("rejected", seq, {"reason": "unknown-source", "file_id": file_id})
                raise UnknownSourceError(f"unknown source: {file_id!r}")
            covered = sorted({_check_line_no(v, src.lines_total) for v in lines})
            missed = tuple(n for n in range(1, src.lines_total + 1) if n not in set(covered))
            covered_t = tuple(covered)
            pct = _pct_bp(len(covered_t), src.lines_total)
            pin = _pin({"file_id": file_id, "covered": list(covered_t),
                        "lines_total": src.lines_total, "seq": seq})
            rec = CoverageRecord(file_id=file_id, covered=covered_t, missed=missed,
                                 lines_total=src.lines_total, covered_count=len(covered_t),
                                 percent_bp=pct, seq=seq, pin=pin)
            self._coverage[file_id] = rec
            self._log("measured", seq, {"file_id": file_id, "covered_count": len(covered_t),
                                       "percent_bp": pct, "pin": pin})
            return rec

    def report(self, seq: int) -> ReportRecord:
        """Aggregate a pinned report over every measured source."""
        with self._lock:
            self._claim_seq(seq)
            files = sorted(self._coverage)
            per_file = []
            lines_total = 0
            covered_total = 0
            for fid in files:
                rec = self._coverage[fid]
                lines_total += rec.lines_total
                covered_total += rec.covered_count
                per_file.append({"file_id": fid, "lines_total": rec.lines_total,
                                 "covered": rec.covered_count, "percent_bp": rec.percent_bp})
            pct = _pct_bp(covered_total, lines_total) if lines_total else 0
            pin = _pin({"files": files, "lines_total": lines_total,
                        "covered_total": covered_total, "seq": seq})
            rec_out = ReportRecord(files=tuple(files), lines_total=lines_total,
                                   covered_total=covered_total, percent_bp=pct,
                                   per_file=tuple(per_file), seq=seq, pin=pin)
            self._log("reported", seq, {"files": files, "percent_bp": pct, "pin": pin})
            return rec_out

    def annotate(self, file_id: str, seq: int) -> AnnotationRecord:
        """Pin per-line covered/uncovered classification for one source."""
        with self._lock:
            if not isinstance(file_id, str) or not file_id:
                raise ValidationError("file_id must be a non-empty str")
            self._claim_seq(seq)
            rec = self._coverage.get(file_id)
            if rec is None:
                src = self._sources.get(file_id)
                if src is None:
                    self._log("rejected", seq, {"reason": "unknown-source", "file_id": file_id})
                    raise UnknownSourceError(f"unknown source: {file_id!r}")
                raise CoverageError(f"source measured but no measurement: {file_id!r}")
            covered_set = set(rec.covered)
            lines = tuple(
                {"no": n, "covered": n in covered_set}
                for n in range(1, rec.lines_total + 1)
            )
            pin = _pin({"file_id": file_id, "lines": [dict(l) for l in lines], "seq": seq})
            ann = AnnotationRecord(file_id=file_id, lines=lines,
                                   covered_count=rec.covered_count,
                                   missed_count=len(rec.missed), seq=seq, pin=pin)
            self._log("annotated", seq, {"file_id": file_id, "covered_count": rec.covered_count,
                                         "pin": pin})
            return ann

    # -- views ---------------------------------------------------------
    def source(self, file_id: str) -> SourceRecord:
        with self._lock:
            rec = self._sources.get(file_id)
            if rec is None:
                raise UnknownSourceError(f"unknown source: {file_id!r}")
            return rec

    def measurement(self, file_id: str) -> CoverageRecord:
        with self._lock:
            rec = self._coverage.get(file_id)
            if rec is None:
                raise UnknownSourceError(f"no measurement for source: {file_id!r}")
            return rec

    def file_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sources))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    r = CoverageReporter()
    r.register_source("mod.py", 10, 0)
    m = r.measure("mod.py", [1, 2, 3, 4, 5, 6, 7], 1)
    assert m.percent_bp == 7000
    assert m.verify()
    rep = r.report(2)
    assert rep.files == ("mod.py",) and rep.percent_bp == 7000
    ann = r.annotate("mod.py", 3)
    assert ann.verify() and ann.covered_count == 7 and ann.missed_count == 3
    print("coverage-reporter OK: register, measure, report, annotate, pins")


if __name__ == "__main__":
    main()
