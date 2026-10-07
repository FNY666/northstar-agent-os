"""Secret scanner interface (Gitleaks shaped, simulated).

Research motivation: agents constantly read, write, and move text --
code, configs, logs, chat transcripts -- and credentials leak into
that text: an AWS key pasted into a debug log, a Slack token in a
committed config, a PEM header in a support ticket. Gitleaks-style
scanning reduces that to a repeatable bookkeeping shape:

- *patterns*: a pinned vocabulary of detection rules (plus
  host-added custom rules), each with a severity and a digest pin;
- *scan*: host-supplied text is booked against the rules and every
  hit becomes a frozen ``Finding`` with line/col, a redacted preview,
  and a digest pin over the full match;
- *allowlist*: pattern-level suppressions with a stated reason, so a
  known test fixture does not re-alert forever.

This module is the *bookkeeping* half of that shape:

- ``SecretScanner`` -- owns the pattern registry. ``add_pattern()``
  admits a host rule (regex, fail-closed); ``scan()`` books
  host-reported text against every rule and returns a frozen
  ``ScanReport``; ``allowlist()`` / ``remove_allowlist()`` manage
  suppressions; ``patterns()`` lists the pinned vocabulary.
- ``secret_scanner_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``scanned`` / ``pattern-added`` / ``allowlisted`` /
  ``allowlist-removed`` / ``rejected``); ids, counts, and digest pins
  only -- matched secret values never cross the audit boundary.

Detection rules (all pinned, deterministic ``re`` matching):

- ``aws-access-key-id``: ``AKIA`` + 16 alphanumerics.
- ``aws-secret-access-key``: ``aws_secret_access_key = <40 chars>``.
- ``github-pat`` / ``github-oauth``: ``ghp_`` / ``gho_`` + 36 chars.
- ``slack-token``: ``xox[baprs]-...``.
- ``stripe-secret-key``: ``sk_live_`` / ``sk_test_`` + 24 chars.
- ``openai-api-key``: ``sk-`` + 20 chars.
- ``google-api-key``: ``AIza`` + 35 chars.
- ``private-key``: PEM ``-----BEGIN [RSA ]PRIVATE KEY-----`` header.
- ``jwt``: three dot-separated base64url segments starting ``eyJ``.
- ``password-in-url``: ``scheme://user:pass@host``.
- ``generic-api-key``: ``api_key|secret|password|token = <16+ chars>``.
- ``generic-high-entropy``: a 20+ char token run whose Shannon
  entropy is >= 4.5 bits/char (heuristic, documented below).

Fail-closed edges (fail loudly, never guess):

- ``scan()`` refuses non-str or empty content and content over the
  1 MiB guardrail (``BadContentError``).
- ``add_pattern()`` refuses duplicate ids, bad id shape, uncompilable
  regexes, and unknown severities (``DuplicatePatternError`` /
  ``BadPatternError``).
- ``allowlist()`` refuses unknown patterns and duplicate
  (pattern, reason) pairs; ``remove_allowlist()`` refuses unknown or
  already-removed entries.
- A ``scan()`` hit is never invented: unknown patterns cannot fire,
  and spans already claimed by an earlier rule are skipped (first
  rule wins, registry order).
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``. A mutation
  that fails *after* consuming its seq keeps the consumed position
  (fail-closed ledger position).

Honest scope:

- This module is simulated bookkeeping, not a detection engine: it
  cannot read files, cannot prove a string is a live credential, and
  cannot prove the absence of secrets (a rotated key format it has
  never seen will not fire).
- The entropy rule is a heuristic: high-entropy strings that are
  not secrets (hashes, UUIDs, random test data) will fire it --
  severity ``low`` exists precisely so hosts can triage it.
- Findings pin what the *caller* supplied -- a lying host gets a
  lying ledger (GIGO boundary). Pair with an attested content feed
  for production.
- In-memory only: pair with the durable audit writer if scan
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Module version.
SECRET_SCANNER_VERSION = "secret-scanner.v1"

#: Schema pin carried by records and audit events.
SECRET_SCANNER_SCHEMA = "northstar.secret-scanner.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned severity vocabulary.
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
SEVERITIES: Tuple[str, ...] = ("low", "medium", "high")

#: Builtin pattern vocabulary: (pattern_id, regex, severity, description).
_BUILTINS: Tuple[Tuple[str, str, str, str], ...] = (
    ("aws-access-key-id",
     r"AKIA[0-9A-Z]{16}",
     HIGH,
     "AWS access key ID (AKIA + 16 alphanumerics)"),
    ("aws-secret-access-key",
     r"aws_secret_access_key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
     HIGH,
     "AWS secret access key assigned in config"),
    ("github-pat",
     r"ghp_[A-Za-z0-9]{36}",
     HIGH,
     "GitHub personal access token"),
    ("github-oauth",
     r"gho_[A-Za-z0-9]{36}",
     HIGH,
     "GitHub OAuth access token"),
    ("slack-token",
     r"xox[baprs]-[0-9A-Za-z-]{10,}",
     HIGH,
     "Slack token (bot/user/app/refresh)"),
    ("stripe-secret-key",
     r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
     HIGH,
     "Stripe secret API key"),
    ("openai-api-key",
     r"sk-[A-Za-z0-9]{20,}",
     MEDIUM,
     "OpenAI-style API key"),
    ("google-api-key",
     r"AIza[0-9A-Za-z\-_]{35}",
     HIGH,
     "Google API key"),
    ("private-key",
     r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
     HIGH,
     "PEM private key header"),
    ("jwt",
     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     MEDIUM,
     "JSON Web Token (three base64url segments)"),
    ("password-in-url",
     r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^\s/]+",
     MEDIUM,
     "URL with embedded credentials"),
    ("generic-api-key",
     r"(?i)(?:api[_-]?key|apikey|secret|passwd|password|token)"
     r"\s*[:=]\s*['\"]?[\w\-.~+/=]{16,}['\"]?",
     LOW,
     "Key/value pair that smells like a credential"),
)

#: Heuristic pseudo-pattern id for the entropy rule (not regex-based).
ENTROPY_PATTERN = "generic-high-entropy"

#: Token runs considered for the entropy heuristic.
_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

#: Minimum Shannon entropy (bits/char) for the heuristic to fire.
ENTROPY_THRESHOLD = 4.5

#: Content guardrail (1 MiB).
_MAX_CONTENT_BYTES = 1024 * 1024

#: Pattern id shape.
_PATTERN_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")

#: Audit event kinds.
KIND_SCANNED = "scanned"
KIND_PATTERN_ADDED = "pattern-added"
KIND_ALLOWLISTED = "allowlisted"
KIND_ALLOWLIST_REMOVED = "allowlist-removed"
KIND_REJECTED = "rejected"
_KINDS = (KIND_SCANNED, KIND_PATTERN_ADDED, KIND_ALLOWLISTED,
          KIND_ALLOWLIST_REMOVED, KIND_REJECTED)

#: Fields that must never cross the audit boundary (secret content).
_BANNED_AUDIT_FIELDS = ("match", "content", "secret", "redacted",
                        "full_match", "raw")


class SecretScannerError(Exception):
    """Base error for the secret scanner."""


class BadContentError(SecretScannerError):
    """scan() content is not a usable str (type, empty, oversized)."""


class BadPatternError(SecretScannerError):
    """add_pattern() was given a bad id, regex, severity, or description."""


class DuplicatePatternError(BadPatternError):
    """The pattern id is already registered."""


class UnknownPatternError(SecretScannerError):
    """A pattern id lookup missed the registry."""


class DuplicateAllowlistError(SecretScannerError):
    """The (pattern, reason) pair is already allowlisted."""


class UnknownAllowlistError(SecretScannerError):
    """An allowlist entry lookup missed the registry."""


class AllowlistRemovedError(UnknownAllowlistError):
    """The allowlist entry was already removed."""


class SeqOrderError(SecretScannerError):
    """A caller seq is not strictly increasing (no wall-clock)."""


class UnknownReportError(SecretScannerError):
    """A report id lookup missed the ledger."""


class UnknownFindingError(SecretScannerError):
    """A finding id lookup missed the ledger."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SecretScannerError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise SecretScannerError(f"{what} must be a non-empty str")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


def _redact(match: str) -> str:
    """Redacted preview: first 4 + ellipsis + last 2 chars, never reversible."""
    if len(match) <= 8:
        return "*" * len(match)
    return match[:4] + "\u2026" + match[-2:]


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass(frozen=True)
class PatternRecord:
    """One detection rule, digest-pinned."""

    pattern_id: str
    regex: str  # "" for the heuristic pseudo-pattern
    severity: str
    description: str
    seq: int
    digest: str
    builtin: bool
    version: str = SECRET_SCANNER_VERSION
    schema: str = SECRET_SCANNER_SCHEMA


@dataclass(frozen=True)
class Finding:
    """One booked secret hit, digest-pinned; the full match is digest-pinned,
    never stored in clear beyond the in-memory record."""

    finding_id: str
    report_id: str
    source_id: str
    pattern_id: str
    line_no: int  # 1-based
    col_no: int  # 1-based
    match_length: int
    redacted: str  # preview only, never reversible
    match_digest: str  # "sha256:" of the full match
    allowlisted: bool
    seq: int
    digest: str
    version: str = SECRET_SCANNER_VERSION
    schema: str = SECRET_SCANNER_SCHEMA

    def verify_match(self, match: str) -> bool:
        """True iff ``match`` re-derives the pinned match digest."""
        import hashlib as _hl
        return self.match_digest == "sha256:" + _hl.sha256(
            match.encode("utf-8")).hexdigest()

    def verify(self) -> bool:
        """Re-derive the record digest from its pinned fields."""
        body = ["finding", self.finding_id, self.report_id, self.source_id,
                self.pattern_id, self.line_no, self.col_no,
                self.match_digest, self.allowlisted, self.seq]
        return _pin(*body) == self.digest


@dataclass(frozen=True)
class ScanReport:
    """One completed scan, digest-pinned."""

    report_id: str
    source_id: str
    label: str
    content_digest: str  # "sha256:" of the scanned content
    findings: Tuple[Finding, ...]
    finding_count: int
    allowlisted_count: int
    seq: int
    digest: str
    version: str = SECRET_SCANNER_VERSION
    schema: str = SECRET_SCANNER_SCHEMA

    def verify(self) -> bool:
        """Re-derive the report digest from its pinned fields."""
        body = ["scan", self.report_id, self.source_id, self.content_digest,
                [f.digest for f in self.findings], self.seq]
        return _pin(*body) == self.digest


@dataclass(frozen=True)
class AllowlistRecord:
    """One pattern-level suppression, digest-pinned."""

    entry_id: str
    pattern_id: str
    reason: str
    active: bool
    seq: int
    digest: str
    version: str = SECRET_SCANNER_VERSION
    schema: str = SECRET_SCANNER_SCHEMA


@dataclass(frozen=True)
class AllowlistRemoval:
    """Terminal removal of an allowlist entry."""

    entry_id: str
    pattern_id: str
    seq: int
    digest: str
    version: str = SECRET_SCANNER_VERSION
    schema: str = SECRET_SCANNER_SCHEMA


class SecretScanner:
    """Deterministic single-host secret-scan bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._patterns: Dict[str, PatternRecord] = {}
        self._compiled: Dict[str, re.Pattern[str]] = {}
        self._order: List[str] = []  # pattern registration order
        self._allowlist: Dict[str, AllowlistRecord] = {}
        self._allowlisted_pairs: set[Tuple[str, str]] = set()
        self._reports: Dict[str, ScanReport] = {}
        self._findings: Dict[str, Finding] = {}
        self._next_report = 0
        self._next_finding = 0
        self._next_entry = 0
        self._last_seq = -1
        for pattern_id, regex, severity, description in _BUILTINS:
            record = PatternRecord(
                pattern_id=pattern_id,
                regex=regex,
                severity=severity,
                description=description,
                seq=0,
                digest=_pin(["pattern", pattern_id, regex, severity,
                             description, 0, True]),
                builtin=True,
            )
            self._patterns[pattern_id] = record
            self._compiled[pattern_id] = re.compile(regex)
            self._order.append(pattern_id)

    def _consume_seq(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than last seq {self._last_seq}"
            )
        self._last_seq = seq

    # -- vocabulary -------------------------------------------------

    def patterns(self) -> Tuple[str, ...]:
        """All pattern ids, builtin first, in registration order."""
        with self._lock:
            return tuple(self._order)

    def pattern(self, pattern_id: str) -> PatternRecord:
        """One pattern record, by id."""
        _check_str(pattern_id, "pattern_id")
        with self._lock:
            record = self._patterns.get(pattern_id)
            if record is None:
                raise UnknownPatternError(f"unknown pattern {pattern_id!r}")
            return record

    def add_pattern(
        self,
        pattern_id: str,
        regex: str,
        severity: str,
        seq: int,
        *,
        description: str = "",
    ) -> PatternRecord:
        """Admit a host rule; regex must compile, ids are unique."""
        if (not isinstance(pattern_id, str)
                or _PATTERN_ID_RE.fullmatch(pattern_id) is None):
            raise BadPatternError(
                "pattern_id must match [a-z0-9][a-z0-9-]{0,63}, "
                f"got {pattern_id!r}"
            )
        if not isinstance(regex, str) or not regex:
            raise BadPatternError("regex must be a non-empty str")
        try:
            compiled = re.compile(regex)
        except re.error as exc:
            raise BadPatternError(f"regex does not compile: {exc}") from exc
        if severity not in SEVERITIES:
            raise BadPatternError(
                f"severity must be one of {SEVERITIES}, got {severity!r}"
            )
        if not isinstance(description, str) or not description:
            raise BadPatternError("description must be a non-empty str")
        if len(description) > 256:
            raise BadPatternError("description exceeds 256 chars")
        with self._lock:
            self._consume_seq(seq)
            if pattern_id in self._patterns:
                raise DuplicatePatternError(
                    f"pattern {pattern_id!r} is already registered"
                )
            digest = _pin(["pattern", pattern_id, regex, severity,
                           description, seq, False])
            record = PatternRecord(
                pattern_id=pattern_id,
                regex=regex,
                severity=severity,
                description=description,
                seq=seq,
                digest=digest,
                builtin=False,
            )
            self._patterns[pattern_id] = record
            self._compiled[pattern_id] = compiled
            self._order.append(pattern_id)
            return record

    # -- allowlist --------------------------------------------------

    def allowlist(
        self, pattern_id: str, seq: int, reason: str
    ) -> AllowlistRecord:
        """Suppress future findings for one pattern, with a stated reason."""
        _check_str(pattern_id, "pattern_id")
        _check_str(reason, "reason")
        if len(reason) > 256:
            raise SecretScannerError("reason exceeds 256 chars")
        with self._lock:
            self._consume_seq(seq)
            if pattern_id not in self._patterns:
                raise UnknownPatternError(f"unknown pattern {pattern_id!r}")
            key = (pattern_id, reason)
            if key in self._allowlisted_pairs:
                raise DuplicateAllowlistError(
                    f"pattern {pattern_id!r} is already allowlisted "
                    f"for reason {reason!r}"
                )
            self._next_entry += 1
            entry_id = f"al-{self._next_entry}"
            digest = _pin(["allowlist", entry_id, pattern_id, reason, seq])
            record = AllowlistRecord(
                entry_id=entry_id,
                pattern_id=pattern_id,
                reason=reason,
                active=True,
                seq=seq,
                digest=digest,
            )
            self._allowlist[entry_id] = record
            self._allowlisted_pairs.add(key)
            return record

    def remove_allowlist(self, entry_id: str, seq: int) -> AllowlistRemoval:
        """Terminally remove an allowlist entry."""
        _check_str(entry_id, "entry_id")
        with self._lock:
            self._consume_seq(seq)
            record = self._allowlist.get(entry_id)
            if record is None:
                raise UnknownAllowlistError(f"unknown entry {entry_id!r}")
            if not record.active:
                raise AllowlistRemovedError(
                    f"entry {entry_id!r} was already removed"
                )
            digest = _pin(["allowlist-remove", entry_id, record.pattern_id,
                           seq])
            removal = AllowlistRemoval(
                entry_id=entry_id,
                pattern_id=record.pattern_id,
                seq=seq,
                digest=digest,
            )
            self._allowlist[entry_id] = AllowlistRecord(
                entry_id=record.entry_id,
                pattern_id=record.pattern_id,
                reason=record.reason,
                active=False,
                seq=record.seq,
                digest=record.digest,
            )
            self._allowlisted_pairs.discard(
                (record.pattern_id, record.reason))
            return removal

    def allowlist_entries(self) -> Tuple[AllowlistRecord, ...]:
        """All allowlist entries, active and removed, in entry order."""
        with self._lock:
            return tuple(
                self._allowlist[f"al-{i}"]
                for i in range(1, self._next_entry + 1)
            )

    # -- scan -------------------------------------------------------

    def _line_col(self, content: str, offset: int) -> Tuple[int, int]:
        line_no = content.count("\n", 0, offset) + 1
        col_no = offset - content.rfind("\n", 0, offset)
        return line_no, col_no

    def _scan_locked(
        self, report_id: str, source_id: str, content: str, seq: int
    ) -> List[Finding]:
        claimed: List[Tuple[int, int]] = []  # (start, end) spans, registry order
        hits: List[Tuple[str, int, int, str]] = []  # (pattern_id, s, e, match)

        def overlaps(start: int, end: int) -> bool:
            return any(start < e and s < end for s, e in claimed)

        for pattern_id in self._order:
            for match in self._compiled[pattern_id].finditer(content):
                start, end = match.span()
                if end <= start or overlaps(start, end):
                    continue
                claimed.append((start, end))
                hits.append((pattern_id, start, end, match.group(0)))

        for match in _ENTROPY_RE.finditer(content):
            start, end = match.span()
            token = match.group(0)
            if overlaps(start, end):
                continue
            if _shannon_entropy(token) < ENTROPY_THRESHOLD:
                continue
            claimed.append((start, end))
            hits.append((ENTROPY_PATTERN, start, end, token))

        hits.sort(key=lambda h: (h[1], h[2]))
        active = {p for (p, _r) in self._allowlisted_pairs}
        findings: List[Finding] = []
        for pattern_id, start, end, matched in hits:
            self._next_finding += 1
            finding_id = f"find-{self._next_finding}"
            line_no, col_no = self._line_col(content, start)
            import hashlib as _hl
            match_digest = "sha256:" + _hl.sha256(
                matched.encode("utf-8")).hexdigest()
            allowlisted = pattern_id in active
            digest = _pin("finding", finding_id, report_id, source_id,
                          pattern_id, line_no, col_no, match_digest,
                          allowlisted, seq)
            findings.append(Finding(
                finding_id=finding_id,
                report_id=report_id,
                source_id=source_id,
                pattern_id=pattern_id,
                line_no=line_no,
                col_no=col_no,
                match_length=end - start,
                redacted=_redact(matched),
                match_digest=match_digest,
                allowlisted=allowlisted,
                seq=seq,
                digest=digest,
            ))
        return findings

    def scan(
        self, source_id: str, content: str, seq: int, *, label: str = ""
    ) -> ScanReport:
        """Book ``content`` against every rule; return a pinned report."""
        _check_str(source_id, "source_id")
        if not isinstance(content, str) or not content:
            raise BadContentError("content must be a non-empty str")
        if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            raise BadContentError(
                f"content exceeds {_MAX_CONTENT_BYTES} bytes guardrail"
            )
        if not isinstance(label, str):
            raise SecretScannerError("label must be a str")
        with self._lock:
            self._consume_seq(seq)
            self._next_report += 1
            report_id = f"scan-{self._next_report}"
            findings = self._scan_locked(report_id, source_id, content, seq)
            import hashlib as _hl
            content_digest = "sha256:" + _hl.sha256(
                content.encode("utf-8")).hexdigest()
            digest = _pin("scan", report_id, source_id, content_digest,
                          [f.digest for f in findings], seq)
            report = ScanReport(
                report_id=report_id,
                source_id=source_id,
                label=label,
                content_digest=content_digest,
                findings=tuple(findings),
                finding_count=len(findings),
                allowlisted_count=sum(1 for f in findings if f.allowlisted),
                seq=seq,
                digest=digest,
            )
            self._reports[report_id] = report
            for finding in findings:
                self._findings[finding.finding_id] = finding
            return report

    # -- views ------------------------------------------------------

    def report(self, report_id: str) -> ScanReport:
        """A scan report, by id."""
        _check_str(report_id, "report_id")
        with self._lock:
            report = self._reports.get(report_id)
            if report is None:
                raise UnknownReportError(f"unknown report {report_id!r}")
            return report

    def report_ids(self) -> Tuple[str, ...]:
        """All report ids, in scan order."""
        with self._lock:
            return tuple(f"scan-{i}" for i in range(1, self._next_report + 1))

    def finding(self, finding_id: str) -> Finding:
        """A finding, by id."""
        _check_str(finding_id, "finding_id")
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                raise UnknownFindingError(f"unknown finding {finding_id!r}")
            return finding


def secret_scanner_audit_event(
    kind: str, seq: int, **fields: Any
) -> "dict[str, Any]":
    """Shape an ``audit.ndjson/1`` record for a secret-scanner event."""
    if kind not in _KINDS:
        raise SecretScannerError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    for key in _BANNED_AUDIT_FIELDS:
        if key in fields:
            raise SecretScannerError(
                f"field {key!r} must not cross the audit boundary"
            )
    event = {
        "kind": kind,
        "seq": seq,
        "schema": AUDIT_SCHEMA,
        "module": SECRET_SCANNER_SCHEMA,
    }
    event.update({k: v for k, v in fields.items()})
    return event


def main() -> None:
    ss = SecretScanner()
    assert "aws-access-key-id" in ss.patterns()
    assert len(ss.patterns()) == len(_BUILTINS)
    # One pinned hit.
    r = ss.scan("repo-a", "key = AKIAIOSFODNN7EXAMPLE\n", 1)
    assert r.report_id == "scan-1" and r.finding_count == 1
    f = r.findings[0]
    assert f.pattern_id == "aws-access-key-id"
    assert (f.line_no, f.col_no) == (1, 7), (f.line_no, f.col_no)
    assert f.redacted == "AKIA\u2026LE", f.redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted
    assert f.verify_match("AKIAIOSFODNN7EXAMPLE")
    assert not f.verify_match("AKIAIOSFODNN7EXAMPLF")
    assert f.verify() and r.verify()
    # Allowlist suppresses, removal re-enables.
    ss.allowlist("aws-access-key-id", 2, "test fixture")
    r2 = ss.scan("repo-a", "key = AKIAIOSFODNN7EXAMPLE\n", 3)
    assert r2.finding_count == 1 and r2.allowlisted_count == 1
    assert r2.findings[0].allowlisted
    ss.remove_allowlist("al-1", 4)
    r3 = ss.scan("repo-a", "key = AKIAIOSFODNN7EXAMPLE\n", 5)
    assert r3.allowlisted_count == 0
    # Fail-closed edges.
    try:
        ss.scan("repo-a", "", 6)
    except BadContentError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BadContentError")
    try:
        ss.add_pattern("aws-access-key-id", r"x", LOW, 7,
                       description="dup")
    except DuplicatePatternError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected DuplicatePatternError")
    try:
        ss.scan("repo-a", "x", 5)
    except SeqOrderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected SeqOrderError")
    secret_scanner_audit_event(
        KIND_SCANNED, 8, report_id=r.report_id,
        findings=r.finding_count, source_id=r.source_id,
    )
    print("secret-scanner OK: patterns, scan, allowlist, refusals, audit")


if __name__ == "__main__":
    main()
