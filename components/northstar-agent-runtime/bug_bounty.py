"""Bug-bounty decision ledger: submit, triage, reward.

Research context: bug-bounty programs (HackerOne / Bugcrowd / huntr shaped)
turn outside vulnerability reports into a workflow: a reporter *submits* a
finding, an analyst *triages* it (accepted / duplicate / invalid /
needs-more-info / out-of-scope), and an accepted finding earns a *reward*.
The dangerous direction is the report content itself -- a submission may
carry exploit code, reproduction steps, or private data that must never
enter the ledger or the audit trail.

This module is the *decision ledger* layer for that workflow. It owns the
submit -> triage -> reward lifecycle as a deterministic, digest-pinned
state machine with caller-int seq discipline and an audit trail. It runs no
program, inspects no report, pays no money; it books the host's *declared*
decisions in a tamper-evident, seq-ordered form.

What each operation means:

1. ``submit(report_id, seq, severity=..., title_digest="", report_digest="")``
   -- books one *declared* report submission. The severity (``critical`` /
   ``high`` / ``medium`` / ``low`` / ``informational``) is host-declared and
   booked as data. Report content travels as ``sha256:`` digest pins only:
   raw titles, descriptions, PoCs, and reproduction steps never enter a
   record. Duplicate ids refused fail-closed.
2. ``triage(report_id, seq, verdict, analyst="")`` -- books one triage
   decision over the pinned verdict vocabulary (``accepted`` / ``duplicate``
   / ``invalid`` / ``needs-more-info`` / ``out-of-scope``), minted as
   ``trg-N``. One triage per report; a second triage is refused
   fail-closed.
3. ``reward(report_id, seq, amount_cents, currency="USD")`` -- books one
   declared bounty award, minted as ``rwd-N``. Requires a prior triage with
   verdict ``accepted``; the amount is an exact non-negative int of minor
   currency units (no floats, no rounding); the currency is a 3-letter
   uppercase code. One reward per report, booked as a *declaration*, never
   proof of payment.
4. ``status(report_id, seq)`` -- pure read view: submission, triage, and
   reward state of one report plus re-derived digest integrity as data.

Honest scope: a booked ``accepted`` verdict means "the host declared this
report accepted at this seq", never "this report describes a real
vulnerability". A booked reward means "the ledger says an award was
declared", never that money moved. Declarations are GIGO host claims.

House style: frozen dataclasses, caller int seqs strictly increasing
(claim-then-burn: failed mutations consume their seq and book
``bug-bounty.rejected``; rewinds raise bare without consuming), no
wall-clock, RLock-guarded, fail-closed, stdlib-only (with the sibling
``canonical_json`` try/except fallback), ``sha256:`` digest pins with
``verify()``, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
BUG_BOUNTY_VERSION = "bug-bounty.v1"

#: Schema pin carried by records and audit events.
BUG_BOUNTY_SCHEMA = "northstar.bug-bounty.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Declared severity vocabulary (booked as data).
SEVERITIES = ("critical", "high", "medium", "low", "informational")

#: Declared triage verdict vocabulary (booked as data).
VERDICTS = ("accepted", "duplicate", "invalid", "needs-more-info", "out-of-scope")

#: Audit kinds for this module (append-only vocabulary).
KIND_SUBMITTED = "bug-bounty.submitted"
KIND_TRIAGED = "bug-bounty.triaged"
KIND_REWARDED = "bug-bounty.rewarded"
KIND_REJECTED = "bug-bounty.rejected"
_KINDS = (KIND_SUBMITTED, KIND_TRIAGED, KIND_REWARDED, KIND_REJECTED)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class BugBountyError(Exception):
    """Base class for all bug-bounty ledger failures."""


class BadIdError(BugBountyError):
    """Report id is malformed."""


class DuplicateReportError(BugBountyError):
    """A report id is already booked."""


class UnknownReportError(BugBountyError):
    """No report is booked under this id."""


class BadDigestError(BugBountyError):
    """A digest pin is not a valid sha256: pin (or empty)."""


class BadSeverityError(BugBountyError):
    """Severity is not in the pinned vocabulary."""


class BadVerdictError(BugBountyError):
    """Triage verdict is not in the pinned vocabulary."""


class BadAmountError(BugBountyError):
    """Reward amount is not a non-negative int of minor currency units."""


class BadCurrencyError(BugBountyError):
    """Currency is not a 3-letter uppercase code."""


class AlreadyTriagedError(BugBountyError):
    """A report that already has a triage decision cannot be triaged again."""


class NotTriagedError(BugBountyError):
    """A reward requires a prior triage decision."""


class NotAcceptedError(BugBountyError):
    """A reward requires a triage verdict of 'accepted'."""


class AlreadyRewardedError(BugBountyError):
    """A report that already has a reward cannot be rewarded again."""


class BadAnalystError(BugBountyError):
    """Analyst label is malformed."""


class SeqOrderError(BugBountyError):
    """Seq is malformed or not strictly increasing."""


class AuditKindError(BugBountyError):
    """Unknown audit kind or banned key in audit detail."""


# ---------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_id(value: Any, name: str = "report_id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise BadIdError(f"{name} must not contain whitespace")
    return value


def _check_analyst(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 128:
        raise BadAnalystError("analyst must be a str (<=128 chars)")
    if value and (value != value.strip() or any(c.isspace() for c in value)):
        raise BadAnalystError("analyst must not contain whitespace")
    return value


def _check_optional_digest(value: Any, name: str) -> str:
    """Digest pin or '' (content pin never required at submit time)."""
    if value == "":
        return ""
    if (
        not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != len("sha256:") + 64
    ):
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    try:
        int(value[len("sha256:"):], 16)
    except ValueError:
        raise BadDigestError(f"{name} must be '' or a 'sha256:<64hex>' pin")
    return value


def _check_severity(value: Any) -> str:
    if not isinstance(value, str) or value not in SEVERITIES:
        raise BadSeverityError(f"severity must be one of {SEVERITIES}")
    return value


def _check_verdict(value: Any) -> str:
    if not isinstance(value, str) or value not in VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERDICTS}")
    return value


def _check_amount(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadAmountError("amount_cents must be an int of minor currency units")
    if value < 0:
        raise BadAmountError("amount_cents must be non-negative")
    return value


def _check_currency(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 3
        or not value.isascii()
        or not value.isalpha()
        or value != value.upper()
    ):
        raise BadCurrencyError("currency must be a 3-letter uppercase code")
    return value


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        try:
            return _cj.jcs_dumps(obj).encode("utf-8")
        except Exception:
            pass
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], domain: str) -> str:
    h = hashlib.sha256()
    h.update(b"northstar.bug-bounty:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def bug_bounty_audit_event(audit_kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw report content never crosses this boundary."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    banned = (
        "title",
        "description",
        "report",
        "content",
        "text",
        "poc",
        "exploit",
        "payload",
        "reproduction",
        "steps",
        "code",
        "secret",
        "raw",
        "private",
        "attachment",
    )
    for key in detail:
        if key in banned:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    event = {
        "schema": AUDIT_SCHEMA,
        "module": BUG_BOUNTY_SCHEMA,
        "kind": audit_kind,
        "seq": _check_seq(seq),
        "detail": dict(detail),
    }
    return event


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportRecord:
    """One booked report submission."""

    report_id: str
    severity: str
    title_digest: str
    report_digest: str
    seq: int
    digest: str
    schema: str = BUG_BOUNTY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.report_id, self.severity, self.title_digest, self.report_digest, self.seq),
            "report",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": BUG_BOUNTY_VERSION,
            "report_id": self.report_id,
            "severity": self.severity,
            "title_digest": self.title_digest,
            "report_digest": self.report_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TriageRecord:
    """One booked triage decision (minted trg-N)."""

    triage_id: str
    report_id: str
    verdict: str
    analyst: str
    seq: int
    digest: str
    schema: str = BUG_BOUNTY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.triage_id, self.report_id, self.verdict, self.analyst, self.seq),
            "triage",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": BUG_BOUNTY_VERSION,
            "triage_id": self.triage_id,
            "report_id": self.report_id,
            "verdict": self.verdict,
            "analyst": self.analyst,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RewardRecord:
    """One booked bounty award (minted rwd-N)."""

    reward_id: str
    report_id: str
    amount_cents: int
    currency: str
    seq: int
    digest: str
    schema: str = BUG_BOUNTY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.reward_id, self.report_id, self.amount_cents, self.currency, self.seq),
            "reward",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": BUG_BOUNTY_VERSION,
            "reward_id": self.reward_id,
            "report_id": self.report_id,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class StatusReport:
    """Pure read view of one report's submit/triage/reward state."""

    report_id: str
    submitted: bool
    severity: str
    triaged: bool
    verdict: str
    rewarded: bool
    amount_cents: int
    currency: str
    integrity_ok: bool
    digest: str
    schema: str = BUG_BOUNTY_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.report_id,
                self.submitted,
                self.severity,
                self.triaged,
                self.verdict,
                self.rewarded,
                self.amount_cents,
                self.currency,
            ),
            "status",
        )
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": BUG_BOUNTY_VERSION,
            "report_id": self.report_id,
            "submitted": self.submitted,
            "severity": self.severity,
            "triaged": self.triaged,
            "verdict": self.verdict,
            "rewarded": self.rewarded,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class BugBounty:
    """Bug-bounty submit -> triage -> reward decision ledger.

    Deterministic single-host state machine: frozen records, caller-int
    seqs strictly increasing (claim-then-burn), RLock-guarded, fail-closed,
    no wall-clock, stdlib-only. Booked verdicts and rewards are host
    declarations, never proof of a vulnerability or of payment.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._reports: Dict[str, ReportRecord] = {}
        self._triages: Dict[str, TriageRecord] = {}
        self._triage_by_report: Dict[str, str] = {}
        self._rewards: Dict[str, RewardRecord] = {}
        self._reward_by_report: Dict[str, str] = {}
        self._n_triage = 0
        self._n_reward = 0
        self._audit: List[Dict[str, Any]] = []

    # -- internals ----------------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(bug_bounty_audit_event(audit_kind, seq, **detail))

    # -- mutations ----------------------------------------------------------

    def submit(
        self,
        report_id: Any,
        seq: Any,
        severity: Any = "low",
        title_digest: Any = "",
        report_digest: Any = "",
    ) -> ReportRecord:
        """Book one report submission. Content travels as digest pins only."""
        with self._lock:
            seq = self._claim(seq)  # claim first: failures burn the seq
            try:
                rid = _check_id(report_id)
                sev = _check_severity(severity)
                tdig = _check_optional_digest(title_digest, "title_digest")
                rdig = _check_optional_digest(report_digest, "report_digest")
                if rid in self._reports:
                    raise DuplicateReportError(f"report already booked: {rid!r}")
                digest = _digest_pin((rid, sev, tdig, rdig, seq), "report")
                record = ReportRecord(
                    report_id=rid,
                    severity=sev,
                    title_digest=tdig,
                    report_digest=rdig,
                    seq=seq,
                    digest=digest,
                )
            except BugBountyError:
                self._emit(KIND_REJECTED, seq, op="submit")
                raise
            self._reports[rid] = record
            self._emit(
                KIND_SUBMITTED,
                seq,
                report_id=rid,
                severity=sev,
                title_digest=tdig,
                report_digest=rdig,
            )
            return record

    def triage(self, report_id: Any, seq: Any, verdict: Any, analyst: Any = "") -> TriageRecord:
        """Book one triage decision for a submitted report (one-shot)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _check_id(report_id)
                ver = _check_verdict(verdict)
                ana = _check_analyst(analyst)
                if rid not in self._reports:
                    raise UnknownReportError(f"unknown report: {rid!r}")
                if rid in self._triage_by_report:
                    raise AlreadyTriagedError(f"report already triaged: {rid!r}")
                self._n_triage += 1
                tid = f"trg-{self._n_triage}"
                digest = _digest_pin((tid, rid, ver, ana, seq), "triage")
                record = TriageRecord(
                    triage_id=tid,
                    report_id=rid,
                    verdict=ver,
                    analyst=ana,
                    seq=seq,
                    digest=digest,
                )
            except BugBountyError:
                self._emit(KIND_REJECTED, seq, op="triage")
                raise
            self._triages[tid] = record
            self._triage_by_report[rid] = tid
            self._emit(
                KIND_TRIAGED, seq, triage_id=tid, report_id=rid, verdict=ver, analyst=ana
            )
            return record

    def reward(self, report_id: Any, seq: Any, amount_cents: Any, currency: Any = "USD") -> RewardRecord:
        """Book one bounty award. Requires a prior triage verdict of 'accepted'."""
        with self._lock:
            seq = self._claim(seq)
            try:
                rid = _check_id(report_id)
                amt = _check_amount(amount_cents)
                cur = _check_currency(currency)
                if rid not in self._reports:
                    raise UnknownReportError(f"unknown report: {rid!r}")
                tid = self._triage_by_report.get(rid)
                if tid is None:
                    raise NotTriagedError(f"report has no triage decision: {rid!r}")
                if self._triages[tid].verdict != "accepted":
                    raise NotAcceptedError(
                        f"report triaged as {self._triages[tid].verdict!r}, not 'accepted'"
                    )
                if rid in self._reward_by_report:
                    raise AlreadyRewardedError(f"report already rewarded: {rid!r}")
                self._n_reward += 1
                wid = f"rwd-{self._n_reward}"
                digest = _digest_pin((wid, rid, amt, cur, seq), "reward")
                record = RewardRecord(
                    reward_id=wid,
                    report_id=rid,
                    amount_cents=amt,
                    currency=cur,
                    seq=seq,
                    digest=digest,
                )
            except BugBountyError:
                self._emit(KIND_REJECTED, seq, op="reward")
                raise
            self._rewards[wid] = record
            self._reward_by_report[rid] = wid
            self._emit(
                KIND_REWARDED,
                seq,
                reward_id=wid,
                report_id=rid,
                amount_cents=amt,
                currency=cur,
            )
            return record

    # -- pure reads ---------------------------------------------------------

    def _read_seq(self, seq: Any) -> int:
        return _check_seq(seq)

    def report_record(self, report_id: Any, seq: Any) -> ReportRecord:
        with self._lock:
            self._read_seq(seq)
            rid = _check_id(report_id)
            if rid not in self._reports:
                raise UnknownReportError(f"unknown report: {rid!r}")
            return self._reports[rid]

    def triage_record(self, report_id: Any, seq: Any) -> TriageRecord:
        with self._lock:
            self._read_seq(seq)
            rid = _check_id(report_id)
            tid = self._triage_by_report.get(rid)
            if tid is None:
                raise UnknownReportError(f"no triage booked for report: {rid!r}")
            return self._triages[tid]

    def reward_record(self, report_id: Any, seq: Any) -> RewardRecord:
        with self._lock:
            self._read_seq(seq)
            rid = _check_id(report_id)
            wid = self._reward_by_report.get(rid)
            if wid is None:
                raise UnknownReportError(f"no reward booked for report: {rid!r}")
            return self._rewards[wid]

    def report_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._reports))

    def triaged_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._triage_by_report))

    def rewarded_ids(self, seq: Any) -> Tuple[str, ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(self._reward_by_report))

    def pending_ids(self, seq: Any) -> Tuple[str, ...]:
        """Submitted reports with no triage decision yet."""
        with self._lock:
            self._read_seq(seq)
            return tuple(sorted(r for r in self._reports if r not in self._triage_by_report))

    def status(self, report_id: Any, seq: Any) -> StatusReport:
        """Pure read view of one report's lifecycle state (seq never consumed)."""
        with self._lock:
            self._read_seq(seq)
            rid = _check_id(report_id)
            rec = self._reports.get(rid)
            if rec is None:
                raise UnknownReportError(f"unknown report: {rid!r}")
            tid = self._triage_by_report.get(rid)
            wid = self._reward_by_report.get(rid)
            tri = self._triages.get(tid) if tid else None
            rwd = self._rewards.get(wid) if wid else None
            verdict = tri.verdict if tri else ""
            amt = rwd.amount_cents if rwd else 0
            cur = rwd.currency if rwd else ""
            integrity = rec.verify()
            if tri is not None:
                integrity = integrity and tri.verify()
            if rwd is not None:
                integrity = integrity and rwd.verify()
            digest = _digest_pin(
                (rid, True, rec.severity, tri is not None, verdict, rwd is not None, amt, cur),
                "status",
            )
            return StatusReport(
                report_id=rid,
                submitted=True,
                severity=rec.severity,
                triaged=tri is not None,
                verdict=verdict,
                rewarded=rwd is not None,
                amount_cents=amt,
                currency=cur,
                integrity_ok=integrity,
                digest=digest,
            )

    def stats(self, seq: Any) -> Dict[str, Any]:
        with self._lock:
            self._read_seq(seq)
            verdict_tally: Dict[str, int] = {v: 0 for v in VERDICTS}
            for tri in self._triages.values():
                verdict_tally[tri.verdict] += 1
            total_cents = sum(r.amount_cents for r in self._rewards.values())
            return {
                "schema": BUG_BOUNTY_SCHEMA,
                "reports": len(self._reports),
                "triaged": len(self._triage_by_report),
                "rewarded": len(self._reward_by_report),
                "pending": len(self._reports) - len(self._triage_by_report),
                "verdicts": verdict_tally,
                "total_reward_cents": total_cents,
                "rejected_rows": sum(1 for e in self._audit if e["kind"] == KIND_REJECTED),
            }

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._read_seq(seq)
            return tuple(self._audit)


def main() -> None:
    ledger = BugBounty()
    digest = "sha256:" + "ab" * 32
    record = ledger.submit("rpt-1", 1, severity="high", title_digest=digest, report_digest=digest)
    assert record.verify()
    tri = ledger.triage("rpt-1", 2, "accepted", analyst="alice")
    assert tri.verify() and tri.triage_id == "trg-1"
    rwd = ledger.reward("rpt-1", 3, 50000, currency="USD")
    assert rwd.verify() and rwd.reward_id == "rwd-1"
    rep = ledger.status("rpt-1", 4)
    assert rep.verify() and rep.integrity_ok and rep.rewarded
    assert rep.amount_cents == 50000 and rep.verdict == "accepted"
    print("bug-bounty OK: submit, triage, reward, status, pins, audit")


if __name__ == "__main__":
    main()
