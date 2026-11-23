"""AI recourse decision ledger: declare recourse, verify, derive posture.

Research motivation: AI recourse -- giving affected individuals a path
to contest, correct, or reverse adverse AI decisions (EU AI Act
Article 85 right to explanation/complaint, GDPR Article 22 safeguards,
counterfactual-recourse literature) -- reduces to one bookkeeping
shape: a named AI *system* carries declared *recourse provisions* --
appeals, corrections, human reviews, rollbacks, counterfactual
guidance, compensation -- each with a host-reported outcome, all
pinned by digest, from which a deterministic recourse posture is
derived. Getting the bookkeeping wrong (unregistered systems, forged
outcomes, raw case material leaking into audit rows, silent digest
drift) corrupts the recourse story before any real remedy runs.

This module is the AI-*recourse* decision ledger, deliberately
distinct from the sibling layers:

- ``ai_oversight.py`` owns oversight *sessions* (human-in-the-loop
  coverage and outcome adequacy);
- ``ai_safety.py`` owns the AI-safety *issue* lifecycle
  (assess hazard -> mitigate);
- ``ai_audit.py`` owns *audit execution* bookkeeping (declared audit
  engagements and findings);
- ``ai_assurance.py`` owns assurance *statements* (third-party /
  self-attested findings);
- ``ai_policy.py`` owns per-system policy declarations and
  enforcements;
- ``appeals.py`` (if present) owns the mechanical appeal workflow
  (filings, deadlines, routing) -- this module owns none of that.
  This module owns the *recourse-provision* ledger: which recourse
  kinds were declared over named AI systems, which outcomes were
  booked, and the derived recourse posture -- all as data, never
  evidence.

Public API:

- ``AIRecourse.provide(system_id, seq, recourse_kind=...,
  outcome=..., recourse_digest="")`` -- book one declared AI
  recourse provision over a named AI system (minted ``rcs-N``).
  First provide registers the system. Recourse kind from the pinned
  8-term vocabulary; outcome from the pinned 4-term vocabulary --
  booked *as data*, never proof that recourse was actually honored.
  Raw case material never enters records: digest pins only.
- ``AIRecourse.verify(recourse_id, seq)`` -- pure read: re-derives
  the digest pin of a recourse record; verdict pinned ``verified`` /
  ``tampered`` as data (tamper reported, never raised). Seq
  shape-validated, never consumed, no audit row.
- ``AIRecourse.evaluate(system_id, seq)`` -- pure read: derived
  recourse posture as data for one system. Posture precedence:
  ``unaddressed`` (nothing booked) -> ``denied-open`` (any denied)
  -> ``pending-open`` (any pending) -> ``unrequested`` (any
  not-requested, none pending/denied) -> ``resolved`` (all resolved).
  Integrity re-derived as data; digest-pinned with ``verify()``.
- ``AIRecourse.retire(system_id, seq, reason="manual")`` --
  terminal; the system id is retired forever and later provide calls
  refuse; reads still work; ids never recycled.
- ``ai_recourse_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``provided`` / ``retired`` / ``rejected``). Raw case
  material never crosses the audit boundary: ids, pinned vocabulary
  values, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``recourse_kind`` must be one of the pinned 8 recourse kinds.
- ``outcome`` must be one of the pinned 4 outcomes.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* AI recourse provisions and
  *host-reported* outcomes. A booked ``resolved`` outcome means the
  host reported resolution -- the module contested no decision, paid
  no compensation, and proves nothing about real-world remedy.
- Digest pins prove record integrity, never recourse quality.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if recourse state must survive a restart.
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
import threading
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AI_RECOURSE_VERSION = "ai-recourse.v1"

#: Schema pin carried by records and audit events.
AI_RECOURSE_SCHEMA = "northstar.ai-recourse.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_PROVIDED = "provided"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_PROVIDED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw case material never crosses).
_BANNED_DETAIL_KEYS = frozenset(
    {"evidence", "transcript", "case_file", "case_material", "personal_data",
     "pii", "complaint_text", "appeal_text", "justification", "notes",
     "document", "attachment", "payload", "content", "raw", "trace", "log",
     "report_text", "analysis", "weights", "model", "decision_text"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned recourse-kind vocabulary. Labels for provision kinds, not procedures.
RECOURSE_APPEAL = "appeal"
RECOURSE_CORRECTION = "correction"
RECOURSE_COUNTERFACTUAL = "counterfactual"
RECOURSE_HUMAN_REVIEW = "human-review"
RECOURSE_ROLLBACK = "rollback"
RECOURSE_COMPENSATION = "compensation"
RECOURSE_DELETION = "deletion"
RECOURSE_EXPLANATION = "explanation"
RECOURSE_KINDS = (
    RECOURSE_APPEAL,
    RECOURSE_CORRECTION,
    RECOURSE_COUNTERFACTUAL,
    RECOURSE_HUMAN_REVIEW,
    RECOURSE_ROLLBACK,
    RECOURSE_COMPENSATION,
    RECOURSE_DELETION,
    RECOURSE_EXPLANATION,
)

#: Pinned outcome vocabulary. Outcomes are host-reported data, never proof.
OUTCOME_RESOLVED = "resolved"
OUTCOME_PENDING = "pending"
OUTCOME_DENIED = "denied"
OUTCOME_NOT_REQUESTED = "not-requested"
OUTCOMES = (OUTCOME_RESOLVED, OUTCOME_PENDING,
            OUTCOME_DENIED, OUTCOME_NOT_REQUESTED)

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_DECOMMISSIONED = "decommissioned"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED,
                  REASON_DECOMMISSIONED)

#: Regex for a well-formed sha256 digest pin.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AIRecourseError(Exception):
    """Base error for the ai-recourse module."""


class BadSystemError(AIRecourseError):
    """Malformed system id."""


class UnknownSystemError(AIRecourseError):
    """System id has no booked recourse."""


class RetiredSystemError(AIRecourseError):
    """System id was retired; never recycled."""


class BadRecourseKindError(AIRecourseError):
    """Recourse kind outside the pinned vocabulary."""


class BadOutcomeError(AIRecourseError):
    """Outcome outside the pinned vocabulary."""


class BadDigestError(AIRecourseError):
    """Malformed sha256 digest pin."""


class BadReasonError(AIRecourseError):
    """Retire reason outside the pinned vocabulary."""


class UnknownRecourseError(AIRecourseError):
    """Recourse id not booked."""


class SeqOrderError(AIRecourseError):
    """Seq not a strictly increasing int."""


class AuditKindError(AIRecourseError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RecourseRecord:
    """One declared AI recourse provision over a named AI system."""
    recourse_id: str
    system_id: str
    recourse_kind: str
    outcome: str
    recourse_digest: str
    seq: int
    digest: str
    schema: str = AI_RECOURSE_SCHEMA
    version: str = AI_RECOURSE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "recourse_id": self.recourse_id,
            "system_id": self.system_id,
            "recourse_kind": self.recourse_kind,
            "outcome": self.outcome,
            "recourse_digest": self.recourse_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _recourse_digest(
            self.recourse_id, self.system_id, self.recourse_kind,
            self.outcome, self.recourse_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one recourse record's integrity (data, not proof)."""
    recourse_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_RECOURSE_SCHEMA
    version: str = AI_RECOURSE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "recourse_id": self.recourse_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.recourse_id, self.verdict)


@dataclass(frozen=True)
class EvaluationReport:
    """Pure read view of derived recourse posture (data, not proof)."""
    system_id: str
    posture: str  # "unaddressed" | "denied-open" | "pending-open"
                  # | "unrequested" | "resolved"
    recourse_count: int
    resolved_count: int
    pending_count: int
    denied_count: int
    not_requested_count: int
    integrity_ok: bool
    recourse_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = AI_RECOURSE_SCHEMA
    version: str = AI_RECOURSE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "recourse_count": self.recourse_count,
            "resolved_count": self.resolved_count,
            "pending_count": self.pending_count,
            "denied_count": self.denied_count,
            "not_requested_count": self.not_requested_count,
            "integrity_ok": self.integrity_ok,
            "recourse_ids": list(self.recourse_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _evaluate_digest(
            self.system_id, self.posture, self.recourse_count,
            self.resolved_count, self.pending_count, self.denied_count,
            self.not_requested_count, self.recourse_ids)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_RECOURSE_SCHEMA
    version: str = AI_RECOURSE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _retire_digest(self.system_id, self.reason)


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------

def _pin(value: Any) -> str:
    return "sha256:" + jcs_sha256_hex(value)


def _recourse_digest(recourse_id: str, system_id: str,
                     recourse_kind: str, outcome: str,
                     recourse_digest: str) -> str:
    return _pin({"recourse_id": recourse_id, "system_id": system_id,
                 "recourse_kind": recourse_kind, "outcome": outcome,
                 "recourse_digest": recourse_digest})


def _verify_digest(recourse_id: str, verdict: str) -> str:
    return _pin({"recourse_id": recourse_id, "verdict": verdict})


def _evaluate_digest(system_id: str, posture: str, recourse_count: int,
                     resolved_count: int, pending_count: int,
                     denied_count: int, not_requested_count: int,
                     recourse_ids: Tuple[str, ...]) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "recourse_count": recourse_count,
                 "resolved_count": resolved_count,
                 "pending_count": pending_count,
                 "denied_count": denied_count,
                 "not_requested_count": not_requested_count,
                 "recourse_ids": sorted(recourse_ids)})


def _retire_digest(system_id: str, reason: str) -> str:
    return _pin({"system_id": system_id, "reason": reason})


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any, err: type) -> str:
    if not isinstance(value, str) or not value:
        raise err(f"bad id: {value!r}")
    if len(value) > _MAX_ID_LEN or any(c.isspace() for c in value):
        raise err(f"bad id: {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"bad seq: {seq!r}")
    if seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_digest(value: Any) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"bad digest pin: {value!r}")
    if value != "" and not _DIGEST_RE.match(value):
        raise BadDigestError(f"bad digest pin: {value!r}")
    return value


def ai_recourse_audit_event(kind: str, seq: int,
                            **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-recourse ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    _check_seq(seq)
    for key in details:
        if key in _BANNED_DETAIL_KEYS:
            raise AuditKindError(f"audit detail key banned: {key!r}")
    return {
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
        "version": AI_RECOURSE_VERSION,
        "detail": dict(details),
    }


def stdlib_only() -> bool:
    """AST self-check: this module imports stdlib modules only."""
    allowed = set(getattr(sys, "stdlib_module_names", ()))
    allowed |= {"canonical_json"}  # the single sanctioned canonicalizer
    path = globals().get("__file__", "")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except OSError:
        return True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


# ---------------------------------------------------------------------------
# AIRecourse
# ---------------------------------------------------------------------------

class AIRecourse:
    """AI recourse provision decision ledger.

    Declares AI recourse provisions over named AI systems, books
    host-reported outcomes, and derives recourse posture as data.
    Deterministic, in-memory, fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._recourses: Dict[str, RecourseRecord] = {}
        self._recourses_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._recourse_counter = 0
        self._last_seq = -1
        self._audit_events: list = []

    # -- internals ---------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq not increasing: {seq!r}")
        self._last_seq = seq
        return seq

    def _burn(self, seq: int) -> None:
        """Claim the seq even for a failed mutation (claim-then-burn)."""
        self._last_seq = max(self._last_seq, seq)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit_events.append(
            ai_recourse_audit_event(kind, seq, **details))

    def _posture(self, recourse_ids: Tuple[str, ...]) -> str:
        """Derive posture from booked outcomes (data, never proof)."""
        if not recourse_ids:
            return "unaddressed"
        outcomes = [self._recourses[rid].outcome for rid in recourse_ids]
        if OUTCOME_DENIED in outcomes:
            return "denied-open"
        if OUTCOME_PENDING in outcomes:
            return "pending-open"
        if OUTCOME_NOT_REQUESTED in outcomes:
            return "unrequested"
        return "resolved"

    def _integrity_ok(self, system_id: str) -> bool:
        for rid in self._recourses_for.get(system_id, ()):
            if not self._recourses[rid].verify():
                return False
        return True

    # -- public API ---------------------------------------------------------

    def provide(self, system_id: str, seq: int,
                recourse_kind: str = RECOURSE_EXPLANATION,
                outcome: str = OUTCOME_NOT_REQUESTED,
                recourse_digest: str = "") -> RecourseRecord:
        """Book one declared AI recourse provision over a named AI system."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            if system_id in self._retired:
                raise RetiredSystemError(
                    f"system retired: {system_id!r}")
            if recourse_kind not in RECOURSE_KINDS:
                raise BadRecourseKindError(
                    f"bad recourse kind: {recourse_kind!r}")
            if outcome not in OUTCOMES:
                raise BadOutcomeError(f"bad outcome: {outcome!r}")
            _check_digest(recourse_digest)
            if system_id not in self._systems:
                self._systems[system_id] = None
                self._recourses_for[system_id] = ()
            self._recourse_counter += 1
            recourse_id = f"rcs-{self._recourse_counter}"
            record = RecourseRecord(
                recourse_id=recourse_id,
                system_id=system_id,
                recourse_kind=recourse_kind,
                outcome=outcome,
                recourse_digest=recourse_digest,
                seq=seq,
                digest=_recourse_digest(recourse_id, system_id,
                                        recourse_kind, outcome,
                                        recourse_digest),
            )
        except AIRecourseError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._recourses[recourse_id] = record
        self._recourses_for[system_id] = (
            self._recourses_for[system_id] + (recourse_id,))
        self._emit(KIND_PROVIDED, seq, recourse_id=recourse_id,
                   system_id=system_id, recourse_kind=recourse_kind,
                   outcome=outcome)
        return record

    def verify(self, recourse_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one recourse record's digest pin."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(recourse_id, UnknownRecourseError)
            try:
                record = self._recourses[recourse_id]
            except KeyError:
                raise UnknownRecourseError(
                    f"unknown recourse: {recourse_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                recourse_id=recourse_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(recourse_id, verdict),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derived recourse posture for one system (data)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            recourse_ids = self._recourses_for.get(system_id, ())
            outcomes = [self._recourses[rid].outcome
                        for rid in recourse_ids]
            posture = self._posture(recourse_ids)
            resolved = sum(1 for o in outcomes if o == OUTCOME_RESOLVED)
            pending = sum(1 for o in outcomes if o == OUTCOME_PENDING)
            denied = sum(1 for o in outcomes if o == OUTCOME_DENIED)
            not_requested = sum(
                1 for o in outcomes if o == OUTCOME_NOT_REQUESTED)
            integrity = self._integrity_ok(system_id)
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                recourse_count=len(recourse_ids),
                resolved_count=resolved,
                pending_count=pending,
                denied_count=denied,
                not_requested_count=not_requested,
                integrity_ok=integrity,
                recourse_ids=recourse_ids,
                seq=seq,
                digest=_evaluate_digest(system_id, posture,
                                        len(recourse_ids), resolved,
                                        pending, denied,
                                        not_requested, recourse_ids),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system id."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            if system_id in self._retired:
                raise RetiredSystemError(
                    f"system retired: {system_id!r}")
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            if reason not in RETIRE_REASONS:
                raise BadReasonError(f"bad reason: {reason!r}")
            record = RetireRecord(
                system_id=system_id,
                reason=reason,
                seq=seq,
                digest=_retire_digest(system_id, reason),
            )
        except AIRecourseError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._retired[system_id] = record
        self._emit(KIND_RETIRED, seq, system_id=system_id, reason=reason)
        return record

    # -- pure-read views -----------------------------------------------------

    def recourse_record(self, recourse_id: str,
                        seq: int) -> RecourseRecord:
        """Pure read: fetch one recourse record (no audit row)."""
        _check_seq(seq)
        try:
            return self._recourses[recourse_id]
        except KeyError:
            raise UnknownRecourseError(
                f"unknown recourse: {recourse_id!r}")

    def recourses_for(self, system_id: str,
                      seq: int) -> Tuple[str, ...]:
        """Pure read: recourse ids for one system (no audit row)."""
        _check_seq(seq)
        _check_id(system_id, BadSystemError)
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return self._recourses_for.get(system_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: provisioned system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._systems.keys())

    def recourse_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: booked recourse ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._recourses.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters (no audit row)."""
        _check_seq(seq)
        return {
            "systems": len(self._systems),
            "recourses": len(self._recourses),
            "retired": len(self._retired),
            "seq": self._last_seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the booked audit.ndjson/1 rows (no audit row)."""
        _check_seq(seq)
        return tuple(self._audit_events)


def main() -> None:
    """Self-check: exercise provide/verify/evaluate/retire paths."""
    r = AIRecourse()
    rec = r.provide("sys-1", 1, recourse_kind=RECOURSE_APPEAL,
                    outcome=OUTCOME_RESOLVED)
    assert rec.recourse_id == "rcs-1" and rec.verify()
    vfy = r.verify("rcs-1", 2)
    assert vfy.verdict == "verified" and vfy.verify()
    rep = r.evaluate("sys-1", 3)
    assert rep.posture == "resolved" and rep.verify()
    ret = r.retire("sys-1", 4)
    assert ret.verify()
    assert stdlib_only()
    print("ai-recourse OK: provide, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
