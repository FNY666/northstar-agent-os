"""AI oversight decision ledger: declare oversight sessions, book verdicts.

Research motivation: AI oversight proposals (human-in-the-loop /
human-on-the-loop / human-in-command, automated screening, spot
checks, deep reviews) all reduce to one operational bookkeeping
shape: a named AI *system* receives declared *oversight sessions*
(declared kind, host-reported outcome), and a ledger derives an
oversight posture *as data*. This module books that shape.

This module is the *oversight* decision ledger, deliberately distinct
from the sibling layers:

- ``human_oversight.py`` owns the human assignment/review lifecycle
  (who reviews, which review records, review outcomes);
- ``process_supervision.py`` owns step-level supervision verdicts
  (OpenAI "Let's Verify Step by Step"-shaped step bookkeeping);
- ``outcome_supervision.py`` owns final-outcome supervision verdicts;
- ``scalable_oversight.py`` owns triage-protocol mechanics (risk tiers,
  auto-approve envelopes, escalation routing);
- ``scalable_oversight_v2.py`` owns the oversight-allocation ledger
  (supervisions booked against allocated oversight methods);
- ``ai_governance.py`` owns governance *controls* and *audit decisions*;
- this module owns the AI-*oversight* decision ledger: which oversight
  sessions were declared over named AI systems, what host-reported
  outcomes were booked, and the derived oversight posture -- all as
  data, never evidence.

Public API:

- ``AIOversight.oversee(system_id, seq, oversight_kind=...,
  outcome=..., oversight_digest="")`` -- book one declared oversight
  session over a named AI system (minted ``ovr-N``). First oversee
  registers the system. Oversight kind comes from the pinned 8-term
  vocabulary; outcome from the pinned 4-term vocabulary -- both booked
  *as data*, never proof oversight happened or worked. Raw oversight
  material never enters records: digest pins only.
- ``AIOversight.evaluate(system_id, seq)`` -- pure read: re-derive the
  ledger-rule oversight posture as data for one named system. Seq
  shape-validated, never consumed, no audit row.
- ``AIOversight.verify(oversight_id, seq)`` -- pure read: re-derive the
  digest pin of one oversight session; verdict pinned
  ``verified`` / ``tampered`` as data (tamper reported, never raised).
  Seq shape-validated, never consumed, no audit row.
- ``AIOversight.retire(system_id, seq, reason="manual")`` -- terminal;
  the system id is retired forever and later oversee calls refuse;
  reads still work; ids never recycled.
- ``AIOversight.report(seq, system_id="")`` -- pure read: derived
  oversight posture as data for one system or the whole ledger.
- ``ai_oversight_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``overseen`` / ``retired`` / ``rejected``). Raw oversight
  material never crosses the audit boundary: ids, pinned vocabulary
  values, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``oversight_kind`` must be one of the pinned 8 oversight kinds.
- ``outcome`` must be one of the pinned 4 outcomes.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* oversight sessions and *host-reported*
  outcomes. A booked ``adequate`` outcome means the host declared
  adequate oversight -- the module watched nothing, screened nothing,
  and proves nothing about real-world oversight coverage.
- Digest pins prove record integrity, never oversight effectiveness.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if oversight state must survive a restart.
"""

from __future__ import annotations

import ast
import hashlib
import re
import sys
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

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
AI_OVERSIGHT_VERSION = "ai-oversight.v1"

#: Schema pin carried by records and audit events.
AI_OVERSIGHT_SCHEMA = "northstar.ai-oversight.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_OVERSEEN = "overseen"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_OVERSEEN, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw oversight material).
_BANNED_DETAIL_KEYS = frozenset(
    {"evidence", "transcript", "weights", "model", "model_weights",
     "policy", "policy_text", "trace", "log", "payload", "content",
     "raw", "document", "attachment", "report_text", "notes",
     "observation", "recording", "screenshot", "telemetry"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned oversight-kind vocabulary. Labels, not certifications.
KIND_HUMAN_IN_THE_LOOP = "human-in-the-loop"
KIND_HUMAN_ON_THE_LOOP = "human-on-the-loop"
KIND_HUMAN_IN_COMMAND = "human-in-command"
KIND_AUTOMATED_SCREENING = "automated-screening"
KIND_SPOT_CHECK = "spot-check"
KIND_DEEP_REVIEW = "deep-review"
KIND_ESCALATED_REVIEW = "escalated-review"
KIND_CONTINUOUS_MONITORING = "continuous-monitoring"
OVERSIGHT_KINDS = (
    KIND_HUMAN_IN_THE_LOOP,
    KIND_HUMAN_ON_THE_LOOP,
    KIND_HUMAN_IN_COMMAND,
    KIND_AUTOMATED_SCREENING,
    KIND_SPOT_CHECK,
    KIND_DEEP_REVIEW,
    KIND_ESCALATED_REVIEW,
    KIND_CONTINUOUS_MONITORING,
)

#: Pinned outcome vocabulary. Outcomes are host-reported data, never proof.
OUTCOME_ADEQUATE = "adequate"
OUTCOME_INADEQUATE = "inadequate"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_NOT_ASSESSED = "not-assessed"
OUTCOMES = (OUTCOME_ADEQUATE, OUTCOME_INADEQUATE, OUTCOME_INCONCLUSIVE,
            OUTCOME_NOT_ASSESSED)

#: Pinned derived-posture vocabulary (ledger rule, as data).
POSTURE_UNWATCHED = "unwatched"
POSTURE_OVERSIGHT_LAPSED = "oversight-lapsed"
POSTURE_CONTESTED = "contested"
POSTURE_NOT_ASSESSED = "not-assessed"
POSTURE_ADEQUATE = "adequate"
POSTURES = (POSTURE_UNWATCHED, POSTURE_OVERSIGHT_LAPSED,
            POSTURE_CONTESTED, POSTURE_NOT_ASSESSED, POSTURE_ADEQUATE)

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

class AIOversightError(Exception):
    """Base error for the ai-oversight module."""


class BadSystemError(AIOversightError):
    """Malformed system id."""


class UnknownSystemError(AIOversightError):
    """System id not under oversight."""


class RetiredSystemError(AIOversightError):
    """System id was retired; never recycled."""


class BadOversightKindError(AIOversightError):
    """Oversight kind outside the pinned vocabulary."""


class BadOutcomeError(AIOversightError):
    """Outcome outside the pinned vocabulary."""


class BadDigestError(AIOversightError):
    """Malformed sha256 digest pin."""


class BadReasonError(AIOversightError):
    """Retire reason outside the pinned vocabulary."""


class UnknownOversightError(AIOversightError):
    """Oversight session id not booked."""


class SeqOrderError(AIOversightError):
    """Seq not a strictly increasing int."""


class AuditKindError(AIOversightError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OversightRecord:
    """One declared oversight session over a named AI system."""
    oversight_id: str
    system_id: str
    oversight_kind: str
    outcome: str
    oversight_digest: str
    seq: int
    digest: str
    schema: str = AI_OVERSIGHT_SCHEMA
    version: str = AI_OVERSIGHT_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "oversight_id": self.oversight_id,
            "system_id": self.system_id,
            "oversight_kind": self.oversight_kind,
            "outcome": self.outcome,
            "oversight_digest": self.oversight_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _oversight_digest(
            self.oversight_id, self.system_id, self.oversight_kind,
            self.outcome, self.oversight_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one oversight session's integrity (data, not proof)."""
    oversight_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_OVERSIGHT_SCHEMA
    version: str = AI_OVERSIGHT_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "oversight_id": self.oversight_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.oversight_id, self.verdict)


@dataclass(frozen=True)
class OversightPostureReport:
    """Pure read view of derived oversight posture (data, not findings)."""
    system_id: str  # "" for whole-ledger scope
    posture: str  # "unwatched" | "oversight-lapsed" | "contested"
                  # | "not-assessed" | "adequate"
    oversight_count: int
    adequate_count: int
    inadequate_count: int
    inconclusive_count: int
    not_assessed_count: int
    integrity_ok: bool
    oversight_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = AI_OVERSIGHT_SCHEMA
    version: str = AI_OVERSIGHT_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "oversight_count": self.oversight_count,
            "adequate_count": self.adequate_count,
            "inadequate_count": self.inadequate_count,
            "inconclusive_count": self.inconclusive_count,
            "not_assessed_count": self.not_assessed_count,
            "integrity_ok": self.integrity_ok,
            "oversight_ids": list(self.oversight_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _report_digest(
            self.system_id, self.posture, self.oversight_count,
            self.adequate_count, self.inadequate_count,
            self.inconclusive_count, self.not_assessed_count,
            self.oversight_ids)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_OVERSIGHT_SCHEMA
    version: str = AI_OVERSIGHT_VERSION

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


def _oversight_digest(oversight_id: str, system_id: str,
                      oversight_kind: str, outcome: str,
                      oversight_digest: str) -> str:
    return _pin({"oversight_id": oversight_id, "system_id": system_id,
                 "oversight_kind": oversight_kind, "outcome": outcome,
                 "oversight_digest": oversight_digest})


def _verify_digest(oversight_id: str, verdict: str) -> str:
    return _pin({"oversight_id": oversight_id, "verdict": verdict})


def _retire_digest(system_id: str, reason: str) -> str:
    return _pin({"system_id": system_id, "reason": reason})


def _report_digest(system_id: str, posture: str, oversight_count: int,
                   adequate_count: int, inadequate_count: int,
                   inconclusive_count: int, not_assessed_count: int,
                   oversight_ids: Tuple[str, ...]) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "oversight_count": oversight_count,
                 "adequate_count": adequate_count,
                 "inadequate_count": inadequate_count,
                 "inconclusive_count": inconclusive_count,
                 "not_assessed_count": not_assessed_count,
                 "oversight_ids": list(oversight_ids)})


# ---------------------------------------------------------------------------
# Input checks
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


def ai_oversight_audit_event(kind: str, seq: int,
                             **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-oversight ledger."""
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
        "version": AI_OVERSIGHT_VERSION,
        "detail": dict(details),
    }


def stdlib_only() -> bool:
    """AST self-check: this module imports stdlib modules only."""
    allowed = set(getattr(sys, "stdlib_module_names", ()))
    allowed |= {"canonical_json"}  # the single sanctioned canonicalizer
    # Read own source from the defining file for accuracy.
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
# AIOversight
# ---------------------------------------------------------------------------

class AIOversight:
    """AI oversight decision ledger.

    Declares oversight sessions over named AI systems, books declared
    host-reported outcomes, and derives oversight posture as data.
    Deterministic, in-memory, fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._sessions: Dict[str, OversightRecord] = {}
        self._sessions_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._session_counter = 0
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
            ai_oversight_audit_event(kind, seq, **details))

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    def _posture(self, oversight_ids: Tuple[str, ...]) -> str:
        """Ledger rule: derive posture as data (never a finding)."""
        outcomes = [self._sessions[oid].outcome for oid in oversight_ids]
        if not outcomes:
            return POSTURE_UNWATCHED
        if OUTCOME_INADEQUATE in outcomes:
            return POSTURE_OVERSIGHT_LAPSED
        if OUTCOME_INCONCLUSIVE in outcomes:
            return POSTURE_CONTESTED
        if OUTCOME_NOT_ASSESSED in outcomes:
            return POSTURE_NOT_ASSESSED
        return POSTURE_ADEQUATE

    def _integrity_ok(self, system_id: str) -> bool:
        """Re-derive all in-scope digest pins as data."""
        for oid in self._sessions_for.get(system_id, ()):
            if not self._sessions[oid].verify():
                return False
        return True

    # -- mutations ---------------------------------------------------------

    def oversee(self, system_id: str, seq: int,
                oversight_kind: str = KIND_HUMAN_IN_THE_LOOP,
                outcome: str = OUTCOME_NOT_ASSESSED,
                oversight_digest: str = "") -> OversightRecord:
        """Book one declared oversight session over a named AI system."""
        with self._lock:
            seq = self._claim(seq)
            try:
                _check_id(system_id, BadSystemError)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system retired: {system_id!r}")
                if oversight_kind not in OVERSIGHT_KINDS:
                    raise BadOversightKindError(
                        f"bad oversight kind: {oversight_kind!r}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                _check_digest(oversight_digest)
                if system_id not in self._systems:
                    self._systems[system_id] = None
                    self._sessions_for[system_id] = ()
                self._session_counter += 1
                oversight_id = f"ovr-{self._session_counter}"
                record = OversightRecord(
                    oversight_id=oversight_id,
                    system_id=system_id,
                    oversight_kind=oversight_kind,
                    outcome=outcome,
                    oversight_digest=oversight_digest,
                    seq=seq,
                    digest=_oversight_digest(
                        oversight_id, system_id, oversight_kind,
                        outcome, oversight_digest),
                )
            except AIOversightError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            self._sessions[oversight_id] = record
            self._sessions_for[system_id] = (
                self._sessions_for[system_id] + (oversight_id,))
            self._emit(KIND_OVERSEEN, seq, oversight_id=oversight_id,
                       system_id=system_id, oversight_kind=oversight_kind,
                       outcome=outcome)
            return record

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system id."""
        with self._lock:
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
            except AIOversightError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            self._retired[system_id] = record
            self._emit(KIND_RETIRED, seq, system_id=system_id,
                       reason=reason)
            return record

    # -- pure reads ----------------------------------------------------------

    def verify(self, oversight_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one oversight session's digest pin."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(oversight_id, UnknownOversightError)
            try:
                record = self._sessions[oversight_id]
            except KeyError:
                raise UnknownOversightError(
                    f"unknown oversight: {oversight_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                oversight_id=oversight_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(oversight_id, verdict),
            )

    def evaluate(self, system_id: str, seq: int) -> OversightPostureReport:
        """Pure read: derived oversight posture for one system (data)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._scoped_report(seq, system_id)

    def report(self, seq: int,
               system_id: str = "") -> OversightPostureReport:
        """Pure read: derived oversight posture (data, never findings)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            if system_id:
                _check_id(system_id, BadSystemError)
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                return self._scoped_report(seq, system_id)
            # whole-ledger scope
            oversight_ids = tuple(self._sessions.keys())
            outcomes = [self._sessions[oid].outcome
                        for oid in oversight_ids]
            integrity = all(
                self._integrity_ok(sid) for sid in self._systems)
            posture = self._posture(oversight_ids)
            return OversightPostureReport(
                system_id="",
                posture=posture,
                oversight_count=len(oversight_ids),
                adequate_count=sum(1 for o in outcomes
                                   if o == OUTCOME_ADEQUATE),
                inadequate_count=sum(1 for o in outcomes
                                     if o == OUTCOME_INADEQUATE),
                inconclusive_count=sum(1 for o in outcomes
                                       if o == OUTCOME_INCONCLUSIVE),
                not_assessed_count=sum(1 for o in outcomes
                                       if o == OUTCOME_NOT_ASSESSED),
                integrity_ok=integrity,
                oversight_ids=oversight_ids,
                seq=seq,
                digest=_report_digest(
                    "", posture, len(oversight_ids),
                    sum(1 for o in outcomes if o == OUTCOME_ADEQUATE),
                    sum(1 for o in outcomes if o == OUTCOME_INADEQUATE),
                    sum(1 for o in outcomes if o == OUTCOME_INCONCLUSIVE),
                    sum(1 for o in outcomes
                        if o == OUTCOME_NOT_ASSESSED),
                    oversight_ids),
            )

    def _scoped_report(self, seq: int,
                       system_id: str) -> OversightPostureReport:
        oversight_ids = self._sessions_for.get(system_id, ())
        outcomes = [self._sessions[oid].outcome for oid in oversight_ids]
        posture = self._posture(oversight_ids)
        adequate = sum(1 for o in outcomes if o == OUTCOME_ADEQUATE)
        inadequate = sum(1 for o in outcomes if o == OUTCOME_INADEQUATE)
        inconclusive = sum(1 for o in outcomes
                           if o == OUTCOME_INCONCLUSIVE)
        not_assessed = sum(1 for o in outcomes
                           if o == OUTCOME_NOT_ASSESSED)
        return OversightPostureReport(
            system_id=system_id,
            posture=posture,
            oversight_count=len(oversight_ids),
            adequate_count=adequate,
            inadequate_count=inadequate,
            inconclusive_count=inconclusive,
            not_assessed_count=not_assessed,
            integrity_ok=self._integrity_ok(system_id),
            oversight_ids=oversight_ids,
            seq=seq,
            digest=_report_digest(system_id, posture, len(oversight_ids),
                                  adequate, inadequate, inconclusive,
                                  not_assessed, oversight_ids),
        )

    # -- views ---------------------------------------------------------------

    def oversight_record(self, oversight_id: str,
                         seq: int) -> OversightRecord:
        """Pure read: fetch one booked oversight session."""
        _check_seq(seq)
        with self._lock:
            _check_id(oversight_id, UnknownOversightError)
            try:
                return self._sessions[oversight_id]
            except KeyError:
                raise UnknownOversightError(
                    f"unknown oversight: {oversight_id!r}")

    def sessions_for(self, system_id: str,
                     seq: int) -> Tuple[str, ...]:
        """Pure read: oversight session ids for one system."""
        _check_seq(seq)
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._sessions_for.get(system_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all registered system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._systems.keys())

    def oversight_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all booked oversight session ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._sessions.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: all retired system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the audit event stream."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._audit_events)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger tallies."""
        _check_seq(seq)
        with self._lock:
            return {
                "systems": len(self._systems),
                "sessions": len(self._sessions),
                "retired": len(self._retired),
                "audit_events": len(self._audit_events),
                "seq": self._last_seq,
            }


def main() -> None:
    """Self-check: exercise oversee/evaluate/verify/retire/report paths."""
    o = AIOversight()
    sess = o.oversee("sys-1", 1, oversight_kind=KIND_HUMAN_IN_COMMAND,
                     outcome=OUTCOME_ADEQUATE)
    assert sess.oversight_id == "ovr-1" and sess.verify()
    evl = o.evaluate("sys-1", 2)
    assert evl.posture == POSTURE_ADEQUATE and evl.verify()
    rep = o.report(3, "sys-1")
    assert rep.posture == POSTURE_ADEQUATE and rep.verify()
    vfy = o.verify("ovr-1", 4)
    assert vfy.verdict == "verified" and vfy.verify()
    ret = o.retire("sys-1", 5)
    assert ret.verify()
    assert stdlib_only()
    print("ai-oversight OK: oversee, evaluate, verify, report, retire, pins, audit")


if __name__ == "__main__":
    main()
