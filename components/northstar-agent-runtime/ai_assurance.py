"""AI assurance decision ledger: declare assurances, verify, derive posture.

Research motivation: AI assurance (NIST AI RMF Measure/Manage,
EU AI Act conformity assessment, ISO/IEC 42001 audits) reduces to one
bookkeeping shape: a named AI *system* carries declared *assurances*
-- independent assessments, third-party reviews, certifications,
self-attestations -- each with a host-reported finding, all pinned by
digest, from which a deterministic assurance posture is derived.
Getting the bookkeeping wrong (undeclared systems, forged findings,
raw evidence leaking into audit rows, silent digest drift) corrupts
the assurance story before any real audit runs.

This module is the *assurance-statement* half, deliberately distinct
from the sibling layers:

- ``assurance.py`` owns the GSN-style assurance *case* structure
  (declare claim -> book argument -> bind evidence -> derive
  structural support -> maintenance reviews);
- ``ai_safety.py`` owns the AI-safety *issue* lifecycle
  (assess hazard -> mitigate);
- ``safe_ai.py`` owns the safety-*assurance* ledger
  (assess dimension -> independent verification);
- ``trustworthy_ai.py`` owns trustworthy-AI assessments over the
  EU HLEG / NIST AI RMF / OECD / ISO framework vocabularies;
- this module owns the AI-assurance *statement* decision ledger:
  which assurances were declared over named AI systems, which
  findings were booked, and the derived assurance posture -- all as
  data, never evidence.

Public API:

- ``AIAssurance.assure(system_id, seq, assurance_kind=...,
  finding=..., assurance_digest="")`` -- book one declared AI
  assurance over a named AI system (minted ``asr-N``). First assure
  registers the system. Assurance kind from the pinned 8-term
  vocabulary; finding from the pinned 5-term vocabulary -- booked
  *as data*, never proof an assurance activity happened or that a
  system is safe. Raw assurance evidence never enters records:
  digest pins only.
- ``AIAssurance.verify(assurance_id, seq)`` -- pure read: re-derives
  the digest pin of an assurance record; verdict pinned
  ``verified`` / ``tampered`` as data (tamper reported, never
  raised). Seq shape-validated, never consumed, no audit row.
- ``AIAssurance.evaluate(system_id, seq)`` -- pure read: derived
  assurance posture as data for one system. Posture precedence:
  ``not-assured`` (any) -> ``inconclusive`` (any) ->
  ``conditionally-assured`` (any) -> ``unassessed`` (nothing booked
  or any ``not-assessed``) -> ``assured`` (all ``assured``).
  Integrity re-derived as data; digest-pinned with ``verify()``.
- ``AIAssurance.retire(system_id, seq, reason="manual")`` --
  terminal; the system id is retired forever and later assure calls
  refuse; reads still work; ids never recycled.
- ``ai_assurance_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``assured`` / ``retired`` / ``rejected``). Raw evidence
  never crosses the audit boundary: ids, pinned vocabulary values,
  and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``assurance_kind`` must be one of the pinned 8 assurance kinds.
- ``finding`` must be one of the pinned 5 findings.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* AI assurances and *host-reported*
  findings. A booked ``assured`` finding means the host reported an
  assurance -- the module inspected no system, ran no audit, and
  proves nothing about real-world safety or compliance.
- Digest pins prove record integrity, never assurance quality.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if assurance state must survive a restart.
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
AI_ASSURANCE_VERSION = "ai-assurance.v1"

#: Schema pin carried by records and audit events.
AI_ASSURANCE_SCHEMA = "northstar.ai-assurance.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ASSURED = "assured"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ASSURED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw evidence never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"evidence", "transcript", "weights", "model", "model_weights",
     "trace", "log", "payload", "content", "raw", "document",
     "attachment", "report_text", "notes", "justification",
     "analysis", "assessment_text", "audit_text", "certificate",
     "finding_text", "proof", "workpapers"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned assurance-kind vocabulary. Labels, not certifications.
ASSURANCE_INDEPENDENT_ASSESSMENT = "independent-assessment"
ASSURANCE_INTERNAL_AUDIT = "internal-audit"
ASSURANCE_THIRD_PARTY_REVIEW = "third-party-review"
ASSURANCE_CERTIFICATION = "certification"
ASSURANCE_CONFORMITY_ASSESSMENT = "conformity-assessment"
ASSURANCE_SELF_ATTESTATION = "self-attestation"
ASSURANCE_REGULATORY_APPROVAL = "regulatory-approval"
ASSURANCE_CONTINUOUS_MONITORING = "continuous-monitoring"
ASSURANCE_KINDS = (
    ASSURANCE_INDEPENDENT_ASSESSMENT,
    ASSURANCE_INTERNAL_AUDIT,
    ASSURANCE_THIRD_PARTY_REVIEW,
    ASSURANCE_CERTIFICATION,
    ASSURANCE_CONFORMITY_ASSESSMENT,
    ASSURANCE_SELF_ATTESTATION,
    ASSURANCE_REGULATORY_APPROVAL,
    ASSURANCE_CONTINUOUS_MONITORING,
)

#: Pinned finding vocabulary. Findings are host-reported data, never proof.
FINDING_ASSURED = "assured"
FINDING_CONDITIONALLY_ASSURED = "conditionally-assured"
FINDING_NOT_ASSURED = "not-assured"
FINDING_INCONCLUSIVE = "inconclusive"
FINDING_NOT_ASSESSED = "not-assessed"
FINDINGS = (FINDING_ASSURED, FINDING_CONDITIONALLY_ASSURED,
            FINDING_NOT_ASSURED, FINDING_INCONCLUSIVE,
            FINDING_NOT_ASSESSED)

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

class AIAssuranceError(Exception):
    """Base error for the ai-assurance module."""


class BadSystemError(AIAssuranceError):
    """Malformed system id."""


class UnknownSystemError(AIAssuranceError):
    """System id not assured."""


class RetiredSystemError(AIAssuranceError):
    """System id was retired; never recycled."""


class BadAssuranceKindError(AIAssuranceError):
    """Assurance kind outside the pinned vocabulary."""


class BadFindingError(AIAssuranceError):
    """Finding outside the pinned vocabulary."""


class BadDigestError(AIAssuranceError):
    """Malformed sha256 digest pin."""


class BadReasonError(AIAssuranceError):
    """Retire reason outside the pinned vocabulary."""


class UnknownAssuranceError(AIAssuranceError):
    """Assurance id not booked."""


class SeqOrderError(AIAssuranceError):
    """Seq not a strictly increasing int."""


class AuditKindError(AIAssuranceError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssuranceRecord:
    """One declared AI assurance over a named AI system."""
    assurance_id: str
    system_id: str
    assurance_kind: str
    finding: str
    assurance_digest: str
    seq: int
    digest: str
    schema: str = AI_ASSURANCE_SCHEMA
    version: str = AI_ASSURANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assurance_id": self.assurance_id,
            "system_id": self.system_id,
            "assurance_kind": self.assurance_kind,
            "finding": self.finding,
            "assurance_digest": self.assurance_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _assurance_digest(
            self.assurance_id, self.system_id, self.assurance_kind,
            self.finding, self.assurance_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one assurance record's integrity (data, not proof)."""
    assurance_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_ASSURANCE_SCHEMA
    version: str = AI_ASSURANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assurance_id": self.assurance_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.assurance_id, self.verdict)


@dataclass(frozen=True)
class EvaluationReport:
    """Pure read view of derived assurance posture (data, not proof)."""
    system_id: str
    posture: str  # "unassessed" | "not-assured" | "inconclusive"
                  # | "conditionally-assured" | "assured"
    assurance_count: int
    assured_count: int
    conditional_count: int
    not_assured_count: int
    inconclusive_count: int
    integrity_ok: bool
    assurance_ids: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = AI_ASSURANCE_SCHEMA
    version: str = AI_ASSURANCE_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "assurance_count": self.assurance_count,
            "assured_count": self.assured_count,
            "conditional_count": self.conditional_count,
            "not_assured_count": self.not_assured_count,
            "inconclusive_count": self.inconclusive_count,
            "integrity_ok": self.integrity_ok,
            "assurance_ids": list(self.assurance_ids),
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _evaluate_digest(
            self.system_id, self.posture, self.assurance_count,
            self.assured_count, self.conditional_count,
            self.not_assured_count, self.inconclusive_count,
            self.assurance_ids)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system id."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_ASSURANCE_SCHEMA
    version: str = AI_ASSURANCE_VERSION

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


def _assurance_digest(assurance_id: str, system_id: str,
                      assurance_kind: str, finding: str,
                      assurance_digest: str) -> str:
    return _pin({"assurance_id": assurance_id, "system_id": system_id,
                 "assurance_kind": assurance_kind, "finding": finding,
                 "assurance_digest": assurance_digest})


def _verify_digest(assurance_id: str, verdict: str) -> str:
    return _pin({"assurance_id": assurance_id, "verdict": verdict})


def _evaluate_digest(system_id: str, posture: str, assurance_count: int,
                     assured_count: int, conditional_count: int,
                     not_assured_count: int, inconclusive_count: int,
                     assurance_ids: Tuple[str, ...]) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "assurance_count": assurance_count,
                 "assured_count": assured_count,
                 "conditional_count": conditional_count,
                 "not_assured_count": not_assured_count,
                 "inconclusive_count": inconclusive_count,
                 "assurance_ids": sorted(assurance_ids)})


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


def ai_assurance_audit_event(kind: str, seq: int,
                             **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-assurance ledger."""
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
        "version": AI_ASSURANCE_VERSION,
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
# AIAssurance
# ---------------------------------------------------------------------------

class AIAssurance:
    """AI assurance statement decision ledger.

    Declares AI assurances over named AI systems, books host-reported
    findings, and derives assurance posture as data. Deterministic,
    in-memory, fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._assurances: Dict[str, AssuranceRecord] = {}
        self._assurances_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assurance_counter = 0
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
            ai_assurance_audit_event(kind, seq, **details))

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    def _posture(self, assurance_ids: Tuple[str, ...]) -> str:
        """Derive posture from booked findings (data, never proof)."""
        if not assurance_ids:
            return "unassessed"
        findings = [self._assurances[aid].finding for aid in assurance_ids]
        if FINDING_NOT_ASSURED in findings:
            return "not-assured"
        if FINDING_INCONCLUSIVE in findings:
            return "inconclusive"
        if FINDING_CONDITIONALLY_ASSURED in findings:
            return "conditionally-assured"
        if FINDING_NOT_ASSESSED in findings:
            return "unassessed"
        return "assured"

    def _integrity_ok(self, system_id: str) -> bool:
        for aid in self._assurances_for.get(system_id, ()):
            if not self._assurances[aid].verify():
                return False
        return True

    # -- public API ---------------------------------------------------------

    def assure(self, system_id: str, seq: int,
               assurance_kind: str = ASSURANCE_SELF_ATTESTATION,
               finding: str = FINDING_NOT_ASSESSED,
               assurance_digest: str = "") -> AssuranceRecord:
        """Book one declared AI assurance over a named AI system."""
        seq = self._claim(seq)
        try:
            _check_id(system_id, BadSystemError)
            if system_id in self._retired:
                raise RetiredSystemError(
                    f"system retired: {system_id!r}")
            if assurance_kind not in ASSURANCE_KINDS:
                raise BadAssuranceKindError(
                    f"bad assurance kind: {assurance_kind!r}")
            if finding not in FINDINGS:
                raise BadFindingError(f"bad finding: {finding!r}")
            _check_digest(assurance_digest)
            if system_id not in self._systems:
                self._systems[system_id] = None
                self._assurances_for[system_id] = ()
            self._assurance_counter += 1
            assurance_id = f"asr-{self._assurance_counter}"
            record = AssuranceRecord(
                assurance_id=assurance_id,
                system_id=system_id,
                assurance_kind=assurance_kind,
                finding=finding,
                assurance_digest=assurance_digest,
                seq=seq,
                digest=_assurance_digest(assurance_id, system_id,
                                         assurance_kind, finding,
                                         assurance_digest),
            )
        except AIAssuranceError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._assurances[assurance_id] = record
        self._assurances_for[system_id] = (
            self._assurances_for[system_id] + (assurance_id,))
        self._emit(KIND_ASSURED, seq, assurance_id=assurance_id,
                   system_id=system_id, assurance_kind=assurance_kind,
                   finding=finding)
        return record

    def verify(self, assurance_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one assurance record's digest pin."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(assurance_id, UnknownAssuranceError)
            try:
                record = self._assurances[assurance_id]
            except KeyError:
                raise UnknownAssuranceError(
                    f"unknown assurance: {assurance_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                assurance_id=assurance_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(assurance_id, verdict),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derived assurance posture for one system (data)."""
        _check_seq(seq)  # shape-validated, never consumed
        with self._lock:
            _check_id(system_id, BadSystemError)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            assurance_ids = self._assurances_for.get(system_id, ())
            findings = [self._assurances[aid].finding
                        for aid in assurance_ids]
            posture = self._posture(assurance_ids)
            assured = sum(1 for f in findings if f == FINDING_ASSURED)
            conditional = sum(
                1 for f in findings if f == FINDING_CONDITIONALLY_ASSURED)
            not_assured = sum(
                1 for f in findings if f == FINDING_NOT_ASSURED)
            inconclusive = sum(
                1 for f in findings if f == FINDING_INCONCLUSIVE)
            integrity = self._integrity_ok(system_id)
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                assurance_count=len(assurance_ids),
                assured_count=assured,
                conditional_count=conditional,
                not_assured_count=not_assured,
                inconclusive_count=inconclusive,
                integrity_ok=integrity,
                assurance_ids=assurance_ids,
                seq=seq,
                digest=_evaluate_digest(system_id, posture,
                                        len(assurance_ids), assured,
                                        conditional, not_assured,
                                        inconclusive, assurance_ids),
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
        except AIAssuranceError as exc:
            self._burn(seq)
            self._emit(KIND_REJECTED, seq,
                       rejected_kind=type(exc).__name__,
                       system_id=system_id)
            raise
        self._retired[system_id] = record
        self._emit(KIND_RETIRED, seq, system_id=system_id, reason=reason)
        return record

    # -- pure-read views -----------------------------------------------------

    def assurance_record(self, assurance_id: str,
                         seq: int) -> AssuranceRecord:
        """Pure read: fetch one assurance record (no audit row)."""
        _check_seq(seq)
        try:
            return self._assurances[assurance_id]
        except KeyError:
            raise UnknownAssuranceError(
                f"unknown assurance: {assurance_id!r}")

    def assurances_for(self, system_id: str,
                       seq: int) -> Tuple[str, ...]:
        """Pure read: assurance ids for one system (no audit row)."""
        _check_seq(seq)
        _check_id(system_id, BadSystemError)
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return self._assurances_for.get(system_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: assured system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._systems.keys())

    def assurance_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: booked assurance ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._assurances.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids (no audit row)."""
        _check_seq(seq)
        return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters (no audit row)."""
        _check_seq(seq)
        return {
            "systems": len(self._systems),
            "assurances": len(self._assurances),
            "retired": len(self._retired),
            "seq": self._last_seq,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the booked audit.ndjson/1 rows (no audit row)."""
        _check_seq(seq)
        return tuple(self._audit_events)


def main() -> None:
    """Self-check: exercise assure/verify/evaluate/retire paths."""
    a = AIAssurance()
    rec = a.assure("sys-1", 1, assurance_kind=ASSURANCE_CERTIFICATION,
                   finding=FINDING_ASSURED)
    assert rec.assurance_id == "asr-1" and rec.verify()
    vfy = a.verify("asr-1", 2)
    assert vfy.verdict == "verified" and vfy.verify()
    rep = a.evaluate("sys-1", 3)
    assert rep.posture == "assured" and rep.verify()
    ret = a.retire("sys-1", 4)
    assert ret.verify()
    assert stdlib_only()
    print("ai-assurance OK: assure, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
