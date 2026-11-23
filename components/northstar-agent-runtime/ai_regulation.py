"""AI regulation compliance decision ledger: declare assessments, book enforcement.

Research motivation: every AI regulatory regime (EU AI Act, NIST AI RMF,
UK AI Safety Institute evaluations, China's generative-AI measures,
Canada's AIDA, Brazil's AI bill, ISO/IEC 42001, OECD AI Principles)
reduces to the same operational bookkeeping shape: a named AI *system*
is assessed against a *regulation* with a declared *risk tier*, and a
regulator declares *enforcement actions* against it. This module books
that shape as data.

This module is the *regulation* layer, deliberately distinct from the
sibling layers:

- ``ai_governance.py`` owns governance *operations* (controls, audits);
- ``governance.py`` owns framework *policy* lifecycle;
- ``compliance.py`` (where present) owns generic compliance attestation;
- this module owns the AI-*regulation* decision ledger: which
  regulation was declared applicable to which system, at which declared
  risk tier, and which enforcement actions were booked against it --
  all as data, never evidence.

Public API:

- ``AIRegulation.assess(system_id, seq, regulation=..., risk_tier=...,
  assessment_digest="")`` -- book one declared regulatory assessment
  (minted ``asm-N``). First assess registers the system. Regulation
  from the pinned 8-term vocabulary; risk tier from the pinned 4-term
  vocabulary -- booked *as data*, never proof a regime applies or a
  tier is correct. Raw assessment material never enters records:
  digest pins only.
- ``AIRegulation.enforce(system_id, seq, action=...,
  enforcement_digest="")`` -- book one declared enforcement action
  (minted ``enf-N``). Action from the pinned 8-term vocabulary --
  booked *as data*, never proof of a real regulator order.
  Fail-closed on unknown or retired systems.
- ``AIRegulation.verify(record_id, seq)`` -- pure read: re-derives
  the digest pin of an assessment or enforcement record; verdict
  pinned ``verified`` / ``tampered`` as data (tamper reported, never
  raised). Seq shape-validated, never consumed, no audit row.
- ``AIRegulation.report(seq, system_id="")`` -- pure read: derived
  regulatory posture as data for one system or the whole ledger.
- ``AIRegulation.retire(system_id, seq, reason="manual")`` --
  terminal; the system id is retired forever and later assess/enforce
  calls refuse; reads still work; ids never recycled.
- ``ai_regulation_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``assessed`` / ``enforced`` / ``retired`` / ``rejected``).
  Raw regulatory material never crosses the audit boundary: ids,
  pinned vocabulary values, and counts only.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` must be a non-empty str, <= 256 chars, no whitespace.
- ``regulation`` must be one of the pinned 8 regulations.
- ``risk_tier`` must be one of the pinned 4 risk tiers.
- ``action`` must be one of the pinned 8 enforcement actions.
- digests must be ``sha256:<64hex>`` when supplied.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* regulatory assessments and
  *host-reported* enforcement actions. A booked ``high-risk`` tier or
  ``fine`` action means the host declared it -- the module inspected
  no regulator filing, ran no compliance check, and proves nothing
  about real-world regulatory exposure.
- Digest pins prove record integrity, never regulatory compliance.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if regulation state must survive a restart.
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
AI_REGULATION_VERSION = "ai-regulation.v1"

#: Schema pin carried by records and audit events.
AI_REGULATION_SCHEMA = "northstar.ai-regulation.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ASSESSED = "assessed"
KIND_ENFORCED = "enforced"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ASSESSED, KIND_ENFORCED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw material never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"assessment", "filing", "evidence", "transcript", "order", "order_text",
     "notice", "dossier", "weights", "model", "trace", "log", "payload",
     "content", "raw", "document", "attachment", "report_text", "notes",
     "correspondence", "settlement"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned regulation vocabulary. Labels, not legal advice.
REG_EU_AI_ACT = "eu-ai-act"
REG_NIST_AI_RMF = "nist-ai-rmf"
REG_UK_AI_SAFETY = "uk-ai-safety"
REG_CHINA_GENAI = "china-genai-reg"
REG_CANADA_AIDA = "canada-aida"
REG_BRAZIL_AI_BILL = "brazil-ai-bill"
REG_ISO_42001 = "iso-42001"
REG_OECD_AI_PRINCIPLES = "oecd-ai-principles"
REGULATIONS = (
    REG_EU_AI_ACT,
    REG_NIST_AI_RMF,
    REG_UK_AI_SAFETY,
    REG_CHINA_GENAI,
    REG_CANADA_AIDA,
    REG_BRAZIL_AI_BILL,
    REG_ISO_42001,
    REG_OECD_AI_PRINCIPLES,
)

#: Pinned risk-tier vocabulary. Host-declared data, never proof.
TIER_UNACCEPTABLE = "unacceptable"
TIER_HIGH_RISK = "high-risk"
TIER_LIMITED_RISK = "limited-risk"
TIER_MINIMAL_RISK = "minimal-risk"
RISK_TIERS = (TIER_UNACCEPTABLE, TIER_HIGH_RISK,
              TIER_LIMITED_RISK, TIER_MINIMAL_RISK)

#: Pinned enforcement-action vocabulary. Booked as data, never proof.
ACTION_WARNING = "warning"
ACTION_CORRECTIVE_ORDER = "corrective-order"
ACTION_FINE = "fine"
ACTION_DEPLOYMENT_SUSPENSION = "deployment-suspension"
ACTION_MARKET_WITHDRAWAL = "market-withdrawal"
ACTION_LICENSE_REVOCATION = "license-revocation"
ACTION_MONITORING_ESCALATION = "monitoring-escalation"
ACTION_NO_ACTION = "no-action"
ACTIONS = (
    ACTION_WARNING,
    ACTION_CORRECTIVE_ORDER,
    ACTION_FINE,
    ACTION_DEPLOYMENT_SUSPENSION,
    ACTION_MARKET_WITHDRAWAL,
    ACTION_LICENSE_REVOCATION,
    ACTION_MONITORING_ESCALATION,
    ACTION_NO_ACTION,
)

#: Actions that drive the "restricted" posture (restrictive measures).
_RESTRICTIVE_ACTIONS = frozenset(
    {ACTION_FINE, ACTION_DEPLOYMENT_SUSPENSION,
     ACTION_MARKET_WITHDRAWAL, ACTION_LICENSE_REVOCATION})

#: Actions that drive the "under-enforcement" posture (non-restrictive measures).
_MEASURE_ACTIONS = frozenset(
    {ACTION_WARNING, ACTION_CORRECTIVE_ORDER,
     ACTION_MONITORING_ESCALATION})

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_DECOMMISSIONED = "decommissioned"
RETIRE_REASONS = (REASON_MANUAL, REASON_SUPERSEDED,
                  REASON_DECOMMISSIONED)

#: Pinned posture vocabulary (derived as data by ``report()``).
POSTURE_UNASSESSED = "unassessed"
POSTURE_RESTRICTED = "restricted"
POSTURE_UNDER_ENFORCEMENT = "under-enforcement"
POSTURE_COMPLIANT = "compliant"
POSTURES = (POSTURE_UNASSESSED, POSTURE_RESTRICTED,
            POSTURE_UNDER_ENFORCEMENT, POSTURE_COMPLIANT)

#: Regex for a well-formed sha256 digest pin.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AIRegulationError(Exception):
    """Base error for the ai-regulation module."""


class BadSystemError(AIRegulationError):
    """Malformed system id."""


class UnknownSystemError(AIRegulationError):
    """System id not assessed."""


class RetiredSystemError(AIRegulationError):
    """System id was retired; never recycled."""


class BadRegulationError(AIRegulationError):
    """Regulation outside the pinned vocabulary."""


class BadRiskTierError(AIRegulationError):
    """Risk tier outside the pinned vocabulary."""


class BadActionError(AIRegulationError):
    """Enforcement action outside the pinned vocabulary."""


class BadDigestError(AIRegulationError):
    """Malformed sha256 digest pin."""


class BadReasonError(AIRegulationError):
    """Retire reason outside the pinned vocabulary."""


class UnknownRecordError(AIRegulationError):
    """Record id not booked."""


class SeqOrderError(AIRegulationError):
    """Seq not a strictly increasing int."""


class AuditKindError(AIRegulationError):
    """Audit kind outside the pinned vocabulary or banned detail key."""


# ---------------------------------------------------------------------------
# Records (frozen dataclasses)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AssessmentRecord:
    """One declared regulatory assessment over a named AI system."""
    assessment_id: str
    system_id: str
    regulation: str
    risk_tier: str
    assessment_digest: str
    seq: int
    digest: str
    schema: str = AI_REGULATION_SCHEMA
    version: str = AI_REGULATION_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "regulation": self.regulation,
            "risk_tier": self.risk_tier,
            "assessment_digest": self.assessment_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        """Recompute the tamper-evident pin."""
        return self.digest == _assessment_digest(
            self.assessment_id, self.system_id, self.regulation,
            self.risk_tier, self.assessment_digest)


@dataclass(frozen=True)
class EnforcementRecord:
    """One declared enforcement action against a named AI system."""
    enforcement_id: str
    system_id: str
    action: str
    enforcement_digest: str
    seq: int
    digest: str
    schema: str = AI_REGULATION_SCHEMA
    version: str = AI_REGULATION_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enforcement_id": self.enforcement_id,
            "system_id": self.system_id,
            "action": self.action,
            "enforcement_digest": self.enforcement_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _enforcement_digest(
            self.enforcement_id, self.system_id, self.action,
            self.enforcement_digest)


@dataclass(frozen=True)
class VerificationReport:
    """Pure read view of one record's integrity (data, not proof)."""
    record_id: str
    verdict: str  # "verified" | "tampered"
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_REGULATION_SCHEMA
    version: str = AI_REGULATION_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _verify_digest(self.record_id, self.verdict)


@dataclass(frozen=True)
class RegulationPostureReport:
    """Pure read view of derived regulatory posture (data, not findings)."""
    system_id: str  # "" for whole-ledger scope
    posture: str  # "unassessed" | "restricted" | "under-enforcement"
                  # | "compliant"
    assessment_count: int
    enforcement_count: int
    restricted_count: int
    measure_count: int
    integrity_ok: bool
    seq: int
    digest: str
    schema: str = AI_REGULATION_SCHEMA
    version: str = AI_REGULATION_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "system_id": self.system_id,
            "posture": self.posture,
            "assessment_count": self.assessment_count,
            "enforcement_count": self.enforcement_count,
            "restricted_count": self.restricted_count,
            "measure_count": self.measure_count,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        return self.digest == _report_digest(
            self.system_id, self.posture, self.assessment_count,
            self.enforcement_count, self.restricted_count,
            self.measure_count)


@dataclass(frozen=True)
class RetireRecord:
    """Terminal record: a system id retired forever."""
    system_id: str
    reason: str
    seq: int
    digest: str
    schema: str = AI_REGULATION_SCHEMA
    version: str = AI_REGULATION_VERSION

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


def _assessment_digest(assessment_id: str, system_id: str, regulation: str,
                       risk_tier: str, assessment_digest: str) -> str:
    return _pin({"assessment_id": assessment_id, "system_id": system_id,
                 "regulation": regulation, "risk_tier": risk_tier,
                 "assessment_digest": assessment_digest})


def _enforcement_digest(enforcement_id: str, system_id: str, action: str,
                        enforcement_digest: str) -> str:
    return _pin({"enforcement_id": enforcement_id, "system_id": system_id,
                 "action": action,
                 "enforcement_digest": enforcement_digest})


def _verify_digest(record_id: str, verdict: str) -> str:
    return _pin({"record_id": record_id, "verdict": verdict})


def _retire_digest(system_id: str, reason: str) -> str:
    return _pin({"system_id": system_id, "reason": reason})


def _report_digest(system_id: str, posture: str, assessment_count: int,
                   enforcement_count: int, restricted_count: int,
                   measure_count: int) -> str:
    return _pin({"system_id": system_id, "posture": posture,
                 "assessment_count": assessment_count,
                 "enforcement_count": enforcement_count,
                 "restricted_count": restricted_count,
                 "measure_count": measure_count})


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


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def ai_regulation_audit_event(kind: str, seq: int,
                             **details: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event for the ai-regulation ledger."""
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
        "version": AI_REGULATION_VERSION,
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
# AIRegulation
# ---------------------------------------------------------------------------

class AIRegulation:
    """AI regulation compliance decision ledger.

    Books declared regulatory assessments and host-reported enforcement
    actions over named AI systems, and derives posture as data.
    Deterministic, in-memory, fail-closed; no wall-clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, None] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._assessments_for: Dict[str, Tuple[str, ...]] = {}
        self._enforcements: Dict[str, EnforcementRecord] = {}
        self._enforcements_for: Dict[str, Tuple[str, ...]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._enforcement_counter = 0
        self._seq = 0
        self._audit: list = []

    # -- internal ------------------------------------------------------

    def _claim(self, seq: int) -> int:
        """Validate and claim a mutating seq.

        Raises bare SeqOrderError on rewind or malformed seq: no
        consumption, no audit row.
        """
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must strictly increase: {seq!r}")
        self._seq = seq
        return seq

    def _burn(self, seq: int) -> None:
        """Consume the seq for a failed mutation (claim-then-burn)."""
        self._seq = max(self._seq, seq)

    def _emit(self, kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_regulation_audit_event(kind, seq, **details))

    def _require_read_seq(self, seq: Any) -> int:
        """Pure reads validate seq shape only; never consume."""
        return _check_seq(seq)

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- assess --------------------------------------------------------

    def assess(self, system_id: str, seq: int,
               regulation: str = REG_EU_AI_ACT,
               risk_tier: str = TIER_HIGH_RISK,
               assessment_digest: str = "") -> AssessmentRecord:
        """Book one declared regulatory assessment (minted ``asm-N``).

        First assess registers the system. Raw assessment material never
        enters the record: digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id, BadSystemError)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                if regulation not in REGULATIONS:
                    raise BadRegulationError(
                        f"bad regulation: {regulation!r}")
                if risk_tier not in RISK_TIERS:
                    raise BadRiskTierError(
                        f"bad risk tier: {risk_tier!r}")
                _check_digest(assessment_digest)
            except AIRegulationError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            self._systems.setdefault(system_id, None)
            self._assessment_counter += 1
            assessment_id = f"asm-{self._assessment_counter}"
            record = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                regulation=regulation,
                risk_tier=risk_tier,
                assessment_digest=assessment_digest,
                seq=seq,
                digest=_assessment_digest(assessment_id, system_id,
                                         regulation, risk_tier,
                                         assessment_digest),
            )
            self._assessments[assessment_id] = record
            self._assessments_for[system_id] = (
                self._assessments_for.get(system_id, ()) + (assessment_id,))
            self._emit(KIND_ASSESSED, seq, assessment_id=assessment_id,
                       system_id=system_id, regulation=regulation,
                       risk_tier=risk_tier)
            return record

    # -- enforce -------------------------------------------------------

    def enforce(self, system_id: str, seq: int,
                action: str = ACTION_WARNING,
                enforcement_digest: str = "") -> EnforcementRecord:
        """Book one declared enforcement action (minted ``enf-N``).

        The action is booked as data, never proof of a real regulator
        order. Fail-closed on unknown or retired systems.
        """
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id, BadSystemError)
                self._require_live(system_id)
                if action not in ACTIONS:
                    raise BadActionError(f"bad action: {action!r}")
                _check_digest(enforcement_digest)
            except AIRegulationError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            self._enforcement_counter += 1
            enforcement_id = f"enf-{self._enforcement_counter}"
            record = EnforcementRecord(
                enforcement_id=enforcement_id,
                system_id=system_id,
                action=action,
                enforcement_digest=enforcement_digest,
                seq=seq,
                digest=_enforcement_digest(enforcement_id, system_id,
                                          action, enforcement_digest),
            )
            self._enforcements[enforcement_id] = record
            self._enforcements_for[system_id] = (
                self._enforcements_for.get(system_id, ()) + (enforcement_id,))
            self._emit(KIND_ENFORCED, seq, enforcement_id=enforcement_id,
                       system_id=system_id, action=action)
            return record

    # -- verify --------------------------------------------------------

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a record's digest pin (never consumed)."""
        with self._lock:
            self._require_read_seq(seq)
            _check_id(record_id, UnknownRecordError)
            record = self._assessments.get(record_id)
            if record is None:
                record = self._enforcements.get(record_id)
            if record is None:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                record_id=record_id,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_verify_digest(record_id, verdict),
            )

    # -- report --------------------------------------------------------

    def report(self, seq: int, system_id: str = "") -> RegulationPostureReport:
        """Pure read: derived regulatory posture as data (never consumed).

        Posture precedence: ``unassessed`` (no assessments) >
        ``restricted`` (any restrictive enforcement) >
        ``under-enforcement`` (any non-restrictive measure) >
        ``compliant``. Whole-ledger scope when ``system_id`` is "".
        """
        with self._lock:
            self._require_read_seq(seq)
            if system_id != "":
                _check_id(system_id, BadSystemError)
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                systems = (system_id,)
            else:
                systems = tuple(self._systems)
            n_assess = sum(len(self._assessments_for.get(s, ()))
                           for s in systems)
            actions = [
                self._enforcements[eid].action
                for s in systems
                for eid in self._enforcements_for.get(s, ())
            ]
            n_enf = len(actions)
            n_restricted = sum(1 for a in actions if a in _RESTRICTIVE_ACTIONS)
            n_measure = sum(1 for a in actions if a in _MEASURE_ACTIONS)
            if n_assess == 0:
                posture = POSTURE_UNASSESSED
            elif n_restricted > 0:
                posture = POSTURE_RESTRICTED
            elif n_measure > 0:
                posture = POSTURE_UNDER_ENFORCEMENT
            else:
                posture = POSTURE_COMPLIANT
            integrity_ok = all(
                self._assessments[aid].verify()
                for s in systems
                for aid in self._assessments_for.get(s, ())
            ) and all(
                self._enforcements[eid].verify()
                for s in systems
                for eid in self._enforcements_for.get(s, ())
            )
            return RegulationPostureReport(
                system_id=system_id,
                posture=posture,
                assessment_count=n_assess,
                enforcement_count=n_enf,
                restricted_count=n_restricted,
                measure_count=n_measure,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_report_digest(system_id, posture, n_assess, n_enf,
                                      n_restricted, n_measure),
            )

    # -- retire --------------------------------------------------------

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminal: retire a system id forever; ids never recycled."""
        with self._lock:
            self._claim(seq)
            try:
                _check_id(system_id, BadSystemError)
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system already retired: {system_id!r}")
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
            except AIRegulationError as exc:
                self._burn(seq)
                self._emit(KIND_REJECTED, seq,
                           rejected_kind=type(exc).__name__,
                           system_id=system_id)
                raise
            record = RetireRecord(
                system_id=system_id,
                reason=reason,
                seq=seq,
                digest=_retire_digest(system_id, reason),
            )
            self._retired[system_id] = record
            self._emit(KIND_RETIRED, seq, system_id=system_id,
                       reason=reason)
            return record

    # -- pure-read views -----------------------------------------------

    def assessment_record(self, assessment_id: str,
                          seq: int) -> AssessmentRecord:
        with self._lock:
            self._require_read_seq(seq)
            try:
                return self._assessments[assessment_id]
            except KeyError:
                raise UnknownRecordError(
                    f"unknown record: {assessment_id!r}")

    def enforcement_record(self, enforcement_id: str,
                           seq: int) -> EnforcementRecord:
        with self._lock:
            self._require_read_seq(seq)
            try:
                return self._enforcements[enforcement_id]
            except KeyError:
                raise UnknownRecordError(
                    f"unknown record: {enforcement_id!r}")

    def assessments_for(self, system_id: str,
                        seq: int) -> Tuple[AssessmentRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._assessments[aid]
                         for aid in self._assessments_for.get(system_id, ()))

    def enforcements_for(self, system_id: str,
                         seq: int) -> Tuple[EnforcementRecord, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._enforcements[eid]
                         for eid in self._enforcements_for.get(system_id, ()))

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._systems)

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._assessments)

    def enforcement_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._enforcements)

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._retired)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "enforcements": len(self._enforcements),
                "retired": len(self._retired),
                "seq": self._seq,
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise assess/enforce/verify/report/retire paths."""
    r = AIRegulation()
    asm = r.assess("sys-1", 1, regulation=REG_EU_AI_ACT,
                   risk_tier=TIER_HIGH_RISK)
    assert asm.assessment_id == "asm-1" and asm.verify()
    enf = r.enforce("sys-1", 2, action=ACTION_NO_ACTION)
    assert enf.enforcement_id == "enf-1" and enf.verify()
    rep = r.report(3, "sys-1")
    assert rep.posture == "compliant" and rep.verify()
    vfy = r.verify("asm-1", 4)
    assert vfy.verdict == "verified" and vfy.verify()
    ret = r.retire("sys-1", 5)
    assert ret.verify()
    assert stdlib_only()
    print("ai-regulation OK: assess, enforce, verify, report, retire, pins, audit")


if __name__ == "__main__":
    main()
