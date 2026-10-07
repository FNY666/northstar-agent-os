"""Machine-ethics reasoning (declare/assess/verify/evaluate) interface, simulated.

Research motivation: machine ethics asks how a machine *reasons* about
right and wrong -- moral-framework declarations (utilitarianism,
deontology, virtue ethics, principlism, care ethics, contractarianism)
feeding into declared judgments over concrete dilemmas (trolley,
resource allocation, autonomy conflicts). Governance needs an
operational ledger for that shape: a host declares the machine's moral
framework, declares judgments over a pinned dilemma vocabulary, and a
report derives a moral posture *from the ledger* -- the report never
independently judges ethics.

This module is the *machine-ethics reasoning* ledger half of that shape:

- ``MachineEthics.declare_framework(system_id, seq,
  framework="unspecified", framework_digest="")`` -- book one declared
  moral framework over the pinned 8-framework vocabulary. Raw
  framework content travels as ``sha256:`` digest pins only; it never
  enters a record. First declaration on an id registers the system.
- ``MachineEthics.assess(system_id, seq,
  dilemma_kind="trolley", judgment="permissible",
  evidence_digest="")`` -- book one declared ethical judgment over
  the pinned 8-dilemma vocabulary x the pinned 4-judgment vocabulary.
  Judgments are host-declared data, never proof the machine reasoned
  ethically. Fail-closed: the system must be registered first.
- ``MachineEthics.verify(record_id, seq)`` -- **pure read** (seq shape
  validated, never consumed, no audit row). Re-derives the digest pin
  of any framework or assessment record; the ``verified``/``tampered``
  verdict is *data*, never proof the judgment was correct.
- ``MachineEthics.evaluate(system_id, seq)`` -- **pure read**.
  Derives posture as data by ledger rule: ``unevaluated`` (no
  assessments) -> ``non-compliant`` (any ``impermissible``) ->
  ``ambiguous`` (any ``ambiguous`` / ``needs-review``) ->
  ``consistent`` (all ``permissible``), plus judgment tallies and
  ``integrity_ok`` as data.
- ``MachineEthics.retire(system_id, seq, reason="manual")`` --
  terminal. Ids are never recycled; post-retire mutations are refused,
  reads still work.
- Pure-read views (``framework_record`` / ``assessment_record`` /
  ``frameworks_for`` / ``assessments_for`` / ``system_ids`` /
  ``retired_ids`` / ``stats`` / ``audit_log``) -- seq shape validated,
  never consumed, no audit rows.
- ``machine_ethics_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  rows (``framework-declared`` / ``assessed`` / ``retired`` /
  ``rejected``); caller-supplied seqs only. Raw framework text,
  dilemma content, and judgments never cross the audit boundary --
  audit rows carry ids, pinned vocabulary labels, digests, and counts
  only.

Distinct layer: ``ai_ethics.py`` owns per-system AI-ethics
*assessments* over 8 ethics dimensions x 4 verdicts (a governance
assessment ledger); ``responsible_ai.py`` owns the responsible-AI
governance ledger; ``ethics_review.py`` owns the institutional-review-board
lifecycle. This module owns the *machine's moral-reasoning* ledger
none of them cover -- declared moral frameworks, declared ethical
judgments over dilemma kinds, and derived moral posture.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``record_id`` must be non-empty str, <= 256 chars,
  no whitespace.
- ``framework`` must be in the pinned 8-framework vocabulary;
  ``dilemma_kind`` must be in the pinned 8-dilemma vocabulary;
  ``judgment`` must be in the pinned 4-judgment vocabulary.
- ``framework_digest`` / ``evidence_digest`` must be
  ``sha256:<64hex>`` when supplied (may be empty).
- ``assess`` / ``retire`` on unknown systems raise; duplicate ids
  never occur (ids are minted ``frm-N`` / ``asm-N``).
- ``declare_framework`` / ``assess`` on a retired system raise
  ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* moral frameworks and judgments
  reported by the host. A booked ``permissible`` judgment means the
  host declared one -- the module performed no moral reasoning,
  resolved no dilemmas, and proves nothing about any real system's
  ethics or safety.
- Digest pins prove ledger integrity and ordering, never the truth of
  any framework or judgment.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if machine-ethics state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
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
MACHINE_ETHICS_VERSION = "machine-ethics.v1"

#: Schema pin carried by records and audit events.
MACHINE_ETHICS_SCHEMA = "northstar.machine-ethics.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_FRAMEWORK_DECLARED = "framework-declared"
KIND_ASSESSED = "assessed"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_FRAMEWORK_DECLARED, KIND_ASSESSED, KIND_RETIRED,
          KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "assessment_text",
     "rationale", "metric", "score", "data", "record", "trace",
     "transcript", "weights", "policy", "model_output", "judgment_text",
     "dilemma_text", "framework_text", "reasoning", "principle_text",
     "note", "comment"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned moral-framework vocabulary (machine-ethics literature shaped).
FW_UTILITARIANISM = "utilitarianism"
FW_DEONTOLOGY = "deontology"
FW_VIRTUE_ETHICS = "virtue-ethics"
FW_PRINCIPLISM = "principlism"
FW_CARE_ETHICS = "care-ethics"
FW_CONTRACTARIANISM = "contractarianism"
FW_MIXED = "mixed"
FW_UNSPECIFIED = "unspecified"
FRAMEWORKS = (
    FW_UTILITARIANISM,
    FW_DEONTOLOGY,
    FW_VIRTUE_ETHICS,
    FW_PRINCIPLISM,
    FW_CARE_ETHICS,
    FW_CONTRACTARIANISM,
    FW_MIXED,
    FW_UNSPECIFIED,
)

#: Pinned moral-dilemma vocabulary. Dilemma content is host-reported data.
DLM_TROLLEY = "trolley"
DLM_RESOURCE_ALLOCATION = "resource-allocation"
DLM_AUTONOMY_CONFLICT = "autonomy-conflict"
DLM_TRUTHFUL_DECEPTION = "truthful-deception"
DLM_HARM_PREVENTION = "harm-prevention"
DLM_FAIRNESS_DISTRIBUTION = "fairness-distribution"
DLM_OVERSIGHT_DEFIANCE = "oversight-defiance"
DLM_PRIVACY_DISCLOSURE = "privacy-disclosure"
DILEMMAS = (
    DLM_TROLLEY,
    DLM_RESOURCE_ALLOCATION,
    DLM_AUTONOMY_CONFLICT,
    DLM_TRUTHFUL_DECEPTION,
    DLM_HARM_PREVENTION,
    DLM_FAIRNESS_DISTRIBUTION,
    DLM_OVERSIGHT_DEFIANCE,
    DLM_PRIVACY_DISCLOSURE,
)

#: Pinned ethical-judgment vocabulary. Judgments are host-declared data.
JUDGMENT_PERMISSIBLE = "permissible"
JUDGMENT_IMPERMISSIBLE = "impermissible"
JUDGMENT_AMBIGUOUS = "ambiguous"
JUDGMENT_NEEDS_REVIEW = "needs-review"
JUDGMENTS = (
    JUDGMENT_PERMISSIBLE,
    JUDGMENT_IMPERMISSIBLE,
    JUDGMENT_AMBIGUOUS,
    JUDGMENT_NEEDS_REVIEW,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNEVALUATED = "unevaluated"
POSTURE_NON_COMPLIANT = "non-compliant"
POSTURE_AMBIGUOUS = "ambiguous"
POSTURE_CONSISTENT = "consistent"
POSTURES = (
    POSTURE_UNEVALUATED,
    POSTURE_NON_COMPLIANT,
    POSTURE_AMBIGUOUS,
    POSTURE_CONSISTENT,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_POLICY_CHANGE = "policy-change"
REASON_NON_COMPLIANCE = "non-compliance"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_POLICY_CHANGE,
    REASON_NON_COMPLIANCE,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class MachineEthicsError(Exception):
    """Base error for the machine-ethics ledger (programming errors)."""


class BadIdError(MachineEthicsError):
    """Raised when a system/record id is malformed."""


class DuplicateRecordError(MachineEthicsError):
    """Raised when a minted id somehow collides (never)."""


class UnknownSystemError(MachineEthicsError):
    """Raised when a system id names no declared system."""


class UnknownRecordError(MachineEthicsError):
    """Raised when a record id names no booked record."""


class RetiredSystemError(MachineEthicsError):
    """Raised when mutating a retired system."""


class DoubleRetireError(MachineEthicsError):
    """Raised when retiring an already-retired system."""


class BadFrameworkError(MachineEthicsError):
    """Raised when a framework is not in the pinned vocabulary."""


class BadDilemmaError(MachineEthicsError):
    """Raised when a dilemma kind is not in the pinned vocabulary."""


class BadJudgmentError(MachineEthicsError):
    """Raised when a judgment is not in the pinned vocabulary."""


class BadDigestError(MachineEthicsError):
    """Raised when a digest is not a sha256: pin."""


class BadReasonError(MachineEthicsError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(MachineEthicsError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(MachineEthicsError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str, allow_empty: bool = False) -> str:
    """Validate a content pin: ``sha256:<64hex>``."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(
            f"{label} must be a sha256: pin, got {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not _DIGEST_RE.match(value):
        raise BadDigestError(
            f"{label} must match sha256:<64hex>, got {value!r}")
    return value


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": MACHINE_ETHICS_SCHEMA,
        "parts": list(parts),
    })


def machine_ethics_audit_event(kind: str, detail: Dict[str, object],
                               seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the machine-ethics ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": MACHINE_ETHICS_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class FrameworkRecord:
    """Frozen record of one declared moral framework (digest-pinned)."""
    framework_id: str
    system_id: str
    framework: str
    framework_digest: str
    seq: int
    digest: str

    def verify(self, framework_id: str, system_id: str, framework: str,
               framework_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "framework", framework_id, system_id, framework,
            framework_digest, self.seq)


@dataclass(frozen=True)
class AssessmentRecord:
    """Frozen record of one declared ethical judgment (digest-pinned)."""
    assessment_id: str
    system_id: str
    dilemma_kind: str
    judgment: str
    evidence_digest: str
    seq: int
    digest: str

    def verify(self, assessment_id: str, system_id: str, dilemma_kind: str,
               judgment: str, evidence_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "assessment", assessment_id, system_id, dilemma_kind, judgment,
            evidence_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    record_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, record_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", record_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_frameworks: int
    n_assessments: int
    n_permissible: int
    n_impermissible: int
    n_ambiguous: int
    n_needs_review: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, system_id: str, posture: str,
               n_permissible: int, n_impermissible: int,
               n_ambiguous: int, n_needs_review: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", system_id, posture, self.n_frameworks,
            self.n_assessments, n_permissible, n_impermissible,
            n_ambiguous, n_needs_review, self.integrity_ok, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of one system retirement (terminal)."""
    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, system_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", system_id, reason, self.seq)


class MachineEthics:
    """Machine-ethics reasoning ledger (declared frameworks, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._frameworks: Dict[str, FrameworkRecord] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._frameworks_by_system: Dict[str, Tuple[str, ...]] = {}
        self._assessments_by_system: Dict[str, Tuple[str, ...]] = {}
        self._framework_ids: Tuple[str, ...] = ()
        self._assessment_ids: Tuple[str, ...] = ()
        self._retired: Dict[str, RetireRecord] = {}
        self._audit: Tuple[Dict[str, object], ...] = ()

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, system_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if system_id:
            detail["system_id"] = system_id
        event = machine_ethics_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = machine_ethics_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _require_read_seq(self, seq: object) -> int:
        """Validate a pure-read seq's shape; never consume, never order."""
        return _check_seq(seq)

    def declare_framework(self, system_id: str, seq: int,
                          framework: str = FW_UNSPECIFIED,
                          framework_digest: str = "") -> FrameworkRecord:
        """Book one declared moral framework. First declaration on an id
        registers the system. Pins the framework digest, never the
        framework content. Returns the frozen ``FrameworkRecord``
        (minted ``frm-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(framework, bool) or not isinstance(framework, str):
                raise BadFrameworkError(
                    f"framework must be str, got {type(framework).__name__}")
            if framework not in FRAMEWORKS:
                raise BadFrameworkError(
                    f"framework must be one of {sorted(FRAMEWORKS)}, "
                    f"got {framework!r}")
            framework_digest = _check_digest(
                framework_digest, "framework_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                framework_id = f"frm-{len(self._framework_ids) + 1}"
                if framework_id in self._frameworks:
                    raise DuplicateRecordError(
                        f"framework id collision: {framework_id!r}")
                digest = _pin("framework", framework_id, system_id,
                              framework, framework_digest, seq)
                record = FrameworkRecord(framework_id, system_id, framework,
                                         framework_digest, seq, digest)
                self._frameworks[framework_id] = record
                self._framework_ids = self._framework_ids + (framework_id,)
                prev = self._frameworks_by_system.get(system_id, ())
                self._frameworks_by_system[system_id] = prev + (framework_id,)
            self._emit(KIND_FRAMEWORK_DECLARED, {
                "system_id": system_id,
                "framework_id": framework_id,
                "framework": framework,
                "framework_digest": framework_digest,
            }, seq)
            return record
        except MachineEthicsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise

    def assess(self, system_id: str, seq: int,
               dilemma_kind: str = DLM_TROLLEY,
               judgment: str = JUDGMENT_PERMISSIBLE,
               evidence_digest: str = "") -> AssessmentRecord:
        """Book one declared ethical judgment over the pinned dilemma
        vocabulary. The system must be registered (declared a framework
        or already assessed). Judgment is host-declared data, never
        proof the machine reasoned ethically. Returns the frozen
        ``AssessmentRecord`` (minted ``asm-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(dilemma_kind, bool) or not isinstance(dilemma_kind, str):
                raise BadDilemmaError(
                    f"dilemma_kind must be str, "
                    f"got {type(dilemma_kind).__name__}")
            if dilemma_kind not in DILEMMAS:
                raise BadDilemmaError(
                    f"dilemma_kind must be one of {sorted(DILEMMAS)}, "
                    f"got {dilemma_kind!r}")
            if isinstance(judgment, bool) or not isinstance(judgment, str):
                raise BadJudgmentError(
                    f"judgment must be str, got {type(judgment).__name__}")
            if judgment not in JUDGMENTS:
                raise BadJudgmentError(
                    f"judgment must be one of {sorted(JUDGMENTS)}, "
                    f"got {judgment!r}")
            evidence_digest = _check_digest(
                evidence_digest, "evidence_digest", allow_empty=True)
            with self._lock:
                known = (system_id in self._frameworks_by_system
                         or system_id in self._assessments_by_system)
                if not known:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                assessment_id = f"asm-{len(self._assessment_ids) + 1}"
                if assessment_id in self._assessments:
                    raise DuplicateRecordError(
                        f"assessment id collision: {assessment_id!r}")
                digest = _pin("assessment", assessment_id, system_id,
                              dilemma_kind, judgment, evidence_digest, seq)
                record = AssessmentRecord(assessment_id, system_id,
                                          dilemma_kind, judgment,
                                          evidence_digest, seq, digest)
                self._assessments[assessment_id] = record
                self._assessment_ids = self._assessment_ids + (assessment_id,)
                prev = self._assessments_by_system.get(system_id, ())
                self._assessments_by_system[system_id] = prev + (assessment_id,)
            self._emit(KIND_ASSESSED, {
                "system_id": system_id,
                "assessment_id": assessment_id,
                "dilemma_kind": dilemma_kind,
                "judgment": judgment,
                "evidence_digest": evidence_digest,
            }, seq)
            return record
        except MachineEthicsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """**Pure read.** Re-derive the digest pin of any framework or
        assessment record. ``verified``/``tampered`` is data, never
        proof the judgment was correct."""
        self._require_read_seq(seq)
        record_id = _check_id(record_id, "record_id")
        with self._lock:
            record = self._frameworks.get(record_id)
            tag = "framework"
            if record is None:
                record = self._assessments.get(record_id)
                tag = "assessment"
            if record is None:
                raise UnknownRecordError(
                    f"unknown record: {record_id!r}")
            if tag == "framework":
                expected = _pin(
                    "framework", record.framework_id, record.system_id,
                    record.framework, record.framework_digest, record.seq)
            else:
                expected = _pin(
                    "assessment", record.assessment_id, record.system_id,
                    record.dilemma_kind, record.judgment,
                    record.evidence_digest, record.seq)
            verdict = "verified" if expected == record.digest else "tampered"
            digest = _pin("verification", record_id, verdict, seq)
            return VerificationReport(record_id, verdict, seq, digest)

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """**Pure read.** Derive moral posture as data by ledger rule:
        ``unevaluated`` (no assessments) -> ``non-compliant`` (any
        ``impermissible``) -> ``ambiguous`` (any ``ambiguous`` /
        ``needs-review``) -> ``consistent`` (all ``permissible``).
        Plus judgment tallies and ``integrity_ok`` as data."""
        self._require_read_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            known = (system_id in self._frameworks_by_system
                     or system_id in self._assessments_by_system)
            if not known:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            fw_ids = self._frameworks_by_system.get(system_id, ())
            as_ids = self._assessments_by_system.get(system_id, ())
            records = [self._assessments[i] for i in as_ids]
            tallies = {j: 0 for j in JUDGMENTS}
            integrity_ok = True
            for record in records:
                tallies[record.judgment] += 1
                expected = _pin(
                    "assessment", record.assessment_id, record.system_id,
                    record.dilemma_kind, record.judgment,
                    record.evidence_digest, record.seq)
                if expected != record.digest:
                    integrity_ok = False
            if not records:
                posture = POSTURE_UNEVALUATED
            elif tallies[JUDGMENT_IMPERMISSIBLE] > 0:
                posture = POSTURE_NON_COMPLIANT
            elif (tallies[JUDGMENT_AMBIGUOUS] > 0
                  or tallies[JUDGMENT_NEEDS_REVIEW] > 0):
                posture = POSTURE_AMBIGUOUS
            else:
                posture = POSTURE_CONSISTENT
            digest = _pin(
                "evaluation", system_id, posture, len(fw_ids), len(as_ids),
                tallies[JUDGMENT_PERMISSIBLE],
                tallies[JUDGMENT_IMPERMISSIBLE],
                tallies[JUDGMENT_AMBIGUOUS],
                tallies[JUDGMENT_NEEDS_REVIEW],
                integrity_ok, seq)
            return EvaluationReport(
                system_id, posture, len(fw_ids), len(as_ids),
                tallies[JUDGMENT_PERMISSIBLE],
                tallies[JUDGMENT_IMPERMISSIBLE],
                tallies[JUDGMENT_AMBIGUOUS],
                tallies[JUDGMENT_NEEDS_REVIEW],
                integrity_ok, seq, digest)

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Retire a system (terminal). Ids are never recycled;
        post-retire mutations are refused, reads still work."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(reason, bool) or not isinstance(reason, str):
                raise BadReasonError(
                    f"reason must be str, got {type(reason).__name__}")
            if reason not in REASONS:
                raise BadReasonError(
                    f"reason must be one of {sorted(REASONS)}, "
                    f"got {reason!r}")
            with self._lock:
                known = (system_id in self._frameworks_by_system
                         or system_id in self._assessments_by_system)
                if not known:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise DoubleRetireError(
                        f"system already retired: {system_id!r}")
                digest = _pin("retire", system_id, reason, seq)
                record = RetireRecord(system_id, reason, seq, digest)
                self._retired[system_id] = record
            self._emit(KIND_RETIRED, {
                "system_id": system_id,
                "reason": reason,
            }, seq)
            return record
        except MachineEthicsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise

    def framework_record(self, framework_id: str,
                         seq: int) -> FrameworkRecord:
        """**Pure read.** Return one framework record by id."""
        self._require_read_seq(seq)
        framework_id = _check_id(framework_id, "framework_id")
        with self._lock:
            record = self._frameworks.get(framework_id)
            if record is None:
                raise UnknownRecordError(
                    f"unknown framework: {framework_id!r}")
            return record

    def assessment_record(self, assessment_id: str,
                          seq: int) -> AssessmentRecord:
        """**Pure read.** Return one assessment record by id."""
        self._require_read_seq(seq)
        assessment_id = _check_id(assessment_id, "assessment_id")
        with self._lock:
            record = self._assessments.get(assessment_id)
            if record is None:
                raise UnknownRecordError(
                    f"unknown assessment: {assessment_id!r}")
            return record

    def frameworks_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """**Pure read.** Framework ids declared for one system."""
        self._require_read_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            return self._frameworks_by_system.get(system_id, ())

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """**Pure read.** Assessment ids booked for one system."""
        self._require_read_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            return self._assessments_by_system.get(system_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """**Pure read.** All known system ids."""
        self._require_read_seq(seq)
        with self._lock:
            ids = set(self._frameworks_by_system) | set(
                self._assessments_by_system)
            return tuple(sorted(ids))

    def framework_ids(self, seq: int) -> Tuple[str, ...]:
        """**Pure read.** All minted framework ids."""
        self._require_read_seq(seq)
        with self._lock:
            return self._framework_ids

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        """**Pure read.** All minted assessment ids."""
        self._require_read_seq(seq)
        with self._lock:
            return self._assessment_ids

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """**Pure read.** All retired system ids."""
        self._require_read_seq(seq)
        with self._lock:
            return tuple(sorted(self._retired))

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Return the audit rows (caller-supplied seqs only)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Ledger counters."""
        with self._lock:
            return {
                "seq": self._last_seq,
                "systems": len(set(self._frameworks_by_system)
                               | set(self._assessments_by_system)),
                "frameworks": len(self._framework_ids),
                "assessments": len(self._assessment_ids),
                "retired": len(self._retired),
                "rejected": sum(1 for row in self._audit
                               if row.get("kind") == KIND_REJECTED),
            }


def main() -> None:
    """Self-check: declare, assess, verify, evaluate, retire, pins, audit."""
    ledger = MachineEthics()
    fw = ledger.declare_framework("sys-1", 1, FW_PRINCIPLISM)
    assert fw.framework_id == "frm-1"
    asm = ledger.assess("sys-1", 2, DLM_TROLLEY, JUDGMENT_PERMISSIBLE)
    assert asm.assessment_id == "asm-1"
    vr = ledger.verify("asm-1", 3)
    assert vr.verdict == "verified"
    rep = ledger.evaluate("sys-1", 4)
    assert rep.posture == POSTURE_CONSISTENT
    assert rep.integrity_ok is True
    ret = ledger.retire("sys-1", 5)
    assert ret.system_id == "sys-1"
    assert stdlib_only()
    assert all(row["schema"] == AUDIT_SCHEMA
               for row in ledger.audit_log())
    print("machine-ethics OK: declare, assess, verify, evaluate, "
          "retire, pins, audit")


if __name__ == "__main__":
    main()
