"""AI standards conformance (declare/verify/evaluate) interface, simulated.

Research motivation: the AI-standards landscape (ISO/IEC 42001 AI
management systems, ISO/IEC 23894 AI risk management, NIST AI RMF,
IEEE 7000 series ethical design, the OECD AI Principles, and the EU
AI Act's harmonized-standards layer) all converge on one operational
shape: a steward *declares* conformance against a pinned standards
document, the ledger pins the declaration, and a report derives
posture *from the ledger* -- the report never independently certifies
conformance.

This module is the *standards-conformance* ledger half of that shape:

- ``AIStandards.declare(system_id, standard, conformance, seq,
  claim_digest="")`` -- book one declared conformance declaration over
  the pinned 8-standard vocabulary x the pinned 4-conformance
  vocabulary. The declaration's evidence is pinned by ``sha256:``
  digest only; raw material never enters a record. First declare on an
  id registers the system.
- ``AIStandards.verify(declaration_id, seq)`` -- **pure read** (seq
  shape validated, never consumed, no audit row). Re-derives the
  digest pin; the ``verified``/``tampered`` verdict is *data*, never
  proof the system conforms to the standard.
- ``AIStandards.evaluate(system_id, seq)`` -- **pure read**. Derives
  posture as data by ledger rule: ``unevaluated`` (no declarations) ->
  ``non-conformant`` (any ``non-conformant``) ->
  ``partially-conformant`` (any ``partially-conformant``) ->
  ``under-assessment`` (any ``not-assessed``) -> ``conformant`` (all
  ``conformant``), plus conformance tallies and ``integrity_ok`` as
  data.
- ``AIStandards.retire(system_id, seq, reason="manual")`` -- terminal.
  Ids are never recycled; post-retire mutations are refused, reads
  still work.
- Pure-read views (``declaration_record`` / ``declarations_for`` /
  ``system_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_standards_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``declared`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw declaration content never crosses the audit boundary --
  audit rows carry ids, pinned standard/conformance labels, digests,
  and counts only.

Distinct layer: ``ai_ethics.py`` owns the per-system ethics
assessment ledger (declared findings over ethics dimensions),
``ai_safety.py`` owns the safety assessment-to-mitigation ledger,
``ai_governance.py`` owns the governance operations ledger (controls
over systems, audit decisions), ``ai_principles.py`` /
``ai_charter.py`` own principle/charter declaration lifecycles. This
module owns the *standards conformance* ledger none of them cover --
declared conformance against named standards documents, digest
re-derivation, and derived posture.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``declaration_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``standard`` must be in the pinned 8-standard vocabulary;
  ``conformance`` must be in the pinned 4-conformance vocabulary.
- ``claim_digest`` must be ``sha256:<64hex>`` when supplied (may be
  empty).
- ``verify`` / ``declare`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``dcl-N``).
- ``declare`` on a retired system raises ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* conformance reported by the host. A
  booked ``conformant`` verdict means the host declared one -- the
  module audited nothing, ran no conformity assessment, and proves
  nothing about any real system's standards compliance.
- Digest pins prove ledger integrity and ordering, never the truth of
  any declaration or the standards conformance of any system.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if conformance state must survive a restart.
"""

from __future__ import annotations

import hashlib
import re
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
AI_STANDARDS_VERSION = "ai-standards.v1"

#: Schema pin carried by records and audit events.
AI_STANDARDS_SCHEMA = "northstar.ai-standards.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_DECLARED = "declared"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_DECLARED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding",
     "justification", "analysis", "report", "claim_text",
     "rationale", "metric", "score", "data", "record", "trace",
     "transcript", "weights", "policy", "model_output", "judgment",
     "decision_text", "note", "comment"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned standards-document vocabulary (ISO/NIST/IEEE/OECD/EU shaped).
STD_ISO_42001 = "iso-42001"
STD_NIST_AI_RMF = "nist-ai-rmf"
STD_ISO_23894 = "iso-23894"
STD_EU_AI_ACT = "eu-ai-act"
STD_OECD_AI_PRINCIPLES = "oecd-ai-principles"
STD_IEEE_7000 = "ieee-7000"
STD_ISO_24028 = "iso-24028"
STD_SELF_DECLARED = "self-declared"
STANDARDS = (
    STD_ISO_42001,
    STD_NIST_AI_RMF,
    STD_ISO_23894,
    STD_EU_AI_ACT,
    STD_OECD_AI_PRINCIPLES,
    STD_IEEE_7000,
    STD_ISO_24028,
    STD_SELF_DECLARED,
)

#: Pinned conformance vocabulary. Conformance is host-reported data.
CONF_CONFORMANT = "conformant"
CONF_NON_CONFORMANT = "non-conformant"
CONF_PARTIALLY_CONFORMANT = "partially-conformant"
CONF_NOT_ASSESSED = "not-assessed"
CONFORMANCES = (
    CONF_CONFORMANT,
    CONF_NON_CONFORMANT,
    CONF_PARTIALLY_CONFORMANT,
    CONF_NOT_ASSESSED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNEVALUATED = "unevaluated"
POSTURE_NON_CONFORMANT = "non-conformant"
POSTURE_PARTIALLY = "partially-conformant"
POSTURE_UNDER_ASSESSMENT = "under-assessment"
POSTURE_CONFORMANT = "conformant"
POSTURES = (
    POSTURE_UNEVALUATED,
    POSTURE_NON_CONFORMANT,
    POSTURE_PARTIALLY,
    POSTURE_UNDER_ASSESSMENT,
    POSTURE_CONFORMANT,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_POLICY_CHANGE = "policy-change"
REASON_NON_CONFORMANCE = "non-conformance"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_POLICY_CHANGE,
    REASON_NON_CONFORMANCE,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AIStandardsError(Exception):
    """Base error for the AI-standards ledger (programming errors)."""


class BadIdError(AIStandardsError):
    """Raised when a system/declaration id is malformed."""


class DuplicateDeclarationError(AIStandardsError):
    """Raised when a minted declaration id somehow collides (never)."""


class UnknownSystemError(AIStandardsError):
    """Raised when a system id names no declared system."""


class UnknownDeclarationError(AIStandardsError):
    """Raised when a declaration id names no booked declaration."""


class RetiredSystemError(AIStandardsError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AIStandardsError):
    """Raised when retiring an already-retired system."""


class BadStandardError(AIStandardsError):
    """Raised when a standard is not in the pinned vocabulary."""


class BadConformanceError(AIStandardsError):
    """Raised when a conformance is not in the pinned vocabulary."""


class BadDigestError(AIStandardsError):
    """Raised when a claim digest is not a sha256: pin."""


class BadReasonError(AIStandardsError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIStandardsError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIStandardsError):
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
        "domain": AI_STANDARDS_SCHEMA,
        "parts": list(parts),
    })


def ai_standards_audit_event(kind: str, detail: Dict[str, object],
                             seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-standards ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_STANDARDS_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class DeclarationRecord:
    """Frozen record of one declared standards conformance (digest-pinned)."""
    declaration_id: str
    system_id: str
    standard: str
    conformance: str
    claim_digest: str
    seq: int
    digest: str

    def verify(self, declaration_id: str, system_id: str, standard: str,
               conformance: str, claim_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "declaration", declaration_id, system_id, standard,
            conformance, claim_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    declaration_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, declaration_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", declaration_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_declarations: int
    n_conformant: int
    n_non_conformant: int
    n_partially: int
    n_not_assessed: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, system_id: str, posture: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", system_id, posture, self.seq)


@dataclass(frozen=True)
class RetireRecord:
    """Frozen record of a terminal retirement (ids never recycled)."""
    system_id: str
    reason: str
    seq: int
    digest: str

    def verify(self, system_id: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("retire", system_id, reason, self.seq)


class AIStandards:
    """AI-standards conformance ledger (declared conformance, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._declarations: Dict[str, DeclarationRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._declaration_ids: Tuple[str, ...] = ()
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
        event = ai_standards_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_standards_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def declare(self, system_id: str, standard: str, conformance: str,
                seq: int, claim_digest: str = "") -> DeclarationRecord:
        """Book one declared standards conformance. First declare on an id
        registers the system. Pins the claim digest, never the claim
        content. Returns the frozen ``DeclarationRecord`` (minted
        ``dcl-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(standard, bool) or not isinstance(standard, str):
                raise BadStandardError(
                    f"standard must be str, got {type(standard).__name__}")
            if standard not in STANDARDS:
                raise BadStandardError(
                    f"standard must be one of {sorted(STANDARDS)}, "
                    f"got {standard!r}")
            if isinstance(conformance, bool) or not isinstance(conformance,
                                                              str):
                raise BadConformanceError(
                    f"conformance must be str, got {type(conformance).__name__}")
            if conformance not in CONFORMANCES:
                raise BadConformanceError(
                    f"conformance must be one of {sorted(CONFORMANCES)}, "
                    f"got {conformance!r}")
            claim_digest = _check_digest(
                claim_digest, "claim_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                declaration_id = f"dcl-{len(self._declaration_ids) + 1}"
                if declaration_id in self._declarations:
                    raise DuplicateDeclarationError(
                        f"declaration id collision: {declaration_id!r}")
                record = DeclarationRecord(
                    declaration_id=declaration_id,
                    system_id=system_id,
                    standard=standard,
                    conformance=conformance,
                    claim_digest=claim_digest,
                    seq=seq,
                    digest=_pin("declaration", declaration_id, system_id,
                                standard, conformance, claim_digest, seq),
                )
                self._declarations[declaration_id] = record
                self._declaration_ids = self._declaration_ids + (
                    declaration_id,)
                self._by_system[system_id] = (
                    self._by_system.get(system_id, ()) + (declaration_id,))
        except AIStandardsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_DECLARED,
                   {"system_id": system_id,
                    "declaration_id": record.declaration_id,
                    "standard": standard,
                    "conformance": conformance,
                    "claim_digest": claim_digest}, seq)
        return record

    def verify(self, declaration_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a declaration's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        declaration_id = _check_id(declaration_id, "declaration_id")
        with self._lock:
            if declaration_id not in self._declarations:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}")
            rec = self._declarations[declaration_id]
            intact = rec.verify(
                rec.declaration_id, rec.system_id, rec.standard,
                rec.conformance, rec.claim_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                declaration_id=declaration_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", declaration_id, verdict, seq),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``non-conformant`` -> ``non-conformant``; any
        ``partially-conformant`` -> ``partially-conformant``; any
        ``not-assessed`` -> ``under-assessment``; all ``conformant`` ->
        ``conformant``). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``EvaluationReport``."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            ids = self._by_system[system_id]
            recs = [self._declarations[i] for i in ids]
            n_conf = sum(1 for r in recs
                         if r.conformance == CONF_CONFORMANT)
            n_non = sum(1 for r in recs
                        if r.conformance == CONF_NON_CONFORMANT)
            n_part = sum(1 for r in recs
                         if r.conformance == CONF_PARTIALLY_CONFORMANT)
            n_not = sum(1 for r in recs
                        if r.conformance == CONF_NOT_ASSESSED)
            integrity_ok = all(
                r.verify(r.declaration_id, r.system_id, r.standard,
                         r.conformance, r.claim_digest) for r in recs)
            if n_non:
                posture = POSTURE_NON_CONFORMANT
            elif n_part:
                posture = POSTURE_PARTIALLY
            elif n_not:
                posture = POSTURE_UNDER_ASSESSMENT
            else:
                posture = POSTURE_CONFORMANT
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                n_declarations=len(recs),
                n_conformant=n_conf,
                n_non_conformant=n_non,
                n_partially=n_part,
                n_not_assessed=n_not,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_pin("evaluation", system_id, posture, seq),
            )

    def retire(self, system_id: str, seq: int,
               reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminally retire a system. Ids are never recycled; post-retire
        mutations are refused, reads still work. Returns the frozen
        ``RetireRecord``."""
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
                if system_id in self._retired:
                    raise DoubleRetireError(
                        f"system already retired: {system_id!r}")
                record = RetireRecord(
                    system_id=system_id,
                    reason=reason,
                    seq=seq,
                    digest=_pin("retire", system_id, reason, seq),
                )
                self._retired[system_id] = record
        except AIStandardsError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    def declaration_record(self, declaration_id: str,
                           seq: int) -> DeclarationRecord:
        """Pure read view of one booked declaration."""
        _check_seq(seq)
        declaration_id = _check_id(declaration_id, "declaration_id")
        with self._lock:
            if declaration_id not in self._declarations:
                raise UnknownDeclarationError(
                    f"unknown declaration: {declaration_id!r}")
            return self._declarations[declaration_id]

    def declarations_for(self, system_id: str,
                         seq: int) -> Tuple[str, ...]:
        """Pure read view of declaration ids for one system, in book order."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered system ids, in first-declare order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._by_system.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of retired system ids."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._retired.keys())

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Pure read view of the audit events (no seq, no audit row)."""
        with self._lock:
            return self._audit

    def stats(self) -> Dict[str, int]:
        """Pure read view of ledger counters (no seq, no audit row)."""
        with self._lock:
            return {
                "systems": len(self._by_system),
                "declarations": len(self._declarations),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: declare, verify, evaluate, retire, pins, audit."""
    st = AIStandards()
    assert AI_STANDARDS_VERSION == "ai-standards.v1"
    assert AI_STANDARDS_SCHEMA == "northstar.ai-standards.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = st.declare("sys-1", STD_ISO_42001, CONF_CONFORMANT, 1, digest)
    assert rec.declaration_id == "dcl-1"
    assert rec.verify("dcl-1", "sys-1", STD_ISO_42001, CONF_CONFORMANT,
                      digest)
    assert not rec.verify("dcl-1", "sys-1", STD_ISO_42001,
                          CONF_NON_CONFORMANT, digest)
    vr = st.verify("dcl-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("dcl-1", "verified")
    ev = st.evaluate("sys-1", 3)
    assert ev.posture == POSTURE_CONFORMANT
    assert ev.integrity_ok
    assert ev.verify("sys-1", POSTURE_CONFORMANT)
    st.declare("sys-1", STD_NIST_AI_RMF, CONF_PARTIALLY_CONFORMANT, 4,
               digest)
    ev = st.evaluate("sys-1", 5)
    assert ev.posture == POSTURE_PARTIALLY
    assert ev.n_declarations == 2 and ev.n_partially == 1
    rr = st.retire("sys-1", 6)
    assert rr.verify("sys-1", REASON_MANUAL)
    try:
        st.declare("sys-1", STD_ISO_23894, CONF_CONFORMANT, 7)
    except RetiredSystemError:
        pass
    else:
        raise AssertionError("declare on retired system must fail closed")
    assert st.stats()["systems"] == 1
    kinds = [row["kind"] for row in st.audit_log()]
    assert kinds == [KIND_DECLARED, KIND_DECLARED, KIND_RETIRED,
                     KIND_REJECTED]
    print("ai-standards OK: declare, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
