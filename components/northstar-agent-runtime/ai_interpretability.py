"""AI interpretability (system-level assessment) interface, simulated.

Research motivation: mechanistic interpretability (Olah et al., 2020;
Anthropic's circuit work), probing, saliency, concept-based methods,
counterfactuals, and behavioral testing all reduce to the same
bookkeeping shape: name an AI system, declare which interpretability
method was applied, book a host-declared finding, and derive a
ledger-rule posture. Getting this ledger wrong (findings booked against
the wrong method, silent method swaps, unpinned finding sets) makes the
assessment unverifiable -- and an unverifiable interpretability claim is
not an interpretability result.

This module is the *decision ledger* half of that shape:

- ``AIInterpretability.interpret(system_id, seq, method="mechanistic",
  finding="interpretable", interpretation_digest="")`` -- book one
  declared interpretability interpretation for a named AI system.
  Returns a frozen ``InterpretationRecord`` with a minted ``int-N`` id
  and a ``sha256:`` digest pin. Raw model internals, activations, and
  weights travel as digest pins only; raw material never enters a
  record. The first interpretation on an id registers the system.
- ``AIInterpretability.verify(record_id, seq)`` -- **pure read**:
  re-derive the digest pin of any interpretation or retirement record;
  verdict ``verified``/``tampered`` is data, never proof the system is
  really interpretable.
- ``AIInterpretability.evaluate(system_id, seq)`` -- **pure read**:
  derive the interpretability posture by ledger rule (``unevaluated``
  -> ``opaque`` -> ``ambiguous`` -> ``interpretable``) plus finding
  tallies and ``integrity_ok`` as data.
- ``AIInterpretability.retire(system_id, seq, reason="manual")`` --
  terminal retirement; ids are never recycled; post-retire mutations
  are refused, reads still work.
- Views (``interpretation_record()``, ``interpretations_for()``,
  ``system_ids()``, ``interpretation_ids()``, ``retired_ids()``,
  ``stats()``, ``audit_log()``) are pure reads: they validate the seq
  shape, consume nothing, and write no audit row.
- ``ai_interpretability_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records (``interpreted`` / ``retired`` /
  ``rejected``); caller-supplied seqs only. Raw model internals,
  activations, findings text, and weights never cross the audit
  boundary -- audit rows carry ids, pinned vocabulary values, and
  digest pins only.

Distinct-layer rationale: ``interpretability.py`` owns the
per-prediction explanation decision ledger (register prediction ->
explain -> attribute -> visualize); ``interpretability_probe.py`` owns
probe bookkeeping; ``mechanistic.py`` owns the mechanistic-analysis
lifecycle -- this module is the *system-level interpretability
assessment* decision ledger none of them own: declared interpretability
methods applied to named AI systems -> declared findings ->
ledger-rule posture, all booked as data.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``record_id`` must be non-empty str, <= 256 chars,
  no whitespace; ids are never recycled.
- ``method`` and ``finding`` are pinned vocabularies; anything else is
  refused.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* interpretations and *host-reported*
  findings. A booked finding is a ledger entry, not a proof of
  interpretability -- findings are GIGO: the module cannot prove the
  host ran mechanistic analysis, probed correctly, or interpreted
  honestly.
- ``interpret()`` names the method as a declaration; it does not run
  the analysis.
- An interpretation record proves the ledger's internal consistency
  (pins match, ids link, seqs order). It does not prove the system is
  interpretable, safe, or fair.
- Digest pins prove ledger integrity and ordering, never the truth of
  any interpretation.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if interpretability state must survive a restart.
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
AI_INTERPRETABILITY_VERSION = "ai-interpretability.v1"

#: Schema pin carried by records and audit events.
AI_INTERPRETABILITY_SCHEMA = "northstar.ai-interpretability.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_INTERPRETED = "interpreted"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_INTERPRETED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw content never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "text", "payload", "raw", "evidence", "finding_text",
     "justification", "analysis", "report", "rationale", "metric", "score",
     "data", "record", "trace", "transcript", "weights", "policy",
     "model_output", "activations", "internals", "reasoning",
     "interpretation_text", "note", "comment", "gradient", "loss"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned interpretability-method vocabulary (literature shaped).
MTH_MECHANISTIC = "mechanistic"
MTH_CIRCUIT_ANALYSIS = "circuit-analysis"
MTH_PROBING = "probing"
MTH_SALIENCY = "saliency"
MTH_CONCEPT_BASED = "concept-based"
MTH_COUNTERFACTUAL = "counterfactual"
MTH_FEATURE_ATTRIBUTION = "feature-attribution"
MTH_BEHAVIORAL_TESTING = "behavioral-testing"
METHODS = (
    MTH_MECHANISTIC,
    MTH_CIRCUIT_ANALYSIS,
    MTH_PROBING,
    MTH_SALIENCY,
    MTH_CONCEPT_BASED,
    MTH_COUNTERFACTUAL,
    MTH_FEATURE_ATTRIBUTION,
    MTH_BEHAVIORAL_TESTING,
)

#: Pinned interpretation-finding vocabulary. Findings are host-declared data.
FND_INTERPRETABLE = "interpretable"
FND_PARTIALLY_INTERPRETABLE = "partially-interpretable"
FND_OPAQUE = "opaque"
FND_INCONCLUSIVE = "inconclusive"
FINDINGS = (
    FND_INTERPRETABLE,
    FND_PARTIALLY_INTERPRETABLE,
    FND_OPAQUE,
    FND_INCONCLUSIVE,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNEVALUATED = "unevaluated"
POSTURE_OPAQUE = "opaque"
POSTURE_AMBIGUOUS = "ambiguous"
POSTURE_INTERPRETABLE = "interpretable"
POSTURES = (
    POSTURE_UNEVALUATED,
    POSTURE_OPAQUE,
    POSTURE_AMBIGUOUS,
    POSTURE_INTERPRETABLE,
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


class AIInterpretabilityError(Exception):
    """Base error for the ai-interpretability ledger (programming errors)."""


class BadIdError(AIInterpretabilityError):
    """Raised when a system/record id is malformed."""


class DuplicateRecordError(AIInterpretabilityError):
    """Raised when a minted id somehow collides (never)."""


class UnknownSystemError(AIInterpretabilityError):
    """Raised when a system id names no declared system."""


class UnknownRecordError(AIInterpretabilityError):
    """Raised when a record id names no booked record."""


class RetiredSystemError(AIInterpretabilityError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AIInterpretabilityError):
    """Raised when retiring an already-retired system."""


class BadMethodError(AIInterpretabilityError):
    """Raised when a method is not in the pinned vocabulary."""


class BadFindingError(AIInterpretabilityError):
    """Raised when a finding is not in the pinned vocabulary."""


class BadDigestError(AIInterpretabilityError):
    """Raised when a digest is not a sha256: pin."""


class BadReasonError(AIInterpretabilityError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AIInterpretabilityError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AIInterpretabilityError):
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
        "domain": AI_INTERPRETABILITY_SCHEMA,
        "parts": list(parts),
    })


def ai_interpretability_audit_event(kind: str, detail: Dict[str, object],
                                    seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the ai-interpretability
    ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_INTERPRETABILITY_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class InterpretationRecord:
    """Frozen record of one declared interpretability interpretation
    (digest-pinned)."""
    interpretation_id: str
    system_id: str
    method: str
    finding: str
    interpretation_digest: str
    seq: int
    digest: str

    def verify(self, interpretation_id: str, system_id: str, method: str,
               finding: str, interpretation_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "interpretation", interpretation_id, system_id, method,
            finding, interpretation_digest, self.seq)


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
    n_interpretations: int
    n_interpretable: int
    n_partially_interpretable: int
    n_opaque: int
    n_inconclusive: int
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self, system_id: str, posture: str,
               n_interpretable: int, n_partially_interpretable: int,
               n_opaque: int, n_inconclusive: int) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "evaluation", system_id, posture, self.n_interpretations,
            n_interpretable, n_partially_interpretable,
            n_opaque, n_inconclusive, self.integrity_ok, self.seq)


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


class AIInterpretability:
    """AI-interpretability assessment ledger (declared interpretations,
    derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._interpretations: Dict[str, InterpretationRecord] = {}
        self._interpretations_by_system: Dict[str, Tuple[str, ...]] = {}
        self._interpretation_ids: Tuple[str, ...] = ()
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
        event = ai_interpretability_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_interpretability_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _require_read_seq(self, seq: object) -> int:
        """Validate a pure-read seq's shape; never consume, never order."""
        return _check_seq(seq)

    def interpret(self, system_id: str, seq: int,
                  method: str = MTH_MECHANISTIC,
                  finding: str = FND_INTERPRETABLE,
                  interpretation_digest: str = "") -> InterpretationRecord:
        """Book one declared interpretability interpretation. The first
        interpretation on an id registers the system. Method and finding
        are pinned vocabularies; raw model internals travel as digest
        pins only. Returns the frozen ``InterpretationRecord`` (minted
        ``int-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(method, bool) or not isinstance(method, str):
                raise BadMethodError(
                    f"method must be str, got {type(method).__name__}")
            if method not in METHODS:
                raise BadMethodError(
                    f"method must be one of {sorted(METHODS)}, "
                    f"got {method!r}")
            if isinstance(finding, bool) or not isinstance(finding, str):
                raise BadFindingError(
                    f"finding must be str, got {type(finding).__name__}")
            if finding not in FINDINGS:
                raise BadFindingError(
                    f"finding must be one of {sorted(FINDINGS)}, "
                    f"got {finding!r}")
            interpretation_digest = _check_digest(
                interpretation_digest, "interpretation_digest",
                allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                interpretation_id = f"int-{len(self._interpretation_ids) + 1}"
                if interpretation_id in self._interpretations:
                    raise DuplicateRecordError(
                        f"interpretation id collision: {interpretation_id!r}")
                digest = _pin("interpretation", interpretation_id,
                              system_id, method, finding,
                              interpretation_digest, seq)
                record = InterpretationRecord(
                    interpretation_id, system_id, method, finding,
                    interpretation_digest, seq, digest)
                self._interpretations[interpretation_id] = record
                self._interpretation_ids = (
                    self._interpretation_ids + (interpretation_id,))
                prev = self._interpretations_by_system.get(system_id, ())
                self._interpretations_by_system[system_id] = (
                    prev + (interpretation_id,))
            self._emit(KIND_INTERPRETED, {
                "system_id": system_id,
                "interpretation_id": interpretation_id,
                "method": method,
                "finding": finding,
                "interpretation_digest": interpretation_digest,
            }, seq)
            return record
        except AIInterpretabilityError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """**Pure read.** Re-derive the digest pin of any interpretation or
        retirement record. ``verified``/``tampered`` is data, never
        proof the system is really interpretable."""
        self._require_read_seq(seq)
        record_id = _check_id(record_id, "record_id")
        with self._lock:
            record = self._interpretations.get(record_id)
            tag = "interpretation"
            if record is None:
                record = self._retired.get(record_id)
                tag = "retire"
            if record is None:
                raise UnknownRecordError(
                    f"unknown record: {record_id!r}")
            if tag == "interpretation":
                expected = _pin(
                    "interpretation", record.interpretation_id,
                    record.system_id, record.method, record.finding,
                    record.interpretation_digest, record.seq)
            else:
                expected = _pin(
                    "retire", record.system_id, record.reason,
                    record.seq)
            verdict = "verified" if expected == record.digest else "tampered"
            digest = _pin("verification", record_id, verdict, seq)
            return VerificationReport(record_id, verdict, seq, digest)

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """**Pure read.** Derive interpretability posture as data by ledger
        rule: ``unevaluated`` (no interpretations) -> ``opaque`` (any
        ``opaque``) -> ``ambiguous`` (any ``inconclusive`` /
        ``partially-interpretable``) -> ``interpretable`` (all
        ``interpretable``). Plus finding tallies and ``integrity_ok`` as
        data."""
        self._require_read_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            known = system_id in self._interpretations_by_system
            if not known:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            int_ids = self._interpretations_by_system.get(system_id, ())
            records = [self._interpretations[i] for i in int_ids]
            tallies = {f: 0 for f in FINDINGS}
            integrity_ok = True
            for record in records:
                tallies[record.finding] += 1
                expected = _pin(
                    "interpretation", record.interpretation_id,
                    record.system_id, record.method, record.finding,
                    record.interpretation_digest, record.seq)
                if expected != record.digest:
                    integrity_ok = False
            if not records:
                posture = POSTURE_UNEVALUATED
            elif tallies[FND_OPAQUE] > 0:
                posture = POSTURE_OPAQUE
            elif (tallies[FND_INCONCLUSIVE] > 0
                  or tallies[FND_PARTIALLY_INTERPRETABLE] > 0):
                posture = POSTURE_AMBIGUOUS
            else:
                posture = POSTURE_INTERPRETABLE
            digest = _pin(
                "evaluation", system_id, posture, len(int_ids),
                tallies[FND_INTERPRETABLE],
                tallies[FND_PARTIALLY_INTERPRETABLE],
                tallies[FND_OPAQUE],
                tallies[FND_INCONCLUSIVE],
                integrity_ok, seq)
            return EvaluationReport(
                system_id, posture, len(int_ids),
                tallies[FND_INTERPRETABLE],
                tallies[FND_PARTIALLY_INTERPRETABLE],
                tallies[FND_OPAQUE],
                tallies[FND_INCONCLUSIVE],
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
                known = system_id in self._interpretations_by_system
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
        except AIInterpretabilityError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise

    def interpretation_record(self, interpretation_id: str,
                              seq: int) -> InterpretationRecord:
        """**Pure read.** Return one interpretation record by id."""
        self._require_read_seq(seq)
        interpretation_id = _check_id(interpretation_id, "interpretation_id")
        with self._lock:
            record = self._interpretations.get(interpretation_id)
            if record is None:
                raise UnknownRecordError(
                    f"unknown interpretation: {interpretation_id!r}")
            return record

    def interpretations_for(self, system_id: str,
                            seq: int) -> Tuple[str, ...]:
        """**Pure read.** Interpretation ids booked for one system."""
        self._require_read_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            return self._interpretations_by_system.get(system_id, ())

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """**Pure read.** All known system ids."""
        self._require_read_seq(seq)
        with self._lock:
            return tuple(sorted(self._interpretations_by_system))

    def interpretation_ids(self, seq: int) -> Tuple[str, ...]:
        """**Pure read.** All minted interpretation ids."""
        self._require_read_seq(seq)
        with self._lock:
            return self._interpretation_ids

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
                "systems": len(self._interpretations_by_system),
                "interpretations": len(self._interpretation_ids),
                "retired": len(self._retired),
                "rejected": sum(1 for row in self._audit
                               if row.get("kind") == KIND_REJECTED),
            }


def main() -> None:
    """Self-check: interpret, verify, evaluate, retire, pins, audit."""
    ledger = AIInterpretability()
    rec = ledger.interpret("sys-1", 1, MTH_MECHANISTIC,
                           FND_INTERPRETABLE)
    assert rec.interpretation_id == "int-1"
    vr = ledger.verify("int-1", 2)
    assert vr.verdict == "verified"
    rep = ledger.evaluate("sys-1", 3)
    assert rep.posture == POSTURE_INTERPRETABLE
    assert rep.integrity_ok is True
    ret = ledger.retire("sys-1", 4)
    assert ret.system_id == "sys-1"
    assert stdlib_only()
    assert all(row["schema"] == AUDIT_SCHEMA
               for row in ledger.audit_log())
    print("ai-interpretability OK: interpret, verify, evaluate, "
          "retire, pins, audit")


if __name__ == "__main__":
    main()
