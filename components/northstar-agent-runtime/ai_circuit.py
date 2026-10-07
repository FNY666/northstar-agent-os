"""AI circuit (analyze/verify/evaluate) interface, simulated.

Research motivation: mechanistic interpretability -- identifying the
computational subgraphs (circuits) responsible for a model's observed
behavior -- reduces to one operational shape: the host declares a
circuit-analysis outcome over a pinned circuit-kind vocabulary, the
ledger pins it, and a report derives posture *from the ledger* -- the
report never independently judges whether the identified circuit is
real or causally responsible.

This module is the *AI-circuit* ledger half of that shape:

- ``AICircuit.analyze(system_id, circuit_kind, verdict, seq,
  circuit_digest="")`` -- book one declared circuit analysis over the
  pinned 8-kind vocabulary x the pinned 5-verdict vocabulary. The
  analyzed material is pinned by ``sha256:`` digest only; raw
  activations, weights, attention patterns, or traces never enter a
  record. First analyze on an id registers the system.
- ``AICircuit.verify(circuit_id, seq)`` -- **pure read**
  (seq shape validated, never consumed, no audit row). Re-derives the
  digest pin; the ``verified``/``tampered`` verdict is *data*, never
  proof the circuit was really found or is causally efficacious.
- ``AICircuit.evaluate(system_id, seq)`` -- **pure read**. Derives
  posture as data by ledger rule: ``unanalyzed`` (no analyses) ->
  ``not-identified`` (any ``not-found``) -> ``contested`` (any
  ``inconclusive``) -> ``partially-identified`` (any ``partial``) ->
  ``identified`` (all ``identified``), plus verdict tallies and
  ``integrity_ok`` as data.
- ``AICircuit.retire(system_id, seq, reason="manual")`` --
  terminal. Ids are never recycled; post-retire mutations are refused,
  reads still work.
- Pure-read views (``circuit_record`` / ``circuits_for`` /
  ``system_ids`` / ``retired_ids`` / ``stats`` / ``audit_log``) --
  seq shape validated, never consumed, no audit rows.
- ``ai_circuit_audit_event(kind, ...)`` -- ``audit.ndjson/1`` rows
  (``analyzed`` / ``retired`` / ``rejected``); caller-supplied seqs
  only. Raw analysis material never crosses the audit boundary --
  audit rows carry ids, pinned circuit-kind/verdict labels, digests,
  and counts only.

Distinct layer: ``mechanistic.py`` owns circuit-level analysis
*mechanics* (how analyses run); ``interpretability.py`` owns
prediction-level explainability; ``circuit.py`` / ``circuit_breaker.py``
own runtime circuit-breaker mechanics; ``ai_interpretability.py`` owns
interpretability provision declarations. This module owns the AI
*circuit-analysis declaration* lifecycle none of them cover -- declared
analyses against pinned circuit kinds, declared verdicts, ledger-rule
posture.

Fail-closed edges (fail loudly, never guess):

- ``system_id`` / ``circuit_id`` must be non-empty str, <= 256
  chars, no whitespace.
- ``circuit_kind`` must be in the pinned 8-kind vocabulary;
  ``verdict`` must be in the pinned 5-verdict vocabulary.
- ``circuit_digest`` must be ``sha256:<64hex>`` when supplied
  (may be empty).
- ``analyze`` / ``verify`` on unknown ids raise; duplicate ids never
  occur (ids are minted ``crc-N``).
- ``analyze`` on a retired system raises ``RetiredSystemError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *declared* circuit analyses reported by the host.
  A booked ``identified`` verdict means the host declared one -- the
  module analyzed nothing, measured nothing, and proves nothing about
  any real model's internals, circuits, or causal mechanisms.
- Digest pins prove ledger integrity and ordering, never the truth of
  any declared circuit finding or the competence of any analyzer.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if circuit-analysis state must survive a restart.
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
AI_CIRCUIT_VERSION = "ai-circuit.v1"

#: Schema pin carried by records and audit events.
AI_CIRCUIT_SCHEMA = "northstar.ai-circuit.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_ANALYZED = "analyzed"
KIND_RETIRED = "retired"
KIND_REJECTED = "rejected"
_KINDS = (KIND_ANALYZED, KIND_RETIRED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw material never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"activations", "logits", "weights", "attention_pattern",
     "attention_weights", "neuron_state", "feature_vector", "sae_features",
     "residual_stream", "prompt", "input_tokens", "completions",
     "gradient", "hessian", "probe_results", "ablation_results",
     "patch_results", "intervention", "intervention_trace",
     "mechanistic_trace", "circuit_trace", "model_output", "transcript",
     "dataset", "evidence", "finding", "analysis", "report", "content",
     "text", "payload", "raw", "trace", "data", "record", "note"})

#: Max id length.
_MAX_ID_LEN = 256

#: Pinned circuit-kind vocabulary (mechanistic interpretability shaped).
KIND_INDUCTION_HEAD = "induction-head"
KIND_IOI_CIRCUIT = "ioi-circuit"
KIND_GREATER_THAN_CIRCUIT = "greater-than-circuit"
KIND_COPY_CIRCUIT = "copy-circuit"
KIND_FACTUAL_RECALL = "factual-recall"
KIND_ATTENTION_HEAD = "attention-head"
KIND_MLP_NEURON = "mlp-neuron"
KIND_FEATURE_MAP = "feature-map"
CIRCUIT_KINDS = (
    KIND_INDUCTION_HEAD,
    KIND_IOI_CIRCUIT,
    KIND_GREATER_THAN_CIRCUIT,
    KIND_COPY_CIRCUIT,
    KIND_FACTUAL_RECALL,
    KIND_ATTENTION_HEAD,
    KIND_MLP_NEURON,
    KIND_FEATURE_MAP,
)

#: Pinned circuit verdict vocabulary. Verdicts are host-reported data.
VERDICT_IDENTIFIED = "identified"
VERDICT_PARTIAL = "partial"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_FOUND = "not-found"
VERDICT_NOT_ANALYZED = "not-analyzed"
VERDICTS = (
    VERDICT_IDENTIFIED,
    VERDICT_PARTIAL,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_FOUND,
    VERDICT_NOT_ANALYZED,
)

#: Pinned derived postures (ledger rule, precedence documented in evaluate).
POSTURE_UNANALYZED = "unanalyzed"
POSTURE_NOT_IDENTIFIED = "not-identified"
POSTURE_CONTESTED = "contested"
POSTURE_PARTIALLY_IDENTIFIED = "partially-identified"
POSTURE_IDENTIFIED = "identified"
POSTURES = (
    POSTURE_UNANALYZED,
    POSTURE_NOT_IDENTIFIED,
    POSTURE_CONTESTED,
    POSTURE_PARTIALLY_IDENTIFIED,
    POSTURE_IDENTIFIED,
)

#: Pinned retire reasons.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_SCOPE_CHANGE = "scope-change"
REASON_ANALYSIS_LOSS = "analysis-loss"
REASONS = (
    REASON_MANUAL,
    REASON_DECOMMISSIONED,
    REASON_SCOPE_CHANGE,
    REASON_ANALYSIS_LOSS,
)

#: Digest pin shape: "sha256:" + 64 lowercase hex.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AICircuitError(Exception):
    """Base error for the AI-circuit ledger (programming errors)."""


class BadIdError(AICircuitError):
    """Raised when a system/circuit id is malformed."""


class DuplicateCircuitError(AICircuitError):
    """Raised when a minted circuit id somehow collides (never)."""


class UnknownSystemError(AICircuitError):
    """Raised when a system id names no analyzed system."""


class UnknownCircuitError(AICircuitError):
    """Raised when a circuit id names no booked analysis."""


class RetiredSystemError(AICircuitError):
    """Raised when mutating a retired system."""


class DoubleRetireError(AICircuitError):
    """Raised when retiring an already-retired system."""


class BadCircuitKindError(AICircuitError):
    """Raised when a circuit kind is not in the pinned vocabulary."""


class BadVerdictError(AICircuitError):
    """Raised when a verdict is not in the pinned vocabulary."""


class BadDigestError(AICircuitError):
    """Raised when a circuit digest is not a sha256: pin."""


class BadReasonError(AICircuitError):
    """Raised when a retire reason is not in the pinned vocabulary."""


class SeqOrderError(AICircuitError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AICircuitError):
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
        "domain": AI_CIRCUIT_SCHEMA,
        "parts": list(parts),
    })


def ai_circuit_audit_event(kind: str, detail: Dict[str, object],
                           seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the AI-circuit ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AI_CIRCUIT_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


@dataclass(frozen=True)
class CircuitRecord:
    """Frozen record of one declared circuit analysis (digest-pinned)."""
    circuit_id: str
    system_id: str
    circuit_kind: str
    verdict: str
    circuit_digest: str
    seq: int
    digest: str

    def verify(self, circuit_id: str, system_id: str, circuit_kind: str,
               verdict: str, circuit_digest: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "circuit", circuit_id, system_id, circuit_kind,
            verdict, circuit_digest, self.seq)


@dataclass(frozen=True)
class VerificationReport:
    """Frozen read-only report of a digest re-derivation (verdict as data)."""
    circuit_id: str
    verdict: str
    seq: int
    digest: str

    def verify(self, circuit_id: str, verdict: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin(
            "verification", circuit_id, verdict, self.seq)


@dataclass(frozen=True)
class EvaluationReport:
    """Frozen read-only report of ledger-rule posture (posture as data)."""
    system_id: str
    posture: str
    n_circuits: int
    n_identified: int
    n_partial: int
    n_inconclusive: int
    n_not_found: int
    n_not_analyzed: int
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


class AICircuit:
    """AI-circuit ledger (declared circuit analyses, derived posture)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._circuits: Dict[str, CircuitRecord] = {}
        self._by_system: Dict[str, Tuple[str, ...]] = {}
        self._circuit_ids: Tuple[str, ...] = ()
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
        event = ai_circuit_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append an audit event (caller has already claimed the seq)."""
        event = ai_circuit_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def analyze(self, system_id: str, circuit_kind: str, verdict: str,
                seq: int, circuit_digest: str = "") -> CircuitRecord:
        """Book one declared circuit analysis. First analyze on an id
        registers the system. Pins the circuit digest, never the raw
        analysis material. Returns the frozen ``CircuitRecord`` (minted
        ``crc-N``)."""
        self._claim(seq)
        try:
            system_id = _check_id(system_id, "system_id")
            if isinstance(circuit_kind, bool) or not isinstance(
                    circuit_kind, str):
                raise BadCircuitKindError(
                    f"circuit_kind must be str, got "
                    f"{type(circuit_kind).__name__}")
            if circuit_kind not in CIRCUIT_KINDS:
                raise BadCircuitKindError(
                    f"circuit_kind must be one of "
                    f"{sorted(CIRCUIT_KINDS)}, got {circuit_kind!r}")
            if isinstance(verdict, bool) or not isinstance(verdict, str):
                raise BadVerdictError(
                    f"verdict must be str, got {type(verdict).__name__}")
            if verdict not in VERDICTS:
                raise BadVerdictError(
                    f"verdict must be one of {sorted(VERDICTS)}, "
                    f"got {verdict!r}")
            circuit_digest = _check_digest(
                circuit_digest, "circuit_digest", allow_empty=True)
            with self._lock:
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system is retired: {system_id!r}")
                circuit_id = f"crc-{len(self._circuit_ids) + 1}"
                if circuit_id in self._circuits:
                    raise DuplicateCircuitError(
                        f"circuit id collision: {circuit_id!r}")
                record = CircuitRecord(
                    circuit_id=circuit_id,
                    system_id=system_id,
                    circuit_kind=circuit_kind,
                    verdict=verdict,
                    circuit_digest=circuit_digest,
                    seq=seq,
                    digest=_pin("circuit", circuit_id, system_id,
                                circuit_kind, verdict, circuit_digest,
                                seq),
                )
                self._circuits[circuit_id] = record
                self._circuit_ids = self._circuit_ids + (circuit_id,)
                self._by_system[system_id] = (
                    self._by_system.get(system_id, ()) + (circuit_id,))
        except AICircuitError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_ANALYZED,
                   {"system_id": system_id,
                    "circuit_id": record.circuit_id,
                    "circuit_kind": circuit_kind,
                    "verdict": verdict,
                    "circuit_digest": circuit_digest}, seq)
        return record

    def verify(self, circuit_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a circuit analysis's digest pin. The
        ``verified``/``tampered`` verdict is *data* (tamper reported,
        never raised). Validates seq shape, consumes nothing, writes no
        audit row. Returns the frozen ``VerificationReport``."""
        _check_seq(seq)
        circuit_id = _check_id(circuit_id, "circuit_id")
        with self._lock:
            if circuit_id not in self._circuits:
                raise UnknownCircuitError(
                    f"unknown circuit: {circuit_id!r}")
            rec = self._circuits[circuit_id]
            intact = rec.verify(
                rec.circuit_id, rec.system_id, rec.circuit_kind,
                rec.verdict, rec.circuit_digest)
            verdict = "verified" if intact else "tampered"
            return VerificationReport(
                circuit_id=circuit_id,
                verdict=verdict,
                seq=seq,
                digest=_pin("verification", circuit_id, verdict, seq),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive posture from the ledger by rule (precedence:
        any ``not-found`` -> ``not-identified``; any ``inconclusive`` ->
        ``contested``; any ``partial`` -> ``partially-identified``; all
        ``identified`` -> ``identified``; any remaining ``not-analyzed``
        without the above -> ``partially-identified``). Validates seq
        shape, consumes nothing, writes no audit row. Returns the frozen
        ``EvaluationReport``."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            ids = self._by_system[system_id]
            recs = [self._circuits[i] for i in ids]
            n_identified = sum(
                1 for r in recs if r.verdict == VERDICT_IDENTIFIED)
            n_partial = sum(
                1 for r in recs if r.verdict == VERDICT_PARTIAL)
            n_inconclusive = sum(
                1 for r in recs if r.verdict == VERDICT_INCONCLUSIVE)
            n_not_found = sum(
                1 for r in recs if r.verdict == VERDICT_NOT_FOUND)
            n_not_analyzed = sum(
                1 for r in recs if r.verdict == VERDICT_NOT_ANALYZED)
            integrity_ok = all(
                r.verify(r.circuit_id, r.system_id, r.circuit_kind,
                         r.verdict, r.circuit_digest) for r in recs)
            if n_not_found:
                posture = POSTURE_NOT_IDENTIFIED
            elif n_inconclusive:
                posture = POSTURE_CONTESTED
            elif n_partial or n_not_analyzed:
                posture = POSTURE_PARTIALLY_IDENTIFIED
            else:
                posture = POSTURE_IDENTIFIED
            return EvaluationReport(
                system_id=system_id,
                posture=posture,
                n_circuits=len(recs),
                n_identified=n_identified,
                n_partial=n_partial,
                n_inconclusive=n_inconclusive,
                n_not_found=n_not_found,
                n_not_analyzed=n_not_analyzed,
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
        except AICircuitError:
            self._burn(seq, system_id if isinstance(system_id, str) else "")
            raise
        self._emit(KIND_RETIRED,
                   {"system_id": system_id, "reason": reason}, seq)
        return record

    def circuit_record(self, circuit_id: str, seq: int) -> CircuitRecord:
        """Pure read view of one booked circuit analysis."""
        _check_seq(seq)
        circuit_id = _check_id(circuit_id, "circuit_id")
        with self._lock:
            if circuit_id not in self._circuits:
                raise UnknownCircuitError(
                    f"unknown circuit: {circuit_id!r}")
            return self._circuits[circuit_id]

    def circuits_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read view of circuit ids for one system, in book order."""
        _check_seq(seq)
        system_id = _check_id(system_id, "system_id")
        with self._lock:
            if system_id not in self._by_system:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return self._by_system[system_id]

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read view of all registered system ids, in first-analyze order."""
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
                "circuits": len(self._circuits),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }


def main() -> None:
    """Self-check: analyze, verify, evaluate, retire, pins, audit."""
    ac = AICircuit()
    assert AI_CIRCUIT_VERSION == "ai-circuit.v1"
    assert AI_CIRCUIT_SCHEMA == "northstar.ai-circuit.v1"
    assert stdlib_only()
    digest = "sha256:" + "0" * 64
    rec = ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
                     digest)
    assert rec.circuit_id == "crc-1"
    assert rec.verify("crc-1", "sys-1", KIND_INDUCTION_HEAD,
                      VERDICT_IDENTIFIED, digest)
    assert not rec.verify("crc-1", "sys-1", KIND_INDUCTION_HEAD,
                          VERDICT_NOT_FOUND, digest)
    vr = ac.verify("crc-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("crc-1", "verified")
    ev = ac.evaluate("sys-1", 3)
    assert ev.posture == POSTURE_IDENTIFIED
    assert ev.integrity_ok
    assert ev.verify("sys-1", POSTURE_IDENTIFIED)
    ac.analyze("sys-1", KIND_IOI_CIRCUIT, VERDICT_NOT_FOUND, 4, digest)
    ev = ac.evaluate("sys-1", 5)
    assert ev.posture == POSTURE_NOT_IDENTIFIED
    assert ev.n_circuits == 2 and ev.n_not_found == 1
    rr = ac.retire("sys-1", 6)
    assert rr.verify("sys-1", REASON_MANUAL)
    try:
        ac.analyze("sys-1", KIND_MLP_NEURON, VERDICT_IDENTIFIED, 7)
    except RetiredSystemError:
        pass
    else:
        raise AssertionError("analyze on retired system must fail closed")
    assert ac.stats()["systems"] == 1
    kinds = [row["kind"] for row in ac.audit_log()]
    assert kinds == [KIND_ANALYZED, KIND_ANALYZED, KIND_RETIRED,
                     KIND_REJECTED]
    print("ai-circuit OK: analyze, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
