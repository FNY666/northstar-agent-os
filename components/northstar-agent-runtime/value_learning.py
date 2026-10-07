"""Value learning decision ledger, Simulated.

Research note: value learning (Russell's program) asks whether an agent can
infer a principal's values from observed behavior: demonstrations, stated
preferences, corrections, interventions, revealed choices, cooperation
signals. Inverse reinforcement learning, Bayesian IRL, and preference
inference are the canonical formal tools. The dangerous half of a value
learning pipeline is the raw material: behavior traces, trajectories,
human utterances, demonstration recordings, preference labels. Those must
never be bundled with the bookkeeping record that tracks the learning.

This module is that bookkeeping layer. It:

* **observe()** - book one declared behavioral observation (minted ``obs-N``
  ids) over a pinned observation-kind vocabulary; the first observation on
  an id registers the subject; raw behavioral material travels as
  ``sha256:`` digest pins only.
* **infer()** - book one declared value inference (minted ``inf-N`` ids)
  from booked observations over a pinned inference-method vocabulary and a
  pinned value-claim vocabulary; the declared value claim is data, never
  proof of the subject's real values.
* **verify()** - pure-read digest re-derivation of one booked inference
  (verdict ``consistent`` / ``tampered``), as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``value-learning.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked observation means a host declared it happened; a
booked ``inf-N`` means a host declared an inference result - it proves
nothing about the subject's actual values; a ``consistent`` verify verdict
means the ledger's digest pins line up, never that the inference was
correct; no behavior is recorded, no model is trained here.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
VALUE_LEARNING_VERSION = "value-learning.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.value-learning.v1"

#: Pinned observation-kind vocabulary (declared, never proof a real
#: observation happened).
OBSERVATION_KINDS = (
    "demonstration",
    "preference-comparison",
    "correction",
    "intervention",
    "stated-value",
    "revealed-choice",
    "feedback",
    "cooperation-signal",
)

#: Pinned inference-method vocabulary (declared, never proof a real
#: inference ran).
INFER_METHODS = (
    "inverse-rl",
    "bayesian-irl",
    "preference-inference",
    "reward-modeling",
    "imitative-inference",
    "stated-aggregation",
    "cooperative-inference",
    "meta-inference",
)

#: Pinned value-claim vocabulary (declared, never measured truth about a
#: subject's values).
VALUE_CLAIMS = (
    "helpfulness",
    "harmlessness",
    "honesty",
    "obedience",
    "fidelity",
    "autonomy",
    "fairness",
    "care",
)

#: Pinned verify verdicts.
VERIFY_VERDICTS = (
    "consistent",
    "tampered",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "observed",
    "inferred",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "behavior",
        "behaviors",
        "trajectory",
        "trajectories",
        "demonstration",
        "demonstrations",
        "utterance",
        "utterances",
        "transcript",
        "text",
        "content",
        "data",
        "raw",
        "notes",
        "note",
        "evidence",
        "prompt",
        "response",
        "preference",
        "preferences",
        "labels",
        "label",
        "weights",
        "model",
        "values",
        "value",
        "detail",
        "details",
        "description",
        "secret",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ValueLearningError(Exception):
    """Base error for value-learning-ledger misuse."""


class BadIdError(ValueLearningError):
    """Malformed subject / observation / inference id."""


class BadDigestError(ValueLearningError):
    """Malformed sha256: digest pin."""


class BadKindError(ValueLearningError):
    """Observation kind outside the pinned vocabulary."""


class BadMethodError(ValueLearningError):
    """Inference method outside the pinned vocabulary."""


class BadClaimError(ValueLearningError):
    """Value claim outside the pinned vocabulary."""


class BadConfidenceError(ValueLearningError):
    """Confidence outside the host-reported [0, 100] int range."""


class UnknownSubjectError(ValueLearningError):
    """Reference to a subject id that was never registered."""


class UnknownObservationError(ValueLearningError):
    """Reference to an observation id that was never booked."""


class UnknownInferenceError(ValueLearningError):
    """Reference to an inference id that was never booked."""


class NoObservationError(ValueLearningError):
    """Inference requested for a subject with no booked observations."""


class SeqOrderError(ValueLearningError):
    """Caller seq did not strictly increase."""


class AuditKindError(ValueLearningError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _require_confidence(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadConfidenceError("confidence must be an int")
    if not 0 <= value <= 100:
        raise BadConfidenceError("confidence must be in [0, 100]")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservationRecord:
    """One declared behavioral observation (minted obs-N ids)."""

    observation_id: str
    subject_id: str
    observation_kind: str
    observation_digest: str
    context_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "observation_id": self.observation_id,
            "subject_id": self.subject_id,
            "observation_kind": self.observation_kind,
            "observation_digest": self.observation_digest,
            "context_digest": self.context_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "observation_id": self.observation_id,
                "subject_id": self.subject_id,
                "observation_kind": self.observation_kind,
                "observation_digest": self.observation_digest,
                "context_digest": self.context_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class InferenceRecord:
    """One declared value inference (minted inf-N ids)."""

    inference_id: str
    subject_id: str
    method: str
    value_claim: str
    confidence: int
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "inference_id": self.inference_id,
            "subject_id": self.subject_id,
            "method": self.method,
            "value_claim": self.value_claim,
            "confidence": self.confidence,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "inference_id": self.inference_id,
                "subject_id": self.subject_id,
                "method": self.method,
                "value_claim": self.value_claim,
                "confidence": self.confidence,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Derived verify verdict for one booked inference (pure read, as data)."""

    inference_id: str
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "inference_id": self.inference_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "inference_id": self.inference_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


def value_learning_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the value-learning ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class ValueLearning:
    """Value-learning decision ledger (Simulated).

    ``observe()`` / ``infer()`` mutate the ledger and consume caller seqs;
    ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._observations: Dict[str, ObservationRecord] = {}
        self._subject_observations: Dict[str, List[str]] = {}
        self._inferences: Dict[str, InferenceRecord] = {}
        self._subject_inferences: Dict[str, List[str]] = {}
        self._obs_counter = 0
        self._inf_counter = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = value_learning_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(
            value_learning_audit_event(audit_kind, seq, **details)
        )

    # -- observe ------------------------------------------------------------

    def observe(
        self,
        subject_id: str,
        seq: int,
        observation_kind: str = "demonstration",
        observation_digest: str = "",
        context_digest: str = "",
    ) -> ObservationRecord:
        """Book one declared behavioral observation.

        The first observation on an id registers the subject. Raw behavioral
        material never enters records (digest pins only).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(subject_id, "subject_id")
                if observation_kind not in OBSERVATION_KINDS:
                    raise BadKindError(
                        f"bad observation kind: {observation_kind!r}"
                    )
                observation_digest = _require_optional_digest(
                    observation_digest, "observation_digest"
                )
                context_digest = _require_optional_digest(
                    context_digest, "context_digest"
                )
                self._obs_counter += 1
                observation_id = f"obs-{self._obs_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "observation_id": observation_id,
                        "subject_id": subject_id,
                        "observation_kind": observation_kind,
                        "observation_digest": observation_digest,
                        "context_digest": context_digest,
                        "seq": seq,
                    }
                )
                record = ObservationRecord(
                    observation_id=observation_id,
                    subject_id=subject_id,
                    observation_kind=observation_kind,
                    observation_digest=observation_digest,
                    context_digest=context_digest,
                    seq=seq,
                    digest=digest,
                )
                self._observations[observation_id] = record
                self._subject_observations.setdefault(subject_id, []).append(
                    observation_id
                )
                self._emit(
                    "observed",
                    seq,
                    observation_id=observation_id,
                    subject_id=subject_id,
                    observation_kind=observation_kind,
                )
                return record
            except ValueLearningError:
                self._burn(seq, "observe")
                raise

    # -- infer --------------------------------------------------------------

    def infer(
        self,
        subject_id: str,
        seq: int,
        method: str = "inverse-rl",
        value_claim: str = "helpfulness",
        confidence: int = 0,
        evidence_digest: str = "",
    ) -> InferenceRecord:
        """Book one declared value inference for a subject.

        Fail-closed: the subject must carry at least one booked observation.
        The declared value claim is data, never proof of the subject's real
        values.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(subject_id, "subject_id")
                if method not in INFER_METHODS:
                    raise BadMethodError(f"bad method: {method!r}")
                if value_claim not in VALUE_CLAIMS:
                    raise BadClaimError(f"bad value claim: {value_claim!r}")
                confidence = _require_confidence(confidence)
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                if not self._subject_observations.get(subject_id):
                    raise NoObservationError(
                        f"subject has no booked observations: {subject_id!r}"
                    )
                self._inf_counter += 1
                inference_id = f"inf-{self._inf_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "inference_id": inference_id,
                        "subject_id": subject_id,
                        "method": method,
                        "value_claim": value_claim,
                        "confidence": confidence,
                        "evidence_digest": evidence_digest,
                        "seq": seq,
                    }
                )
                record = InferenceRecord(
                    inference_id=inference_id,
                    subject_id=subject_id,
                    method=method,
                    value_claim=value_claim,
                    confidence=confidence,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=digest,
                )
                self._inferences[inference_id] = record
                self._subject_inferences.setdefault(subject_id, []).append(
                    inference_id
                )
                self._emit(
                    "inferred",
                    seq,
                    inference_id=inference_id,
                    subject_id=subject_id,
                    method=method,
                    value_claim=value_claim,
                )
                return record
            except ValueLearningError:
                self._burn(seq, "infer")
                raise

    # -- verify (pure read) --------------------------------------------------

    def verify(self, inference_id: str, seq: int) -> VerificationReport:
        """Pure-read digest re-derivation for one booked inference, as data.

        Verdict is ``consistent`` when the stored digest pins line up with a
        re-derivation, else ``tampered``; the verdict describes the ledger,
        never the truth of the inference.
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(inference_id, "inference_id")
            record = self._inferences.get(inference_id)
            if record is None:
                raise UnknownInferenceError(
                    f"unknown inference: {inference_id!r}"
                )
            ok = record.verify()
            verdict = "consistent" if ok else "tampered"
            report = VerificationReport(
                inference_id=inference_id,
                verdict=verdict,
                integrity_ok=ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "inference_id": inference_id,
                        "verdict": verdict,
                        "integrity_ok": ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return report

    # -- views (pure reads) ---------------------------------------------------

    def observation_record(
        self, observation_id: str, seq: int
    ) -> ObservationRecord:
        """Return one observation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(observation_id, "observation_id")
            record = self._observations.get(observation_id)
            if record is None:
                raise UnknownObservationError(
                    f"unknown observation: {observation_id!r}"
                )
            return record

    def inference_record(
        self, inference_id: str, seq: int
    ) -> InferenceRecord:
        """Return one inference record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(inference_id, "inference_id")
            record = self._inferences.get(inference_id)
            if record is None:
                raise UnknownInferenceError(
                    f"unknown inference: {inference_id!r}"
                )
            return record

    def observations_for(self, subject_id: str, seq: int) -> Tuple[str, ...]:
        """Observation ids booked for one subject, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(subject_id, "subject_id")
            if subject_id not in self._subject_observations:
                raise UnknownSubjectError(
                    f"subject never observed: {subject_id!r}"
                )
            return tuple(self._subject_observations[subject_id])

    def inferences_for(self, subject_id: str, seq: int) -> Tuple[str, ...]:
        """Inference ids booked for one subject, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(subject_id, "subject_id")
            return tuple(self._subject_inferences.get(subject_id, ()))

    def subject_ids(self, seq: int) -> Tuple[str, ...]:
        """All subjects with booked observations, in first-observe order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._subject_observations.keys())

    def observation_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked observation ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._observations.keys())

    def inference_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked inference ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._inferences.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "subjects": len(self._subject_observations),
                "observations": len(self._observations),
                "inferences": len(self._inferences),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the value-learning ledger end to end."""
    vl = ValueLearning()
    o1 = vl.observe("sub-1", 1, observation_kind="demonstration")
    assert o1.observation_id == "obs-1"
    assert o1.verify()
    i1 = vl.infer(
        "sub-1", 2, method="inverse-rl", value_claim="helpfulness",
        confidence=80,
    )
    assert i1.inference_id == "inf-1"
    assert i1.verify()
    rep = vl.verify("inf-1", 3)
    assert rep.verdict == "consistent"
    assert rep.integrity_ok
    assert vl.observations_for("sub-1", 4) == ("obs-1",)
    assert vl.stats(5) == {
        "subjects": 1,
        "observations": 1,
        "inferences": 1,
        "rejected": 0,
    }
    print("value-learning OK: observe, infer, verify, pins, audit")


if __name__ == "__main__":
    main()
