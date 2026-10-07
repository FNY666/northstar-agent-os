"""Reward modeling: reward-model governance decision ledger, Simulated.

Research note: reward modeling from human feedback is the backbone of
modern alignment pipelines (Christiano et al., "Deep Reinforcement
Learning from Human Preferences", 2017). A reward model is trained on
host-declared feedback - preference pairs (Bradley & Terry, 1952),
demonstrations, corrections, scalar ratings, rankings - then used to
rank or score outputs (Ouyang et al., "Training Language Models to
Follow Instructions with Human Feedback", 2022; Bai et al.,
"Constitutional AI", 2022; Lightman et al., "Let's Verify Step by
Step", 2023, for process supervision). What matters here is the
*decision ledger*: which feedback was declared collected, which reward
models were declared trained (by which method, with what declared
outcome), and which evaluations were declared against them - defensible
bookkeeping, never proof that any model is aligned.

This module owns the collect -> train -> evaluate lifecycle:

* **collect()** - book one declared feedback-collection batch (minted
  ``col-N`` ids; pinned 6-term feedback-kind vocabulary); the first
  collect registers its dataset. Raw feedback, prompts, responses,
  demonstrations, and scores never enter records - digest pins only.
* **train()** - book one declared reward-model training run (minted
  ``trn-N`` ids; pinned method vocabulary x pinned outcome
  vocabulary), fail-closed on unknown collections; books the
  *declaration*, never the training.
* **evaluate()** - book one declared evaluation of a training run
  (minted ``evl-N`` ids; pinned metric vocabulary; host-reported score
  int in [0, 100]), booked **as data**, never proof the reward model
  is any good.
* **retire()** - terminal retirement of a dataset id; ids are never
  recycled.
* **report()** - pure read: per-dataset collection/training/evaluation
  tallies, lifecycle posture, and digest-pinned integrity, all as
  data.

Distinct-layer rationale: ``rlaif.py`` owns the RLAIF AI-feedback
lifecycle (critique -> prefer -> reward -> train); ``recursive_reward.py``
is a *mechanical* preference ledger - it learns linear weights from
caller-supplied feedback and estimates reward from decomposed subtasks
(reward-modeling *mechanics*); ``reward_hacking.py`` owns the
reward-*hacking* detection lifecycle (test -> detect -> mitigate).
This module performs no learning, computes no loss, and detects no
hacking; it is the reward-modeling *governance* decision ledger none
of them own: declared collection -> declared training -> declared
evaluation.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``reward-modeling.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no training, learns no weights,
measures no agreement, and proves nothing about real reward quality. A
booked ``converged`` outcome means "the host declared it", never "the
model converged". Feedback payloads, weights, gradients, losses,
scores, and raw human labels never enter records or cross the audit
boundary - digest pins only.
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
REWARD_MODELING_VERSION = "reward-modeling.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.reward-modeling.v1"

#: Pinned feedback-kind vocabulary (what was declared collected).
FEEDBACK_KINDS = (
    "preference-pair",
    "demonstration",
    "correction",
    "scalar-rating",
    "ranking",
    "thumbs",
)

#: Pinned reward-model training-method vocabulary.
TRAIN_METHODS = (
    "bradley-terry",
    "regression",
    "dpo-style",
    "rlhf-ppo",
    "constitutional",
    "process-supervision",
)

#: Pinned training-outcome vocabulary (booked as data, never proof).
TRAIN_OUTCOMES = (
    "converged",
    "diverged",
    "not-run",
    "inconclusive",
)

#: Pinned evaluation-metric vocabulary.
EVAL_METRICS = (
    "held-out-agreement",
    "calibration",
    "robustness",
    "ood-generalization",
    "human-correlation",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "collected",
    "trained",
    "evaluated",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row. Pinned vocabulary
#: values (feedback_kind, method, outcome, metric) remain emittable as
#: declared data - only these raw-material keys are banned.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "trajectory",
        "trajectories",
        "action",
        "actions",
        "observation",
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "loss",
        "feedback",
        "preference",
        "preferences",
        "prompt",
        "prompts",
        "response",
        "responses",
        "demonstration",
        "demonstrations",
        "correction",
        "corrections",
        "rating",
        "ranking",
        "thumbs",
        "score",
        "payload",
        "content",
        "text",
        "transcript",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RewardModelingError(Exception):
    """Base error for reward-modeling ledger misuse."""


class BadIdError(RewardModelingError):
    """Malformed dataset, collection, training, or evaluation id."""


class UnknownDatasetError(RewardModelingError):
    """Dataset not registered."""


class RetiredDatasetError(RewardModelingError):
    """Dataset id already retired; never recycled."""


class BadFeedbackKindError(RewardModelingError):
    """Unknown feedback kind."""


class BadDigestError(RewardModelingError):
    """Malformed sha256: digest pin."""


class BadMethodError(RewardModelingError):
    """Unknown reward-model training method."""


class BadOutcomeError(RewardModelingError):
    """Unknown training outcome."""


class UnknownCollectionError(RewardModelingError):
    """Collection id not booked."""


class BadMetricError(RewardModelingError):
    """Unknown evaluation metric."""


class BadScoreError(RewardModelingError):
    """Score is not an int in [0, 100]."""


class UnknownTrainingError(RewardModelingError):
    """Training id not booked."""


class BadReasonError(RewardModelingError):
    """Unknown retirement reason."""


class SeqOrderError(RewardModelingError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(RewardModelingError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_score(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadScoreError(f"{field_name} must be an int, not bool")
    if value < 0 or value > 100:
        raise BadScoreError(f"{field_name} must be in [0, 100]")
    return value


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionRecord:
    collection_id: str
    dataset_id: str
    feedback_kind: str
    feedback_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "collection_id": self.collection_id,
            "dataset_id": self.dataset_id,
            "feedback_kind": self.feedback_kind,
            "feedback_digest": self.feedback_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "collection_id": self.collection_id,
                "dataset_id": self.dataset_id,
                "feedback_kind": self.feedback_kind,
                "feedback_digest": self.feedback_digest,
            }
        )


@dataclass(frozen=True)
class TrainingRecord:
    training_id: str
    collection_id: str
    dataset_id: str
    method: str
    outcome: str
    train_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "training_id": self.training_id,
            "collection_id": self.collection_id,
            "dataset_id": self.dataset_id,
            "method": self.method,
            "outcome": self.outcome,
            "train_digest": self.train_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "training_id": self.training_id,
                "collection_id": self.collection_id,
                "dataset_id": self.dataset_id,
                "method": self.method,
                "outcome": self.outcome,
                "train_digest": self.train_digest,
            }
        )


@dataclass(frozen=True)
class EvaluationRecord:
    evaluation_id: str
    training_id: str
    dataset_id: str
    metric: str
    score: int
    eval_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "evaluation_id": self.evaluation_id,
            "training_id": self.training_id,
            "dataset_id": self.dataset_id,
            "metric": self.metric,
            "score": self.score,
            "eval_digest": self.eval_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "evaluation_id": self.evaluation_id,
                "training_id": self.training_id,
                "dataset_id": self.dataset_id,
                "metric": self.metric,
                "score": self.score,
                "eval_digest": self.eval_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    dataset_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "dataset_id": self.dataset_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "dataset_id": self.dataset_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class ModelingReport:
    dataset_id: str
    n_collections: int
    n_trainings: int
    n_evaluations: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "dataset_id": self.dataset_id,
            "n_collections": self.n_collections,
            "n_trainings": self.n_trainings,
            "n_evaluations": self.n_evaluations,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "dataset_id": self.dataset_id,
                "n_collections": self.n_collections,
                "n_trainings": self.n_trainings,
                "n_evaluations": self.n_evaluations,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def reward_modeling_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the reward-modeling ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class RewardModeling:
    """Reward-model governance decision ledger, Simulated.

    ``collect()`` / ``train()`` / ``evaluate()`` / ``retire()`` mutate
    the ledger and consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._datasets: Dict[str, List[str]] = {}
        self._collections: Dict[str, CollectionRecord] = {}
        self._collections_by_dataset: Dict[str, List[str]] = {}
        self._trainings: Dict[str, TrainingRecord] = {}
        self._trainings_by_collection: Dict[str, List[str]] = {}
        self._trainings_by_dataset: Dict[str, List[str]] = {}
        self._evaluations: Dict[str, EvaluationRecord] = {}
        self._evaluations_by_training: Dict[str, List[str]] = {}
        self._evaluations_by_dataset: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._col_counter = 0
        self._trn_counter = 0
        self._evl_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: RewardModelingError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            reward_modeling_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_known_dataset(self, dataset_id: str) -> None:
        if dataset_id not in self._datasets:
            raise UnknownDatasetError(f"unknown dataset: {dataset_id!r}")

    def _require_live_dataset(self, dataset_id: str) -> None:
        self._require_known_dataset(dataset_id)
        if dataset_id in self._retired:
            raise RetiredDatasetError(f"dataset already retired: {dataset_id!r}")

    # -- mutations --------------------------------------------------------

    def collect(
        self,
        dataset_id: Any,
        seq: Any,
        feedback_kind: Any = "preference-pair",
        feedback_digest: Any = "",
    ) -> CollectionRecord:
        """Book one declared feedback-collection batch (minted ``col-N``).

        The first collect registers its dataset. Feedback payloads
        travel as a digest pin only; raw preferences, prompts,
        responses, and scores never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _require_id(dataset_id, "dataset_id")
                if did in self._retired:
                    raise RetiredDatasetError(f"dataset id never recycled: {did!r}")
                if not isinstance(feedback_kind, str) or feedback_kind not in FEEDBACK_KINDS:
                    raise BadFeedbackKindError(
                        f"feedback_kind must be one of {sorted(FEEDBACK_KINDS)}"
                    )
                pin = _require_digest(feedback_digest, "feedback_digest")
                self._col_counter += 1
                cid = f"col-{self._col_counter}"
                rec = CollectionRecord(
                    collection_id=cid,
                    dataset_id=did,
                    feedback_kind=feedback_kind,
                    feedback_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "collection_id": cid,
                            "dataset_id": did,
                            "feedback_kind": feedback_kind,
                            "feedback_digest": pin,
                        }
                    ),
                )
                self._collections[cid] = rec
                self._datasets.setdefault(did, []).append(cid)
                self._collections_by_dataset.setdefault(did, []).append(cid)
                self._audit.append(
                    reward_modeling_audit_event(
                        "collected",
                        seq_v,
                        collection_id=cid,
                        dataset_id=did,
                        feedback_kind=feedback_kind,
                    )
                )
                return rec
            except RewardModelingError as exc:
                self._burn(seq_v, "collect", exc)
                raise

    def train(
        self,
        collection_id: Any,
        seq: Any,
        method: Any = "bradley-terry",
        outcome: Any = "not-run",
        train_digest: Any = "",
    ) -> TrainingRecord:
        """Book one declared reward-model training run (minted ``trn-N``).

        Outcomes are booked **as data**, never proof that training
        converged (or diverged).
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                cid = _require_id(collection_id, "collection_id")
                col = self._collections.get(cid)
                if col is None:
                    raise UnknownCollectionError(f"unknown collection: {cid!r}")
                self._require_live_dataset(col.dataset_id)
                if not isinstance(method, str) or method not in TRAIN_METHODS:
                    raise BadMethodError(
                        f"method must be one of {sorted(TRAIN_METHODS)}"
                    )
                if not isinstance(outcome, str) or outcome not in TRAIN_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(TRAIN_OUTCOMES)}"
                    )
                pin = _require_digest(train_digest, "train_digest")
                self._trn_counter += 1
                tid = f"trn-{self._trn_counter}"
                rec = TrainingRecord(
                    training_id=tid,
                    collection_id=cid,
                    dataset_id=col.dataset_id,
                    method=method,
                    outcome=outcome,
                    train_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "training_id": tid,
                            "collection_id": cid,
                            "dataset_id": col.dataset_id,
                            "method": method,
                            "outcome": outcome,
                            "train_digest": pin,
                        }
                    ),
                )
                self._trainings[tid] = rec
                self._trainings_by_collection.setdefault(cid, []).append(tid)
                self._trainings_by_dataset.setdefault(col.dataset_id, []).append(tid)
                self._audit.append(
                    reward_modeling_audit_event(
                        "trained",
                        seq_v,
                        training_id=tid,
                        collection_id=cid,
                        dataset_id=col.dataset_id,
                        method=method,
                        outcome=outcome,
                    )
                )
                return rec
            except RewardModelingError as exc:
                self._burn(seq_v, "train", exc)
                raise

    def evaluate(
        self,
        training_id: Any,
        seq: Any,
        metric: Any = "held-out-agreement",
        score: Any = 0,
        eval_digest: Any = "",
    ) -> EvaluationRecord:
        """Book one declared evaluation of a training run (minted ``evl-N``).

        The score is host-reported data in [0, 100], never measured
        agreement.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                tid = _require_id(training_id, "training_id")
                trn = self._trainings.get(tid)
                if trn is None:
                    raise UnknownTrainingError(f"unknown training: {tid!r}")
                self._require_live_dataset(trn.dataset_id)
                if not isinstance(metric, str) or metric not in EVAL_METRICS:
                    raise BadMetricError(
                        f"metric must be one of {sorted(EVAL_METRICS)}"
                    )
                val = _require_score(score, "score")
                pin = _require_digest(eval_digest, "eval_digest")
                self._evl_counter += 1
                eid = f"evl-{self._evl_counter}"
                rec = EvaluationRecord(
                    evaluation_id=eid,
                    training_id=tid,
                    dataset_id=trn.dataset_id,
                    metric=metric,
                    score=val,
                    eval_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "evaluation_id": eid,
                            "training_id": tid,
                            "dataset_id": trn.dataset_id,
                            "metric": metric,
                            "score": val,
                            "eval_digest": pin,
                        }
                    ),
                )
                self._evaluations[eid] = rec
                self._evaluations_by_training.setdefault(tid, []).append(eid)
                self._evaluations_by_dataset.setdefault(trn.dataset_id, []).append(eid)
                self._audit.append(
                    reward_modeling_audit_event(
                        "evaluated",
                        seq_v,
                        evaluation_id=eid,
                        training_id=tid,
                        dataset_id=trn.dataset_id,
                        metric=metric,
                    )
                )
                return rec
            except RewardModelingError as exc:
                self._burn(seq_v, "evaluate", exc)
                raise

    def retire(
        self,
        dataset_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a dataset id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                did = _require_id(dataset_id, "dataset_id")
                if did in self._retired:
                    raise RetiredDatasetError(f"dataset already retired: {did!r}")
                self._require_known_dataset(did)
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    dataset_id=did,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "dataset_id": did,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[did] = rec
                self._audit.append(
                    reward_modeling_audit_event(
                        "retired",
                        seq_v,
                        dataset_id=did,
                        reason=reason,
                    )
                )
                return rec
            except RewardModelingError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def collection_record(self, collection_id: Any, seq: Any) -> CollectionRecord:
        """Return one collection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            cid = _require_id(collection_id, "collection_id")
            if cid not in self._collections:
                raise UnknownCollectionError(f"unknown collection: {cid!r}")
            return self._collections[cid]

    def training_record(self, training_id: Any, seq: Any) -> TrainingRecord:
        """Return one training record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            tid = _require_id(training_id, "training_id")
            if tid not in self._trainings:
                raise UnknownTrainingError(f"unknown training: {tid!r}")
            return self._trainings[tid]

    def evaluation_record(self, evaluation_id: Any, seq: Any) -> EvaluationRecord:
        """Return one evaluation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(evaluation_id, "evaluation_id")
            if eid not in self._evaluations:
                raise UnknownTrainingError(f"unknown evaluation: {eid!r}")
            return self._evaluations[eid]

    def dataset_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered dataset ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._datasets.keys())

    def collection_ids(self, seq: Any) -> Tuple[str, ...]:
        """All collection ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"col-{i}" for i in range(1, self._col_counter + 1))

    def training_ids(self, seq: Any) -> Tuple[str, ...]:
        """All training ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"trn-{i}" for i in range(1, self._trn_counter + 1))

    def evaluation_ids(self, seq: Any) -> Tuple[str, ...]:
        """All evaluation ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"evl-{i}" for i in range(1, self._evl_counter + 1))

    def collections_for(self, dataset_id: Any, seq: Any) -> Tuple[str, ...]:
        """Collection ids booked against one dataset (mint order)."""
        with self._lock:
            self._check_seq(seq)
            did = _require_id(dataset_id, "dataset_id")
            self._require_known_dataset(did)
            return tuple(self._collections_by_dataset.get(did, ()))

    def trainings_for(self, collection_id: Any, seq: Any) -> Tuple[str, ...]:
        """Training ids booked against one collection (mint order)."""
        with self._lock:
            self._check_seq(seq)
            cid = _require_id(collection_id, "collection_id")
            if cid not in self._collections:
                raise UnknownCollectionError(f"unknown collection: {cid!r}")
            return tuple(self._trainings_by_collection.get(cid, ()))

    def evaluations_for(self, training_id: Any, seq: Any) -> Tuple[str, ...]:
        """Evaluation ids booked against one training run (mint order)."""
        with self._lock:
            self._check_seq(seq)
            tid = _require_id(training_id, "training_id")
            if tid not in self._trainings:
                raise UnknownTrainingError(f"unknown training: {tid!r}")
            return tuple(self._evaluations_by_training.get(tid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired dataset ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def report(self, dataset_id: Any, seq: Any) -> ModelingReport:
        """Per-dataset collection/training/evaluation tallies (pure read).

        ``posture`` is ledger truth - ``collected`` / ``trained`` /
        ``evaluated`` - derived as data, never proof the reward model
        works. ``integrity_ok`` re-derives all in-scope digest pins.
        """
        with self._lock:
            self._check_seq(seq)
            did = _require_id(dataset_id, "dataset_id")
            self._require_known_dataset(did)
            col_ids = self._collections_by_dataset.get(did, ())
            trn_ids = self._trainings_by_dataset.get(did, ())
            evl_ids = self._evaluations_by_dataset.get(did, ())
            if not trn_ids:
                posture = "collected"
            elif not evl_ids:
                posture = "trained"
            else:
                posture = "evaluated"
            integrity_ok = all(
                rec.verify()
                for rec in (
                    *(self._collections[cid] for cid in col_ids),
                    *(self._trainings[tid] for tid in trn_ids),
                    *(self._evaluations[eid] for eid in evl_ids),
                )
            )
            return ModelingReport(
                dataset_id=did,
                n_collections=len(col_ids),
                n_trainings=len(trn_ids),
                n_evaluations=len(evl_ids),
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "dataset_id": did,
                        "n_collections": len(col_ids),
                        "n_trainings": len(trn_ids),
                        "n_evaluations": len(evl_ids),
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "datasets": len(self._datasets),
                "collections": len(self._collections),
                "trainings": len(self._trainings),
                "evaluations": len(self._evaluations),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    rm = RewardModeling()
    pin = "sha256:" + "ab" * 32
    col = rm.collect("ds-1", 1, feedback_kind="preference-pair", feedback_digest=pin)
    assert col.collection_id == "col-1"
    trn = rm.train("col-1", 2, method="bradley-terry", outcome="converged",
                   train_digest=pin)
    assert trn.training_id == "trn-1"
    evl = rm.evaluate("trn-1", 3, metric="held-out-agreement", score=87,
                      eval_digest=pin)
    assert evl.evaluation_id == "evl-1"
    rm.retire("ds-1", 4, reason="decommissioned")
    rep = rm.report("ds-1", 5)
    assert rep.verify()
    assert rep.integrity_ok is True
    assert rep.posture == "evaluated"
    assert rm.stats(6) == {
        "datasets": 1,
        "collections": 1,
        "trainings": 1,
        "evaluations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("reward-modeling OK: collect, train, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
