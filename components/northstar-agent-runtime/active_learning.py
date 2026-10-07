"""Active learning: query-acquisition governance ledger, Simulated.

Research note: active learning is the sample-efficiency discipline in
which the learner *chooses which examples to get labeled* rather than
consuming a fixed labeled set (Settles, "Active Learning Literature
Survey", 2009; Settles & Craven, "An Analysis of Active Learning
Strategies for Sequence Labeling Tasks", 2008). What matters here is
the *decision ledger*: which learners issued which declared queries
under which acquisition strategies, which declared learning updates
were booked against those queries, and what evaluation posture was
derived from the booked outcomes - defensible bookkeeping, never proof
that any learning actually happened or that any acquisition strategy
is optimal.

This module owns the query -> learn -> evaluate lifecycle:

* **query()** - book one declared query selection (minted ``qry-N``
  ids; pinned 8-term acquisition-strategy vocabulary); the first query
  registers its learner. Candidate content travels as a digest pin
  only; raw examples, labels, and model internals never enter records.
* **learn()** - book one declared learning update against a booked
  query (minted ``lrn-N`` ids; pinned outcome vocabulary); outcomes
  are booked **as data**, never proof the learner actually changed.
* **evaluate()** - pure read: derive the learner's evaluation posture
  by ledger rule (``untrained`` / ``improving`` / ``plateaued`` /
  ``regressed`` / ``inconclusive``) - as data, never proof of real
  learning.
* **retire()** - terminal retirement of a learner id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``curriculum_*`` modules own
training curricula; ``preference_learning.py`` / ``value_learning.py``
/ ``rlhf.py`` / ``rlaif.py`` own preference/value learning mechanics;
``query_planner.py`` owns query planning mechanics. This module is the
active-learning *acquisition governance* decision ledger none of them
own: which strategy was declared, which candidates were selected, and
what outcomes were declared - all Simulated.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``active-learning.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no learning, selects no real
candidates, and proves nothing about sample efficiency. A booked
``improved`` outcome means "the host declared it", never "the model
learned". Prompts, examples, labels, gradients, weights, and raw
evaluation scores never enter records or cross the audit boundary -
digest pins only.
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
ACTIVE_LEARNING_VERSION = "active-learning.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.active-learning.v1"

#: Pinned acquisition-strategy vocabulary (the query strategies this ledger tracks).
STRATEGIES = (
    "uncertainty-sampling",
    "query-by-committee",
    "expected-model-change",
    "expected-error-reduction",
    "variance-reduction",
    "density-weighted",
    "margin-sampling",
    "entropy-sampling",
)

#: Pinned learning-outcome vocabulary (booked as data, never proof).
LEARN_OUTCOMES = (
    "improved",
    "no-change",
    "regressed",
    "inconclusive",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "budget-exhausted",
    "converged",
    "superseded",
    "decommissioned",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "queried",
    "learned",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "example",
        "examples",
        "candidate",
        "candidates",
        "label",
        "labels",
        "oracle",
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "action",
        "actions",
        "state",
        "states",
        "observation",
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "score",
        "scores",
        "capability",
        "capabilities",
        "performance",
        "benchmark",
        "loss",
        "feedback",
        "payload",
        "prompt",
        "response",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "report",
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


class ActiveLearningError(Exception):
    """Base error for active-learning ledger misuse."""


class BadIdError(ActiveLearningError):
    """Malformed learner, query, or learn id."""


class UnknownLearnerError(ActiveLearningError):
    """Learner not registered."""


class RetiredLearnerError(ActiveLearningError):
    """Learner id already retired; never recycled."""


class BadStrategyError(ActiveLearningError):
    """Unknown acquisition strategy."""


class BadDigestError(ActiveLearningError):
    """Malformed sha256: digest pin."""


class BadOutcomeError(ActiveLearningError):
    """Unknown learning outcome."""


class UnknownQueryError(ActiveLearningError):
    """Query id not booked."""


class AlreadyLearnedError(ActiveLearningError):
    """Query already has a booked learn update."""


class BadReasonError(ActiveLearningError):
    """Unknown retirement reason."""


class SeqOrderError(ActiveLearningError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(ActiveLearningError):
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


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QueryRecord:
    query_id: str
    learner_id: str
    strategy: str
    candidate_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "query_id": self.query_id,
            "learner_id": self.learner_id,
            "strategy": self.strategy,
            "candidate_digest": self.candidate_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "query_id": self.query_id,
                "learner_id": self.learner_id,
                "strategy": self.strategy,
                "candidate_digest": self.candidate_digest,
            }
        )


@dataclass(frozen=True)
class LearnRecord:
    learn_id: str
    query_id: str
    learner_id: str
    outcome: str
    label_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "learn_id": self.learn_id,
            "query_id": self.query_id,
            "learner_id": self.learner_id,
            "outcome": self.outcome,
            "label_digest": self.label_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "learn_id": self.learn_id,
                "query_id": self.query_id,
                "learner_id": self.learner_id,
                "outcome": self.outcome,
                "label_digest": self.label_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    learner_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "learner_id": self.learner_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "learner_id": self.learner_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class EvaluateReport:
    learner_id: str
    posture: str
    n_queries: int
    n_learns: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "learner_id": self.learner_id,
            "posture": self.posture,
            "n_queries": self.n_queries,
            "n_learns": self.n_learns,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "learner_id": self.learner_id,
                "posture": self.posture,
                "n_queries": self.n_queries,
                "n_learns": self.n_learns,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def active_learning_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the active-learning ledger."""
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


class ActiveLearning:
    """Query-acquisition governance ledger, Simulated.

    Deterministic single-host state machine: caller-supplied strictly
    increasing int seqs, claim-then-burn (failed mutations consume their
    seq and book an ``active-learning.rejected`` row; rewinds raise bare),
    no wall-clock, RLock-guarded, fail-closed, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._learners: Dict[str, List[str]] = {}
        self._queries: Dict[str, QueryRecord] = {}
        self._learns: Dict[str, LearnRecord] = {}
        self._learns_by_query: Dict[str, str] = {}
        self._learns_by_learner: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._qry_counter = 0
        self._lrn_counter = 0
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

    def _burn(self, seq: int, method: str, exc: ActiveLearningError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            active_learning_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_known_learner(self, learner_id: str) -> None:
        if learner_id not in self._learners:
            raise UnknownLearnerError(f"unknown learner: {learner_id!r}")

    def _require_live_learner(self, learner_id: str) -> None:
        if learner_id in self._retired:
            raise RetiredLearnerError(f"learner already retired: {learner_id!r}")

    # -- mutations ---------------------------------------------------------

    def query(
        self,
        learner_id: Any,
        seq: Any,
        strategy: Any = "uncertainty-sampling",
        candidate_digest: Any = "",
    ) -> QueryRecord:
        """Book one declared query selection (minted ``qry-N``).

        The first query registers its learner. Candidate examples
        travel as a digest pin only; raw examples, labels, and model
        internals never enter records.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                lid = _require_id(learner_id, "learner_id")
                if lid in self._retired:
                    raise RetiredLearnerError(f"learner id never recycled: {lid!r}")
                if not isinstance(strategy, str) or strategy not in STRATEGIES:
                    raise BadStrategyError(
                        f"strategy must be one of {sorted(STRATEGIES)}"
                    )
                pin = _require_digest(candidate_digest, "candidate_digest")
                self._qry_counter += 1
                qid = f"qry-{self._qry_counter}"
                rec = QueryRecord(
                    query_id=qid,
                    learner_id=lid,
                    strategy=strategy,
                    candidate_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "query_id": qid,
                            "learner_id": lid,
                            "strategy": strategy,
                            "candidate_digest": pin,
                        }
                    ),
                )
                self._queries[qid] = rec
                self._learners.setdefault(lid, []).append(qid)
                self._audit.append(
                    active_learning_audit_event(
                        "queried",
                        seq_v,
                        query_id=qid,
                        learner_id=lid,
                        strategy=strategy,
                        candidate_digest=pin,
                    )
                )
                return rec
            except ActiveLearningError as exc:
                self._burn(seq_v, "query", exc)
                raise

    def learn(
        self,
        query_id: Any,
        seq: Any,
        outcome: Any = "improved",
        label_digest: Any = "",
    ) -> LearnRecord:
        """Book one declared learning update against a booked query (minted ``lrn-N``).

        Outcomes are booked **as data**, never proof the learner
        actually changed. One learn per query, fail-closed.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                qid = _require_id(query_id, "query_id")
                if qid not in self._queries:
                    raise UnknownQueryError(f"unknown query: {qid!r}")
                if qid in self._learns_by_query:
                    raise AlreadyLearnedError(f"query already learned: {qid!r}")
                if not isinstance(outcome, str) or outcome not in LEARN_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(LEARN_OUTCOMES)}"
                    )
                pin = _require_digest(label_digest, "label_digest")
                lid = self._queries[qid].learner_id
                self._require_live_learner(lid)
                self._lrn_counter += 1
                lid2 = f"lrn-{self._lrn_counter}"
                rec = LearnRecord(
                    learn_id=lid2,
                    query_id=qid,
                    learner_id=lid,
                    outcome=outcome,
                    label_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "learn_id": lid2,
                            "query_id": qid,
                            "learner_id": lid,
                            "outcome": outcome,
                            "label_digest": pin,
                        }
                    ),
                )
                self._learns[lid2] = rec
                self._learns_by_query[qid] = lid2
                self._learns_by_learner.setdefault(lid, []).append(lid2)
                self._audit.append(
                    active_learning_audit_event(
                        "learned",
                        seq_v,
                        learn_id=lid2,
                        query_id=qid,
                        learner_id=lid,
                        outcome=outcome,
                        label_digest=pin,
                    )
                )
                return rec
            except ActiveLearningError as exc:
                self._burn(seq_v, "learn", exc)
                raise

    def retire(self, learner_id: Any, seq: Any, reason: Any = "manual") -> RetireRecord:
        """Terminal retirement of a learner id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                lid = _require_id(learner_id, "learner_id")
                self._require_known_learner(lid)
                if lid in self._retired:
                    raise RetiredLearnerError(f"learner id never recycled: {lid!r}")
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    learner_id=lid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "learner_id": lid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[lid] = rec
                self._audit.append(
                    active_learning_audit_event(
                        "retired", seq_v, learner_id=lid, reason=reason
                    )
                )
                return rec
            except ActiveLearningError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads --------------------------------------------------------

    def query_record(self, query_id: Any, seq: Any) -> QueryRecord:
        """Return one query record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            qid = _require_id(query_id, "query_id")
            if qid not in self._queries:
                raise UnknownQueryError(f"unknown query: {qid!r}")
            return self._queries[qid]

    def learn_record(self, learn_id: Any, seq: Any) -> LearnRecord:
        """Return one learn record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            lid = _require_id(learn_id, "learn_id")
            if lid not in self._learns:
                raise UnknownQueryError(f"unknown learn: {lid!r}")
            return self._learns[lid]

    def learner_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered learner ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._learners.keys())

    def query_ids(self, seq: Any) -> Tuple[str, ...]:
        """All query ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"qry-{i}" for i in range(1, self._qry_counter + 1))

    def learn_ids(self, seq: Any) -> Tuple[str, ...]:
        """All learn ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"lrn-{i}" for i in range(1, self._lrn_counter + 1))

    def queries_for(self, learner_id: Any, seq: Any) -> Tuple[str, ...]:
        """Query ids booked against one learner (mint order)."""
        with self._lock:
            self._check_seq(seq)
            lid = _require_id(learner_id, "learner_id")
            self._require_known_learner(lid)
            return tuple(self._learners[lid])

    def learns_for(self, learner_id: Any, seq: Any) -> Tuple[str, ...]:
        """Learn ids booked against one learner (mint order)."""
        with self._lock:
            self._check_seq(seq)
            lid = _require_id(learner_id, "learner_id")
            self._require_known_learner(lid)
            return tuple(self._learns_by_learner.get(lid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired learner ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def evaluate(self, learner_id: Any, seq: Any) -> EvaluateReport:
        """Derive one learner's evaluation posture by ledger rule (pure read).

        Posture rules (ledger data, never measured truth):
        - ``untrained`` when no learns are booked
        - ``regressed`` when any booked outcome is ``regressed``
        - ``inconclusive`` when any booked outcome is ``inconclusive``
          (and none is ``regressed``)
        - ``improving`` when every booked outcome is ``improved``
        - ``plateaued`` otherwise (no-change outcomes present)
        """
        with self._lock:
            self._check_seq(seq)
            lid = _require_id(learner_id, "learner_id")
            self._require_known_learner(lid)
            query_ids = self._learners[lid]
            learn_ids = self._learns_by_learner.get(lid, ())
            outcomes = {self._learns[l].outcome for l in learn_ids}
            if not learn_ids:
                posture = "untrained"
            elif "regressed" in outcomes:
                posture = "regressed"
            elif "inconclusive" in outcomes:
                posture = "inconclusive"
            elif outcomes == {"improved"}:
                posture = "improving"
            else:
                posture = "plateaued"
            integrity_ok = all(
                rec.verify()
                for rec in (
                    *(self._queries[q] for q in query_ids),
                    *(self._learns[l] for l in learn_ids),
                )
            )
            return EvaluateReport(
                learner_id=lid,
                posture=posture,
                n_queries=len(query_ids),
                n_learns=len(learn_ids),
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "learner_id": lid,
                        "posture": posture,
                        "n_queries": len(query_ids),
                        "n_learns": len(learn_ids),
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
                "learners": len(self._learners),
                "queries": len(self._queries),
                "learns": len(self._learns),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    al = ActiveLearning()
    pin = "sha256:" + "ab" * 32
    qry = al.query("sys-1", 1, strategy="entropy-sampling", candidate_digest=pin)
    assert qry.query_id == "qry-1"
    lrn = al.learn("qry-1", 2, outcome="improved", label_digest=pin)
    assert lrn.learn_id == "lrn-1"
    rep = al.evaluate("sys-1", 3)
    assert rep.verify()
    assert rep.posture == "improving"
    assert rep.integrity_ok is True
    al.retire("sys-1", 4, reason="converged")
    assert al.stats(5) == {
        "learners": 1,
        "queries": 1,
        "learns": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("active-learning OK: query, learn, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
