"""Collaborative-filtering recommendation engine (twenty-ninth batch).

Simulated recommendation interface over host-reported interaction data:

* :meth:`RecommendationEngine.add_interaction` books ``(user, item,
  rating)`` triples reported by the host.
* :meth:`RecommendationEngine.train` builds a digest-pinned
  :class:`ModelSnapshot`: user-user and item-item cosine similarities
  over mean-centered ratings, plus popularity baselines.
* :meth:`RecommendationEngine.recommend` returns a top-N
  :class:`RecommendationList` for a user via a pinned method vocabulary
  (``"usercf"``, ``"itemcf"``, ``"popular"``), excluding already-seen
  items. ``"popular"`` doubles as the cold-start path for unknown
  users.
* :meth:`RecommendationEngine.evaluate` scores the snapshot against
  host-reported held-out interactions: RMSE over predictable pairs,
  precision@k and recall@k over relevant (rating >= 4.0) held-out
  items.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock), RLock-guarded, fail-closed validation
taxonomy (failed mutations consume their seq), stdlib-only, sha256
digest pins over canonical payloads, ``audit.ndjson/1`` events.
Scoring outcomes are *data* (an empty recommendation list, a skipped
held-out pair); only malformed inputs raise.

Research note: user-based and item-based collaborative filtering are
the classical memory-based CF families (Resnick et al., GroupLens,
1994; Sarwar et al., item-based CF, 2001). Cosine similarity over
mean-centered ratings is the textbook baseline; this module implements
exactly that baseline as deterministic bookkeeping, with popularity
as the standard cold-start fallback.

Honest boundary: this module computes cosine similarities over
*host-reported* ratings. It cannot prove a rating is truthful, cannot
observe user satisfaction, and has no exploration/exploitation
machinery — a recommendation means "highest predicted score under
this snapshot", never "this will delight the user". Pair with a real
evaluation harness and bandit feedback before production use.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


#: Version pin for this module's record shape.
RECOMMENDATION_ENGINE_VERSION = "recommendation-engine.v1"

#: Schema pin carried by records and audit events.
RECOMMENDATION_ENGINE_SCHEMA = "northstar.recommendation-engine.v1"

#: Audit envelope schema.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned recommendation-method vocabulary.
METHODS = ("usercf", "itemcf", "popular")

#: Rating scale: host-reported ratings must lie in [0, 5].
_MIN_RATING = 0.0
_MAX_RATING = 5.0

#: Held-out ratings at or above this are "relevant" for precision/recall.
_RELEVANCE_THRESHOLD = 4.0

#: Upper bound on requested recommendation counts.
_MAX_TOP_N = 50

#: Audit kinds.
_AUDIT_KINDS = (
    "interaction-added",
    "trained",
    "recommended",
    "evaluated",
    "rejected",
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed).
# ---------------------------------------------------------------------------

class RecommendationError(Exception):
    """Base class for all recommendation-engine errors."""


class BadInputError(RecommendationError):
    """Malformed input: bad ids, ratings, methods, counts, or shapes."""


class DuplicateInteractionError(RecommendationError):
    """An interaction for this (user, item) pair is already booked."""


class UnknownUserError(RecommendationError):
    """User id is not known to the trained model (usercf/itemcf path)."""


class SeqOrderError(RecommendationError):
    """Seq is not a strictly increasing non-negative int."""


class TrainingError(RecommendationError):
    """Training refused or recommend/evaluate called without a model."""


class EvaluationError(RecommendationError):
    """Held-out evaluation input is malformed."""


# ---------------------------------------------------------------------------
# Canonical digest helpers.
# ---------------------------------------------------------------------------

def _canonical(obj: Any) -> bytes:
    # Ratings are validated finite at the input boundary, so the only
    # floats reaching here are finite; json repr is deterministic.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _pin(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Validation helpers.
# ---------------------------------------------------------------------------

def _check_id(value: Any, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadInputError("%s must be a non-empty str" % name)
    return value


def _check_rating(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadInputError("rating must be a number in [0, 5]")
    rating = float(value)
    if math.isnan(rating) or math.isinf(rating):
        raise BadInputError("rating must be finite")
    if not (_MIN_RATING <= rating <= _MAX_RATING):
        raise BadInputError("rating must be in [0, 5]")
    return rating


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    if seq <= last:
        raise SeqOrderError("seq must be strictly increasing")
    return seq


def _check_observation_seq(seq: Any) -> int:
    # recommend() is an observation: it validates the seq shape but does
    # not consume the ledger counter.
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


def _check_top_n(top_n: Any, name: str) -> int:
    if isinstance(top_n, bool) or not isinstance(top_n, int):
        raise BadInputError("%s must be an int" % name)
    if not (1 <= top_n <= _MAX_TOP_N):
        raise BadInputError("%s must be in [1, %d]" % (name, _MAX_TOP_N))
    return top_n


# ---------------------------------------------------------------------------
# Frozen records.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InteractionRecord:
    """One booked host-reported (user, item, rating) triple."""
    interaction_id: str
    user_id: str
    item_id: str
    rating: float
    seq: int
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin({
            "interaction_id": self.interaction_id,
            "user_id": self.user_id,
            "item_id": self.item_id,
            "rating": self.rating,
            "seq": self.seq,
        })


@dataclass(frozen=True)
class ModelSnapshot:
    """Digest-pinned, fully serializable training output."""
    snapshot_id: str
    seq: int
    n_users: int
    n_items: int
    n_interactions: int
    user_sims: Tuple[Tuple[str, str, float], ...]
    item_sims: Tuple[Tuple[str, str, float], ...]
    popularity: Tuple[Tuple[str, int], ...]
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin({
            "snapshot_id": self.snapshot_id,
            "seq": self.seq,
            "n_users": self.n_users,
            "n_items": self.n_items,
            "n_interactions": self.n_interactions,
            "user_sims": [list(t) for t in self.user_sims],
            "item_sims": [list(t) for t in self.item_sims],
            "popularity": [list(t) for t in self.popularity],
        })


@dataclass(frozen=True)
class Recommendation:
    """One ranked recommendation."""
    item_id: str
    score: float
    rank: int


@dataclass(frozen=True)
class RecommendationList:
    """Top-N recommendations for a user under a pinned model."""
    rec_id: str
    user_id: str
    method: str
    model_pin: str
    top_n: int
    recommendations: Tuple[Recommendation, ...]
    seq: int
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin({
            "rec_id": self.rec_id,
            "user_id": self.user_id,
            "method": self.method,
            "model_pin": self.model_pin,
            "top_n": self.top_n,
            "recommendations": [
                {"item_id": r.item_id, "score": r.score, "rank": r.rank}
                for r in self.recommendations
            ],
            "seq": self.seq,
        })

    def item_ids(self) -> Tuple[str, ...]:
        return tuple(r.item_id for r in self.recommendations)


@dataclass(frozen=True)
class EvalReport:
    """Held-out evaluation of a model snapshot."""
    eval_id: str
    seq: int
    model_pin: str
    top_k: int
    n_held_out: int
    n_scored: int
    n_skipped: int
    rmse: Optional[float]
    precision_at_k: float
    recall_at_k: float
    digest: str = ""

    def verify(self) -> bool:
        return self.digest == _pin({
            "eval_id": self.eval_id,
            "seq": self.seq,
            "model_pin": self.model_pin,
            "top_k": self.top_k,
            "n_held_out": self.n_held_out,
            "n_scored": self.n_scored,
            "n_skipped": self.n_skipped,
            "rmse": self.rmse,
            "precision_at_k": self.precision_at_k,
            "recall_at_k": self.recall_at_k,
        })


# ---------------------------------------------------------------------------
# Audit events.
# ---------------------------------------------------------------------------

def recommendation_engine_audit_event(kind: str, seq: int,
                                     **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for engine activity.

    Carries ids, counts, and digest pins only — raw rating values stay
    in the interaction ledger, never in the audit trail.
    """
    if kind not in _AUDIT_KINDS:
        raise RecommendationError("unknown audit kind: %r" % kind)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise RecommendationError("seq must be a non-negative int")
    return {
        "schema": AUDIT_SCHEMA,
        "module": "recommendation_engine",
        "moduleVersion": RECOMMENDATION_ENGINE_VERSION,
        "moduleSchema": RECOMMENDATION_ENGINE_SCHEMA,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Math core (pure functions, deterministic).
# ---------------------------------------------------------------------------

def _cosine(a: Mapping[str, float], b: Mapping[str, float]) -> float:
    """Cosine similarity over the intersection of two centered vectors."""
    common = [k for k in a if k in b]
    if not common:
        return 0.0
    dot = sum(a[k] * b[k] for k in common)
    na = math.sqrt(sum(a[k] * a[k] for k in common))
    nb = math.sqrt(sum(b[k] * b[k] for k in common))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


# ---------------------------------------------------------------------------
# Engine.
# ---------------------------------------------------------------------------

class RecommendationEngine:
    """Deterministic collaborative-filtering bookkeeping engine."""

    def __init__(self, seed: str = "recommendation-engine") -> None:
        self._seed = seed
        self._lock = threading.RLock()
        self._last_seq = 0
        self._interactions: Dict[Tuple[str, str], InteractionRecord] = {}
        self._next_ixn = 1
        self._next_mdl = 1
        self._next_rec = 1
        self._next_evl = 1
        self._audit_log: List[Dict[str, Any]] = []
        # Trained-model internals (rebuilt by train()).
        self._model: Optional[ModelSnapshot] = None
        self._ratings: Dict[str, Dict[str, float]] = {}
        self._user_means: Dict[str, float] = {}
        self._item_means: Dict[str, float] = {}
        self._user_sims: Dict[str, Dict[str, float]] = {}
        self._item_sims: Dict[str, Dict[str, float]] = {}
        self._popularity: List[Tuple[str, int]] = []

    # -- internal helpers -------------------------------------------------

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            recommendation_engine_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str, **detail: Any) -> None:
        # Failed mutations consume their seq and are audited; the seq
        # was already advanced by the caller before validation failed.
        self._audit("rejected", seq, reason=reason, **detail)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)

    # -- mutations --------------------------------------------------------

    def add_interaction(self, user_id: str, item_id: str,
                        rating: Any, seq: int) -> InteractionRecord:
        """Book one host-reported (user, item, rating) triple."""
        with self._lock:
            try:
                _check_seq(seq, self._last_seq)
            except SeqOrderError:
                raise
            self._last_seq = seq  # failed mutations consume their seq
            try:
                user_id = _check_id(user_id, "user_id")
                item_id = _check_id(item_id, "item_id")
                rating = _check_rating(rating)
            except RecommendationError as exc:
                self._reject(seq, type(exc).__name__,
                             user_id=str(user_id), item_id=str(item_id))
                raise
            if (user_id, item_id) in self._interactions:
                self._reject(seq, "DuplicateInteractionError",
                             user_id=user_id, item_id=item_id)
                raise DuplicateInteractionError(
                    "interaction already booked for (%r, %r)"
                    % (user_id, item_id))
            interaction_id = "ixn-%d" % self._next_ixn
            self._next_ixn += 1
            record = InteractionRecord(
                interaction_id=interaction_id,
                user_id=user_id,
                item_id=item_id,
                rating=rating,
                seq=seq,
                digest=_pin({
                    "interaction_id": interaction_id,
                    "user_id": user_id,
                    "item_id": item_id,
                    "rating": rating,
                    "seq": seq,
                }),
            )
            self._interactions[(user_id, item_id)] = record
            self._audit("interaction-added", seq,
                       interaction_id=interaction_id,
                       user_id=user_id, item_id=item_id)
            return record

    def train(self, seq: int) -> ModelSnapshot:
        """Build a digest-pinned model snapshot from booked interactions."""
        with self._lock:
            try:
                _check_seq(seq, self._last_seq)
            except SeqOrderError:
                raise
            self._last_seq = seq
            if not self._interactions:
                self._reject(seq, "TrainingError: no interactions")
                raise TrainingError("cannot train on an empty ledger")

            ratings: Dict[str, Dict[str, float]] = {}
            item_users: Dict[str, Dict[str, float]] = {}
            for (user_id, item_id), rec in self._interactions.items():
                ratings.setdefault(user_id, {})[item_id] = rec.rating
                item_users.setdefault(item_id, {})[user_id] = rec.rating

            user_means = {u: sum(v.values()) / len(v)
                          for u, v in ratings.items()}
            item_means = {i: sum(v.values()) / len(v)
                          for i, v in item_users.items()}
            user_centered = {
                u: {i: r - user_means[u] for i, r in v.items()}
                for u, v in ratings.items()
            }
            item_centered = {
                i: {u: r - item_means[i] for u, r in v.items()}
                for i, v in item_users.items()
            }

            users = sorted(ratings)
            items = sorted(item_users)
            user_sims: Dict[str, Dict[str, float]] = {u: {} for u in users}
            for x in range(len(users)):
                for y in range(x + 1, len(users)):
                    u1, u2 = users[x], users[y]
                    sim = _cosine(user_centered[u1], user_centered[u2])
                    user_sims[u1][u2] = sim
                    user_sims[u2][u1] = sim
            item_sims: Dict[str, Dict[str, float]] = {i: {} for i in items}
            for x in range(len(items)):
                for y in range(x + 1, len(items)):
                    i1, i2 = items[x], items[y]
                    sim = _cosine(item_centered[i1], item_centered[i2])
                    item_sims[i1][i2] = sim
                    item_sims[i2][i1] = sim

            counts = {i: len(v) for i, v in item_users.items()}
            popularity = sorted(counts.items(),
                                key=lambda kv: (-kv[1], -item_means[kv[0]],
                                                kv[0]))

            snapshot_id = "mdl-%d" % self._next_mdl
            self._next_mdl += 1
            user_sim_tuples = tuple(
                sorted((u1, u2, user_sims[u1][u2])
                       for u1 in users for u2 in users if u1 < u2))
            item_sim_tuples = tuple(
                sorted((i1, i2, item_sims[i1][i2])
                       for i1 in items for i2 in items if i1 < i2))
            popularity_tuples = tuple((i, c) for i, c in popularity)
            snapshot = ModelSnapshot(
                snapshot_id=snapshot_id,
                seq=seq,
                n_users=len(users),
                n_items=len(items),
                n_interactions=len(self._interactions),
                user_sims=user_sim_tuples,
                item_sims=item_sim_tuples,
                popularity=popularity_tuples,
                digest=_pin({
                    "snapshot_id": snapshot_id,
                    "seq": seq,
                    "n_users": len(users),
                    "n_items": len(items),
                    "n_interactions": len(self._interactions),
                    "user_sims": [list(t) for t in user_sim_tuples],
                    "item_sims": [list(t) for t in item_sim_tuples],
                    "popularity": [list(t) for t in popularity_tuples],
                }),
            )
            # Publish internals atomically under the lock.
            self._model = snapshot
            self._ratings = ratings
            self._user_means = user_means
            self._item_means = item_means
            self._user_sims = user_sims
            self._item_sims = item_sims
            self._popularity = popularity
            self._audit("trained", seq, snapshot_id=snapshot_id,
                       digest=snapshot.digest,
                       n_users=len(users), n_items=len(items),
                       n_interactions=len(self._interactions))
            return snapshot

    # -- scoring (pure w.r.t. trained internals) --------------------------

    def _predict_usercf(self, user_id: str, item_id: str) -> float:
        num = den = 0.0
        for other, sim in self._user_sims.get(user_id, {}).items():
            if sim <= 0.0:
                continue
            r = self._ratings.get(other, {}).get(item_id)
            if r is None:
                continue
            num += sim * r
            den += sim
        if den > 0.0:
            return num / den
        return self._item_means[item_id]

    def _predict_itemcf(self, user_id: str, item_id: str) -> float:
        u_mean = self._user_means[user_id]
        num = den = 0.0
        for seen_item, r in self._ratings[user_id].items():
            sim = self._item_sims.get(item_id, {}).get(seen_item, 0.0)
            if sim <= 0.0:
                continue
            num += sim * (r - u_mean)
            den += sim
        if den > 0.0:
            return u_mean + num / den
        return u_mean

    def _score(self, user_id: str, item_id: str, method: str) -> float:
        if method == "usercf":
            return self._predict_usercf(user_id, item_id)
        if method == "itemcf":
            return self._predict_itemcf(user_id, item_id)
        raise BadInputError("unknown method: %r" % method)

    def _recommend_locked(self, user_id: str, top_n: int,
                          method: str) -> List[Tuple[str, float]]:
        if self._model is None:
            raise TrainingError("no trained model: call train() first")
        if method == "popular":
            seen = set(self._ratings.get(user_id, {}))
            ranked = [(i, float(c)) for i, c in self._popularity
                      if i not in seen]
            return ranked[:top_n]
        if user_id not in self._ratings:
            raise UnknownUserError("unknown user: %r" % user_id)
        seen = set(self._ratings[user_id])
        scored = [(item, self._score(user_id, item, method))
                  for item in self._item_means if item not in seen]
        scored.sort(key=lambda kv: (-kv[1], kv[0]))
        return scored[:top_n]

    # -- observations -----------------------------------------------------

    def recommend(self, user_id: str, seq: int, top_n: int = 5,
                  method: str = "usercf") -> RecommendationList:
        """Return a top-N recommendation list (observation; seq not consumed)."""
        with self._lock:
            _check_observation_seq(seq)
            user_id = _check_id(user_id, "user_id")
            top_n = _check_top_n(top_n, "top_n")
            if method not in METHODS:
                raise BadInputError(
                    "method must be one of %s" % (METHODS,))
            ranked = self._recommend_locked(user_id, top_n, method)
            rec_id = "rec-%d" % self._next_rec
            self._next_rec += 1
            recs = tuple(Recommendation(item_id=item, score=score, rank=n + 1)
                         for n, (item, score) in enumerate(ranked))
            model_pin = self._model.digest if self._model else ""
            result = RecommendationList(
                rec_id=rec_id,
                user_id=user_id,
                method=method,
                model_pin=model_pin,
                top_n=top_n,
                recommendations=recs,
                seq=seq,
                digest=_pin({
                    "rec_id": rec_id,
                    "user_id": user_id,
                    "method": method,
                    "model_pin": model_pin,
                    "top_n": top_n,
                    "recommendations": [
                        {"item_id": r.item_id, "score": r.score,
                         "rank": r.rank} for r in recs
                    ],
                    "seq": seq,
                }),
            )
            self._audit("recommended", seq, rec_id=rec_id, user_id=user_id,
                       method=method, model_pin=model_pin,
                       count=len(recs))
            return result

    def evaluate(self, seq: int,
                 held_out: Sequence[Tuple[str, str, Any]],
                 top_k: int = 5) -> EvalReport:
        """Score the trained model against host-reported held-out triples."""
        with self._lock:
            try:
                _check_seq(seq, self._last_seq)
            except SeqOrderError:
                raise
            self._last_seq = seq
            top_k = _check_top_n(top_k, "top_k")
            if not held_out:
                self._reject(seq, "EvaluationError: held_out must not be empty")
                raise EvaluationError("held_out must not be empty")
            pairs: List[Tuple[str, str, float]] = []
            for triple in held_out:
                try:
                    if not isinstance(triple, (tuple, list)) or len(triple) != 3:
                        raise EvaluationError(
                            "held_out entries must be (user, item, rating)")
                    user_id = _check_id(triple[0], "held_out user_id")
                    item_id = _check_id(triple[1], "held_out item_id")
                    rating = _check_rating(triple[2])
                except RecommendationError as exc:
                    self._reject(seq, "EvaluationError: %s" % type(exc).__name__)
                    raise EvaluationError(str(exc)) from exc
                pairs.append((user_id, item_id, rating))
            if self._model is None:
                self._reject(seq, "TrainingError: no trained model")
                raise TrainingError("no trained model: call train() first")

            sum_se = 0.0
            n_scored = 0
            n_skipped = 0
            relevant: Dict[str, List[str]] = {}
            for user_id, item_id, rating in pairs:
                if (user_id not in self._ratings
                        or item_id not in self._item_means):
                    n_skipped += 1
                    continue
                pred = self._predict_usercf(user_id, item_id)
                if not math.isfinite(pred):
                    n_skipped += 1
                    continue
                sum_se += (pred - rating) ** 2
                n_scored += 1
                if rating >= _RELEVANCE_THRESHOLD:
                    relevant.setdefault(user_id, []).append(item_id)

            precisions: List[float] = []
            recalls: List[float] = []
            for user_id, rel_items in relevant.items():
                ranked = [item for item, _ in
                          self._recommend_locked(user_id, top_k, "usercf")]
                hits = sum(1 for item in ranked if item in rel_items)
                precisions.append(hits / top_k)
                recalls.append(hits / len(rel_items))

            rmse = math.sqrt(sum_se / n_scored) if n_scored else None
            eval_id = "evl-%d" % self._next_evl
            self._next_evl += 1
            report = EvalReport(
                eval_id=eval_id,
                seq=seq,
                model_pin=self._model.digest,
                top_k=top_k,
                n_held_out=len(pairs),
                n_scored=n_scored,
                n_skipped=n_skipped,
                rmse=rmse,
                precision_at_k=(sum(precisions) / len(precisions)
                                if precisions else 0.0),
                recall_at_k=(sum(recalls) / len(recalls)
                             if recalls else 0.0),
                digest=_pin({
                    "eval_id": eval_id,
                    "seq": seq,
                    "model_pin": self._model.digest,
                    "top_k": top_k,
                    "n_held_out": len(pairs),
                    "n_scored": n_scored,
                    "n_skipped": n_skipped,
                    "rmse": rmse,
                    "precision_at_k": (sum(precisions) / len(precisions)
                                       if precisions else 0.0),
                    "recall_at_k": (sum(recalls) / len(recalls)
                                    if recalls else 0.0),
                }),
            )
            self._audit("evaluated", seq, eval_id=eval_id,
                       model_pin=self._model.digest,
                       n_held_out=len(pairs), n_scored=n_scored,
                       n_skipped=n_skipped)
            return report


def main() -> None:
    engine = RecommendationEngine()
    seq = 0
    data = [("u1", "i1", 5), ("u1", "i2", 3),
            ("u2", "i1", 4), ("u2", "i2", 2), ("u2", "i3", 5),
            ("u3", "i1", 1), ("u3", "i2", 5)]
    for user_id, item_id, rating in data:
        seq += 1
        engine.add_interaction(user_id, item_id, rating, seq)
    seq += 1
    snapshot = engine.train(seq)
    assert snapshot.verify()
    recs = engine.recommend("u1", seq + 1, top_n=3, method="usercf")
    assert recs.verify()
    assert recs.item_ids() == ("i3",)
    report = engine.evaluate(seq + 2, [("u1", "i3", 5.0)], top_k=2)
    assert report.verify()
    print("recommendation-engine OK: interactions, train, recommend, "
          "evaluate, pins, audit")


if __name__ == "__main__":
    main()
