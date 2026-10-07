"""Preference learning decision ledger, Simulated.

Research note: preference learning (the RLHF / RLAIF lineage) converts
human preference judgments into a trainable signal: collect pairwise or
scalar feedback, fit a preference model (Bradley-Terry, DPO, IPO, KTO,
PPO-shaped reward modeling), evaluate the learned preferences. The
dangerous half of the pipeline is the raw material: prompts, chosen and
rejected responses, annotator identities, reward scores. Those must never
be bundled with the bookkeeping record that tracks the pipeline's
lifecycle.

This module is that bookkeeping layer. It:

* **collect()** - book one declared feedback collection (minted ``col-N``
  ids) over a pinned source vocabulary; the first collection on an id
  registers the system; raw prompts/responses/identities travel as
  ``sha256:`` digest pins only.
* **train()** - book one declared preference-model training run (minted
  ``trn-N`` ids) over a pinned method vocabulary; fail-closed unless the
  system carries at least one booked collection; books the *declaration*,
  never the trained weights.
* **evaluate()** - pure-read derived training posture per system, as data.
* **retire()** - terminal; retired ids are never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``preference-learning.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: a booked collection is a host-declared claim that feedback
was gathered, never proof real humans judged anything; a booked train run
is a host-declared claim, never proof a preference model was actually
fitted; a derived ``trained`` posture is a ledger rule satisfied, never
evidence the system's preferences are any good.
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
PREFERENCE_LEARNING_VERSION = "preference-learning.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.preference-learning.v1"

#: Pinned feedback-source vocabulary (declared, never proof of real humans).
COLLECTION_SOURCES = (
    "human",
    "expert",
    "crowd",
    "ai-feedback",
    "synthetic",
)

#: Pinned preference-training method vocabulary (declared, never proof).
TRAIN_METHODS = (
    "bradley-terry",
    "dpo",
    "ipo",
    "kto",
    "ppo",
    "reward-model",
)

#: Pinned derived postures for evaluate().
POSTURES = (
    "collected",
    "trained",
)

#: Pinned retirement reasons.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "model-withdrawn",
    "training-complete",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "collected",
    "trained",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "preference",
        "feedback",
        "response",
        "chosen",
        "rejected_response",
        "prompt",
        "annotator",
        "rater",
        "identity",
        "weights",
        "dataset",
        "reward",
        "score",
        "text",
        "content",
        "data",
        "raw",
        "notes",
        "note",
        "secret",
        "details",
        "detail",
        "description",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PreferenceLearningError(Exception):
    """Base error for preference-learning-ledger misuse."""


class BadIdError(PreferenceLearningError):
    """Malformed system / collection / train id."""


class BadDigestError(PreferenceLearningError):
    """Malformed sha256: digest pin."""


class BadSourceError(PreferenceLearningError):
    """Collection source outside the pinned vocabulary."""


class BadMethodError(PreferenceLearningError):
    """Training method outside the pinned vocabulary."""


class BadCountError(PreferenceLearningError):
    """Host-reported pair count outside the valid int range."""


class UnknownSystemError(PreferenceLearningError):
    """Reference to a system id that was never registered."""


class NoCollectionError(PreferenceLearningError):
    """Training attempted before any collection was booked."""


class BadReasonError(PreferenceLearningError):
    """Retirement reason outside the pinned vocabulary."""


class RetiredSystemError(PreferenceLearningError):
    """Mutation attempted against a retired system."""


class SeqOrderError(PreferenceLearningError):
    """Caller seq did not strictly increase."""


class AuditKindError(PreferenceLearningError):
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


def _require_count(n_pairs: int) -> int:
    if isinstance(n_pairs, bool) or not isinstance(n_pairs, int):
        raise BadCountError("n_pairs must be an int")
    if n_pairs < 0:
        raise BadCountError("n_pairs must be >= 0")
    return n_pairs


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CollectionRecord:
    """One declared feedback collection (minted col-N ids)."""

    collection_id: str
    system_id: str
    source: str
    n_pairs: int
    feedback_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "collection_id": self.collection_id,
            "system_id": self.system_id,
            "source": self.source,
            "n_pairs": self.n_pairs,
            "feedback_digest": self.feedback_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "collection_id": self.collection_id,
                "system_id": self.system_id,
                "source": self.source,
                "n_pairs": self.n_pairs,
                "feedback_digest": self.feedback_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class TrainRecord:
    """One declared preference-model training run (minted trn-N ids)."""

    train_id: str
    system_id: str
    method: str
    train_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "train_id": self.train_id,
            "system_id": self.system_id,
            "method": self.method,
            "train_digest": self.train_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "train_id": self.train_id,
                "system_id": self.system_id,
                "method": self.method,
                "train_digest": self.train_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a system's preference-learning lifecycle."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read derived preference-learning posture of one system."""

    system_id: str
    n_collections: int
    n_trains: int
    total_pairs: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_collections": self.n_collections,
            "n_trains": self.n_trains,
            "total_pairs": self.total_pairs,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_collections": self.n_collections,
                "n_trains": self.n_trains,
                "total_pairs": self.total_pairs,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def preference_learning_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the preference ledger."""
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


class PreferenceLearning:
    """Preference learning decision ledger (Simulated).

    ``collect()`` / ``train()`` / ``retire()`` mutate the ledger and consume
    caller seqs; ``evaluate()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._collections: Dict[str, CollectionRecord] = {}
        self._system_collections: Dict[str, List[str]] = {}
        self._trains: Dict[str, TrainRecord] = {}
        self._system_trains: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._collection_counter = 0
        self._train_counter = 0
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
            row = preference_learning_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(preference_learning_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- collect ------------------------------------------------------------

    def collect(
        self,
        system_id: str,
        seq: int,
        source: str = "human",
        n_pairs: int = 0,
        feedback_digest: str = "",
    ) -> CollectionRecord:
        """Book one declared feedback collection for a system.

        The first collection on an id registers the system; raw
        prompts/responses/identities never enter records (digest pins only).
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if source not in COLLECTION_SOURCES:
                    raise BadSourceError(f"bad collection source: {source!r}")
                n_pairs = _require_count(n_pairs)
                feedback_digest = _require_optional_digest(feedback_digest, "feedback_digest")
                self._require_live(system_id)
                self._collection_counter += 1
                collection_id = f"col-{self._collection_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "collection_id": collection_id,
                        "system_id": system_id,
                        "source": source,
                        "n_pairs": n_pairs,
                        "feedback_digest": feedback_digest,
                        "seq": seq,
                    }
                )
                record = CollectionRecord(
                    collection_id=collection_id,
                    system_id=system_id,
                    source=source,
                    n_pairs=n_pairs,
                    feedback_digest=feedback_digest,
                    seq=seq,
                    digest=digest,
                )
                self._collections[collection_id] = record
                self._system_collections.setdefault(system_id, []).append(collection_id)
                self._emit(
                    "collected",
                    seq,
                    collection_id=collection_id,
                    system_id=system_id,
                    source=source,
                    n_pairs=n_pairs,
                )
                return record
            except PreferenceLearningError:
                self._burn(seq, "collect")
                raise

    # -- train ----------------------------------------------------------------

    def train(
        self,
        system_id: str,
        seq: int,
        method: str = "bradley-terry",
        train_digest: str = "",
    ) -> TrainRecord:
        """Book one declared preference-model training run.

        Fail-closed unless the system carries at least one booked
        collection; books the *declaration*, never the trained weights.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if method not in TRAIN_METHODS:
                    raise BadMethodError(f"bad training method: {method!r}")
                train_digest = _require_optional_digest(train_digest, "train_digest")
                self._require_live(system_id)
                col_ids = self._system_collections.get(system_id, [])
                if not col_ids:
                    raise NoCollectionError(
                        f"no collection booked for system: {system_id!r}"
                    )
                self._train_counter += 1
                train_id = f"trn-{self._train_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "train_id": train_id,
                        "system_id": system_id,
                        "method": method,
                        "train_digest": train_digest,
                        "seq": seq,
                    }
                )
                record = TrainRecord(
                    train_id=train_id,
                    system_id=system_id,
                    method=method,
                    train_digest=train_digest,
                    seq=seq,
                    digest=digest,
                )
                self._trains[train_id] = record
                self._system_trains.setdefault(system_id, []).append(train_id)
                self._emit(
                    "trained",
                    seq,
                    train_id=train_id,
                    system_id=system_id,
                    method=method,
                )
                return record
            except PreferenceLearningError:
                self._burn(seq, "train")
                raise

    # -- retire ----------------------------------------------------------------

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system's preference-learning lifecycle.

        Retired ids are never recycled; post-retire mutations are refused,
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad retirement reason: {reason!r}")
                if system_id not in self._system_collections:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                self._require_live(system_id)
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    system_id=system_id, reason=reason, seq=seq, digest=digest
                )
                self._retired[system_id] = record
                self._emit("retired", seq, system_id=system_id, reason=reason)
                return record
            except PreferenceLearningError:
                self._burn(seq, "retire")
                raise

    # -- evaluate (pure read) --------------------------------------------------

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derived preference-learning posture of one system, as data.

        Posture rules (ledger data, never measured truth):
        - ``trained`` when at least one train run is booked
        - ``collected`` when at least one collection is booked and no train
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(system_id, "system_id")
            if system_id not in self._system_collections:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            col_ids = self._system_collections[system_id]
            train_ids = self._system_trains.get(system_id, [])
            all_ok = all(
                self._collections[cid].verify() for cid in col_ids
            ) and all(self._trains[tid].verify() for tid in train_ids)
            total_pairs = sum(self._collections[cid].n_pairs for cid in col_ids)
            posture = "trained" if train_ids else "collected"
            record = EvaluationReport(
                system_id=system_id,
                n_collections=len(col_ids),
                n_trains=len(train_ids),
                total_pairs=total_pairs,
                posture=posture,
                integrity_ok=all_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "n_collections": len(col_ids),
                        "n_trains": len(train_ids),
                        "total_pairs": total_pairs,
                        "posture": posture,
                        "integrity_ok": all_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    # -- views (pure reads) ------------------------------------------------------

    def collection_record(self, collection_id: str, seq: int) -> CollectionRecord:
        """Return one collection record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(collection_id, "collection_id")
            if collection_id not in self._collections:
                raise UnknownSystemError(f"unknown collection: {collection_id!r}")
            return self._collections[collection_id]

    def train_record(self, train_id: str, seq: int) -> TrainRecord:
        """Return one train record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(train_id, "train_id")
            if train_id not in self._trains:
                raise UnknownSystemError(f"unknown train run: {train_id!r}")
            return self._trains[train_id]

    def collections_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Collection ids booked for one system, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(system_id, "system_id")
            if system_id not in self._system_collections:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(self._system_collections[system_id])

    def trains_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Train ids booked for one system, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(system_id, "system_id")
            if system_id not in self._system_collections:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(self._system_trains.get(system_id, []))

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids in first-collection order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._system_collections.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "systems": len(self._system_collections),
                "collections": len(self._collections),
                "trains": len(self._trains),
                "retired": len(self._retired),
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
    """Self-check: exercise the preference-learning ledger end to end."""
    pl = PreferenceLearning()
    c1 = pl.collect("s-1", 1, source="human", n_pairs=120)
    assert c1.collection_id == "col-1"
    t1 = pl.train("s-1", 2, method="dpo")
    assert t1.train_id == "trn-1"
    rep = pl.evaluate("s-1", 3)
    assert rep.posture == "trained"
    assert rep.total_pairs == 120
    assert rep.verify()
    pl.collect("s-2", 4, source="expert")
    assert pl.evaluate("s-2", 5).posture == "collected"
    pl.retire("s-1", 6)
    assert pl.stats(7) == {
        "systems": 2,
        "collections": 2,
        "trains": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("preference-learning OK: collect, train, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
