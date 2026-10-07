"""Two-Phase Set (2P-Set): add/remove with convergent merge.

Research note: the Two-Phase Set is the classic remove-capable CRDT set
(Shapiro et al. 2011). It is two grow-only sets glued together:

* ``added`` — every element ever added (tombstones never retract this);
* ``removed`` — every element ever removed (tombstones only ever grow).

Membership is ``added - removed``. ``merge`` is *union* of both halves,
so it is commutative, associative, and idempotent: replicas can merge in
any order, any number of times, and always converge to the same member
set. The complementary counters live in :mod:`crdt_interface`
(GCounter / PNCounter); this module is the *set* counterpart.

* **Two-phase discipline** — removal is permanent. Adding an element
  after it was removed does *not* resurrect it (the tombstone wins
  forever). This is the whole "two-phase" contract: phase one can add,
  phase two can only remove, and there is no phase three. The module
  enforces it fail-closed: a post-removal ``add`` is booked as a
  redundant record, not an error, and membership stays ``removed``.
* **Idempotent adds/removes** — re-adding or re-removing is a no-op on
  membership; redundant operations are booked (with ``redundant=True`` /
  ``was_member=False`` in the audit detail) so the ledger stays total.
* **Merge is convergent** — importing another replica's added/removed
  digests and unioning both halves converges regardless of order or
  repetition. A merge never invents elements and never resurrects
  removed ones.
* **Fail-closed** — malformed elements, merges with non-``TwoPSet``
  objects, and out-of-order seqs raise
  (:class:`TwoPSetError` and friends); a merge never silently drops a
  replica's contribution.
* **No wall-clock** — all sequencing is caller-supplied strictly
  increasing ``seq`` ints; replicas are identified by the
  caller-supplied ``set_id`` string.

Honest scope: merge is *convergent*, not *authenticated* — a Byzantine
replica can add bogus elements and the union will adopt them (spotting
liars is the :mod:`federated_attack_detector` layer's job, not this
module's). A merged member set means "every replica's reported adds
minus every replica's reported removes", never "the true set".
Cross-restart persistence is the host's job; this module holds state in
memory. Elements are host-reported scalars (str/int); the module books
them, it does not prove they came from a real world.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Module version pin for this module's record shape.
TWOPSET_VERSION = "twopset.v1"

#: Schema pin carried by records and audit events.
TWOPSET_SCHEMA = "northstar.twopset.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for all pins minted by this module.
_DIGEST_PREFIX = "sha256:"

#: Largest string element accepted (defensive cap; elements are booked, not streamed).
_MAX_ELEMENT_LEN = 1024


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TwoPSetError(Exception):
    """Malformed input to the TwoPSet (programming error)."""


class BadElementError(TwoPSetError):
    """Element failed validation."""


class BadMergeError(TwoPSetError):
    """Merge source was not a TwoPSet (or otherwise unusable)."""


class SeqOrderError(TwoPSetError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{field_name} must be a non-negative int")
    return value


def _check_element(value: Any) -> Any:
    """Validate an element (str/int scalar); return the canonical value."""
    if isinstance(value, bool):
        raise BadElementError("element must be str or int, got bool")
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadElementError("int element outside safe range")
        return value
    if isinstance(value, str):
        if not value:
            raise BadElementError("str element must be non-empty")
        if len(value) > _MAX_ELEMENT_LEN:
            raise BadElementError(
                f"str element exceeds {_MAX_ELEMENT_LEN} chars"
            )
        return value
    raise BadElementError(
        f"element must be str or int, got {type(value).__name__}"
    )


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise TwoPSetError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise TwoPSetError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise TwoPSetError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


def _element_digest(element: Any) -> str:
    """Stable digest identifying an element (type-tagged: ``1`` != ``"1"``)."""
    return _DIGEST_PREFIX + hashlib.sha256(_canonical(element)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddRecord:
    """One booked add of an element (idempotent; may be redundant)."""

    element: Any
    element_digest: str
    seq: int
    redundant: bool
    digest: str
    schema: str = TWOPSET_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["add", _canonical(self.element).decode("utf-8"),
                 self.redundant, self.seq],
                seed,
            ),
        )


@dataclass(frozen=True)
class RemoveRecord:
    """One booked remove (tombstone) of an element (idempotent)."""

    element: Any
    element_digest: str
    seq: int
    was_member: bool
    digest: str
    schema: str = TWOPSET_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["remove", _canonical(self.element).decode("utf-8"),
                 self.was_member, self.seq],
                seed,
            ),
        )


@dataclass(frozen=True)
class MergeRecord:
    """One booked merge of another replica's knowledge (counts only)."""

    other_set_id: str
    added_imported: int
    removed_imported: int
    added_total: int
    removed_total: int
    seq: int
    digest: str
    schema: str = TWOPSET_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                ["merge", self.other_set_id, self.added_imported,
                 self.removed_imported, self.added_total,
                 self.removed_total, self.seq],
                seed,
            ),
        )


@dataclass(frozen=True)
class StatsReport:
    """Pure read view over a TwoPSet's ledger (no seq consumed)."""

    set_id: str
    members: int
    added: int
    removed: int
    add_records: int
    remove_records: int
    merges: int
    audit_rows: int


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

KIND_ADDED = "twopset.element-added"
KIND_REMOVED = "twopset.element-removed"
KIND_MERGED = "twopset.merged"
KIND_REJECTED = "twopset.rejected"
_KINDS = (KIND_ADDED, KIND_REMOVED, KIND_MERGED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw elements stay local).
_BANNED_DETAIL_KEYS = {"element"}


def twopset_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the TwoPSet.

    Raw element values are banned from the audit boundary — only
    ``element_digest`` pins and counts cross it.
    """
    if kind not in _KINDS:
        raise TwoPSetError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = _BANNED_DETAIL_KEYS.intersection(detail)
    if banned:
        raise TwoPSetError(
            f"detail carries banned keys: {sorted(banned)}"
        )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "twopset",
        "module_version": TWOPSET_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# TwoPSet
# ---------------------------------------------------------------------------


class TwoPSet:
    """Deterministic two-phase-set bookkeeping (CRDT add/remove).

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads validate the seq shape but do not consume it and write no
    audit rows.
    """

    def __init__(self, set_id: str = "", seed: str = "") -> None:
        self._lock = threading.RLock()
        self._set_id = set_id if isinstance(set_id, str) else ""
        self._seed = seed if isinstance(seed, str) else ""
        self._last_seq = -1
        # element_digest -> element (grow-only halves)
        self._added: dict[str, Any] = {}
        self._removed: dict[str, Any] = {}
        self._add_records: list[AddRecord] = []
        self._remove_records: list[RemoveRecord] = []
        self._merges: list[MergeRecord] = []
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(twopset_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    # -- mutations -----------------------------------------------------

    def add(self, element: Any, seq: int) -> AddRecord:
        """Book an add. Idempotent: re-adding is recorded as redundant."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                element = _check_element(element)
            except TwoPSetError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _element_digest(element)
            redundant = digest in self._added
            record = AddRecord(
                element=element,
                element_digest=digest,
                seq=seq,
                redundant=redundant,
                digest=_pin(
                    ["add", _canonical(element).decode("utf-8"),
                     redundant, seq],
                    self._seed,
                ),
            )
            self._added.setdefault(digest, element)
            self._add_records.append(record)
            self._emit(
                KIND_ADDED,
                seq,
                element_digest=digest,
                redundant=redundant,
            )
            return record

    def remove(self, element: Any, seq: int) -> RemoveRecord:
        """Book a remove (tombstone). Permanent: re-adding never resurrects."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                element = _check_element(element)
            except TwoPSetError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _element_digest(element)
            was_member = digest in self._added and digest not in self._removed
            record = RemoveRecord(
                element=element,
                element_digest=digest,
                seq=seq,
                was_member=was_member,
                digest=_pin(
                    ["remove", _canonical(element).decode("utf-8"),
                     was_member, seq],
                    self._seed,
                ),
            )
            self._removed.setdefault(digest, element)
            self._remove_records.append(record)
            self._emit(
                KIND_REMOVED,
                seq,
                element_digest=digest,
                was_member=was_member,
            )
            return record

    def merge(self, other: "TwoPSet", seq: int) -> MergeRecord:
        """Union another replica's added/removed halves into this set.

        Commutative, associative, idempotent: any merge order converges.
        """
        with self._lock:
            seq = self._next_seq(seq)
            if not isinstance(other, TwoPSet):
                self._reject(seq, f"merge source must be TwoPSet, got {type(other).__name__}")
                raise BadMergeError(
                    f"merge source must be TwoPSet, got {type(other).__name__}"
                )
            with other._lock:
                other_added = dict(other._added)
                other_removed = dict(other._removed)
                other_id = other._set_id
            added_imported = 0
            for digest, element in other_added.items():
                if digest not in self._added:
                    self._added[digest] = element
                    added_imported += 1
            removed_imported = 0
            for digest, element in other_removed.items():
                if digest not in self._removed:
                    self._removed[digest] = element
                    removed_imported += 1
            record = MergeRecord(
                other_set_id=other_id,
                added_imported=added_imported,
                removed_imported=removed_imported,
                added_total=len(self._added),
                removed_total=len(self._removed),
                seq=seq,
                digest=_pin(
                    ["merge", other_id, added_imported, removed_imported,
                     len(self._added), len(self._removed), seq],
                    self._seed,
                ),
            )
            self._merges.append(record)
            self._emit(
                KIND_MERGED,
                seq,
                other_set_id=other_id,
                added_imported=added_imported,
                removed_imported=removed_imported,
            )
            return record

    # -- views (pure reads: seq validated, not consumed, no audit) -----

    def members(self, seq: int) -> Tuple[Any, ...]:
        """Current member set (added minus removed), digest-ordered."""
        _check_seq(seq, "seq")
        with self._lock:
            return tuple(
                self._added[d] for d in sorted(self._added)
                if d not in self._removed
            )

    def contains(self, element: Any, seq: int) -> bool:
        """Whether ``element`` is currently a member."""
        _check_seq(seq, "seq")
        element = _check_element(element)
        with self._lock:
            digest = _element_digest(element)
            return digest in self._added and digest not in self._removed

    def stats(self, seq: int) -> StatsReport:
        """Ledger rollup (pure view)."""
        _check_seq(seq, "seq")
        with self._lock:
            return StatsReport(
                set_id=self._set_id,
                members=sum(
                    1 for d in self._added if d not in self._removed
                ),
                added=len(self._added),
                removed=len(self._removed),
                add_records=len(self._add_records),
                remove_records=len(self._remove_records),
                merges=len(self._merges),
                audit_rows=len(self._audit_log),
            )

    def add_record(self, index: int) -> AddRecord:
        with self._lock:
            return self._add_records[index]

    def remove_record(self, index: int) -> RemoveRecord:
        with self._lock:
            return self._remove_records[index]

    def merge_record(self, index: int) -> MergeRecord:
        with self._lock:
            return self._merges[index]

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def main() -> None:
    """Self-check: add, remove, merge, pins, audit."""
    s = TwoPSet(set_id="selfcheck")
    s.add("a", 1)
    s.add("b", 2)
    s.remove("a", 3)
    assert s.members(3) == ("b",)
    t = TwoPSet(set_id="peer")
    t.add("c", 1)
    t.remove("b", 2)
    s.merge(t, 4)
    # Two-phase: "b" was removed by t, stays removed; "a" removed locally.
    assert set(s.members(4)) == {"c"}
    assert len(s.audit_log()) == 4
    for row in s.audit_log():
        assert row["schema"] == AUDIT_SCHEMA
    rec = s.add_record(0)
    assert rec.verify()
    mrec = s.merge_record(0)
    assert mrec.verify()
    rrec = s.remove_record(0)
    assert rrec.verify()
    print("twopset OK: add, remove, merge, pins, audit")


if __name__ == "__main__":
    main()
