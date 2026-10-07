"""Grow-only Set (GSet) CRDT: convergent add-only membership.

Research note: Conflict-free Replicated Data Types (Shapiro et al. 2011).
A GSet holds elements that can be added but never removed; ``merge`` is
set *union*, which is commutative, associative, and idempotent, so any
pair of replicas converges to the same membership regardless of merge
order. This is the multi-writer set counterpart to the counters in
:mod:`crdt_interface`: where a GCounter converges on per-replica maxima,
a GSet converges on the union of reported elements.

Fit for agent-fleet bookkeeping where removal is never needed: the set
of capabilities an agent has demonstrated, the set of probe ids
completed, the set of content hashes pinned, the set of allowlisted
artifact digests. When removal *is* needed, reach for an OR-Set or a
2P-Set, not this module.

* **Immutable records** — sets are frozen dataclasses; ``add``,
  ``add_all`` and ``merge`` return a *new* set. A replica that wants to
  keep its knowledge applies the result.
* **Elements are opaque strings** — sorted and deduplicated internally,
  so two replicas that saw the same elements hold byte-identical tuples
  and identical ``sha256:`` digests.
* **No wall-clock** — sequencing lives in caller-supplied ``seq`` ints
  on audit events; replicas are identified by string ``replica_id``.
* **Fail-closed** — non-string elements, oversized elements, and
  cross-type merges raise (:class:`GSetError` / ``TypeError``); a merge
  never silently drops an element.

Honest scope: merge is *convergent*, not *authenticated* — a Byzantine
replica can add arbitrary elements and union will adopt them (inflation
is the :mod:`federated_attack_detector` layer's job, not this module's).
A merged set means "every replica's reported membership, unioned",
never "the true membership". Cross-restart persistence is the host's
job; this module holds state in memory.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


#: Module version.
GSET_VERSION = "gset.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.gset.v1"

#: Audit envelope this module emits.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset({"add", "merge"})

#: Longest single element accepted (fail-closed, never silently truncated).
_MAX_ELEMENT_LEN = 4096


class GSetError(Exception):
    """Malformed input to a GSet (programming error)."""


def _check_replica_id(replica_id: object) -> str:
    if isinstance(replica_id, bool) or not isinstance(replica_id, str):
        raise GSetError(f"replica_id must be a non-empty str, got {replica_id!r}")
    if not replica_id:
        raise GSetError("replica_id must be non-empty")
    if len(replica_id) > 1024:
        raise GSetError("replica_id exceeds 1024 chars")
    return replica_id


def _check_element(element: object) -> str:
    if isinstance(element, bool) or not isinstance(element, str):
        raise GSetError(f"element must be a str, got {element!r}")
    if len(element) > _MAX_ELEMENT_LEN:
        raise GSetError(f"element exceeds {_MAX_ELEMENT_LEN} chars")
    return element


def _check_elements(elements: object) -> Tuple[str, ...]:
    """Normalize an iterable of elements to a sorted, deduplicated tuple."""
    if isinstance(elements, (str, bytes)):
        raise GSetError(f"elements must be an iterable of str, got {type(elements).__name__}")
    try:
        items = list(elements)  # type: ignore[arg-type]
    except TypeError:
        raise GSetError(f"elements must be an iterable, got {elements!r}")
    seen = set()
    for item in items:
        seen.add(_check_element(item))
    return tuple(sorted(seen))


def _pin_digest(elements: Tuple[str, ...]) -> str:
    """Domain-separated digest over the sorted membership.

    The replica id is deliberately excluded: two replicas that converged
    on the same membership must hold identical digests.
    """
    raw = jcs_canonical_json([GSET_VERSION, list(elements)])
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class GSet:
    """Grow-only set.

    ``elements`` is the sorted, deduplicated membership. Only additions
    are possible (via :meth:`add` / :meth:`add_all`); :meth:`merge` is
    set union. All mutating operations return a *new* :class:`GSet`.
    """

    replica_id: str
    elements: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        rid = _check_replica_id(self.replica_id)
        normalized = _check_elements(self.elements)
        object.__setattr__(self, "replica_id", rid)
        object.__setattr__(self, "elements", normalized)

    def __len__(self) -> int:
        return len(self.elements)

    def __contains__(self, element: object) -> bool:
        return _check_element(element) in self.elements

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.elements)

    @property
    def digest(self) -> str:
        """``sha256:`` pin over the sorted membership (replica-agnostic)."""
        return _pin_digest(self.elements)

    def verify(self) -> bool:
        """Recompute the digest and compare (tamper-evidence)."""
        return self.digest == _pin_digest(self.elements)

    def add(self, element: str) -> "GSet":
        """Return a new set with ``element`` added (no-op if present)."""
        item = _check_element(element)
        if item in self.elements:
            return GSet(self.replica_id, self.elements)
        return GSet(self.replica_id, (*self.elements, item))

    def add_all(self, elements: Iterable[str]) -> "GSet":
        """Return a new set with every element of ``elements`` added."""
        merged = set(self.elements)
        for item in _check_elements(elements):
            merged.add(item)
        return GSet(self.replica_id, tuple(sorted(merged)))

    def merge(self, other: "GSet") -> "GSet":
        """Return the union of both sets (commutative/associative/idempotent)."""
        if not isinstance(other, GSet):
            raise TypeError(f"can only merge GSet with GSet, got {type(other).__name__}")
        return GSet(self.replica_id, tuple(sorted(set(self.elements) | set(other.elements))))

    def contains(self, element: str) -> bool:
        """Membership test (fail-closed on non-string input)."""
        return _check_element(element) in self.elements

    def issubset(self, other: "GSet") -> bool:
        """True when every element of this set is in ``other``."""
        if not isinstance(other, GSet):
            raise TypeError(f"issubset needs a GSet, got {type(other).__name__}")
        return set(self.elements) <= set(other.elements)

    def as_dict(self) -> Dict[str, Any]:
        """JSON-safe record of this set."""
        return {
            "schema": SCHEMA_PIN,
            "kind": "gset",
            "replica_id": self.replica_id,
            "elements": list(self.elements),
            "size": len(self.elements),
            "digest": self.digest,
        }


def gset_audit_event(kind: str, gset: GSet, seq: int) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a GSet operation.

    ``kind`` is a fixed vocabulary: ``add`` / ``merge``. ``seq`` is the
    caller's sequence number (no wall-clock). Element *values* never
    cross the audit boundary — the record carries the membership digest
    and size only.
    """
    if kind not in _AUDIT_KINDS:
        raise GSetError(f"unknown audit kind: {kind!r}")
    if not isinstance(gset, GSet):
        raise TypeError(f"gset must be GSet, got {type(gset).__name__}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise GSetError(f"seq must be a non-negative int, got {seq!r}")
    return {
        "schema": AUDIT_FORMAT,
        "event": "gset",
        "kind": kind,
        "module": GSET_VERSION,
        "replica_id": gset.replica_id,
        "digest": gset.digest,
        "size": len(gset),
        "audit_seq": seq,
    }


def main() -> None:
    """Self-check: replicas converge regardless of merge order."""
    a = GSet("a").add("x").add("y")
    b = GSet("b").add("y").add("z")
    ab, ba = a.merge(b), b.merge(a)
    assert ab.elements == ba.elements == ("x", "y", "z")  # commutativity
    assert ab.digest == ba.digest  # replica-agnostic digest
    c = GSet("c").add("w")
    assert a.merge(b).merge(c).elements == a.merge(b.merge(c)).elements  # associativity
    assert a.merge(a).elements == a.elements  # idempotence
    grown = a.add("new")
    assert "new" not in a.elements and "new" in grown.elements  # add returns new
    assert "x" in a and a.contains("y") and not a.contains("zzz")
    assert GSet("a", ("x",)).issubset(ab)
    assert ab.verify()

    ev = gset_audit_event("merge", ab, seq=1)
    assert ev["schema"] == AUDIT_FORMAT and ev["audit_seq"] == 1
    assert ev["digest"] == ab.digest

    print("gset OK: add, merge, converge")


if __name__ == "__main__":
    main()
