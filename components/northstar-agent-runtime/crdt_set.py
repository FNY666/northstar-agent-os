"""CRDT set: observed-remove set (OR-Set) for eventually consistent replicas.

Research note: the Observed-Remove Set (Shapiro et al., 2011, "A
comprehensive study of Convergent and Commutative Replicated Data Types")
is the standard convergent set CRDT. Every add mints a globally unique
*tag* (dot); a remove records, per element, the set of add-tags it had
observed at remove time. An element is present iff it has at least one
add-tag that was never tombstoned::

    present(e)  <=>  exists (e, t) in adds with (e, t) not in tombstones

Merge is the pairwise union of ``adds`` and ``tombstones`` — commutative,
associative, and idempotent — so replicas converge no matter the merge
order. The classic consequence is *add-wins*: a concurrent add whose tag
the remover never observed survives the remove. That is the documented
semantics, not a bug.

* **Immutable records** — the set is a frozen dataclass; ``add`` /
  ``remove`` / ``merge`` each return a *new* set. A replica that wants to
  keep its knowledge applies the result.
* **Deterministic tags** — ``add(element)`` auto-mints a tag from the
  replica's logical clock (``"<replica_id>:<n>"``); an explicit ``tag``
  may be supplied for interop with external replicas. No wall-clock, no
  randomness, no UUIDs.
* **Fail-closed** — malformed construction and merges raise
  (:class:`CRDTSetError` / ``TypeError``); a merge never silently drops a
  replica's contribution. Elements and tags are pinned to non-empty
  strings.
* **Audit** — :func:`crdt_set_audit_event` builds ``audit.ndjson/1``
  records (``add`` / ``remove`` / ``merge``) on caller-supplied ``seq``
  ints, matching :mod:`crdt_interface` conventions.

Honest scope: merge is *convergent*, not *authenticated* — a Byzantine
replica can add arbitrary elements or tombstone anything it observed, and
the union-merge will adopt both (Sybil/equivocation handling is the
:mod:`federated_attack_detector` layer's job, not this module's). A merged
set means "every replica's reported adds minus every replica's reported
removes", never "the true membership". Cross-restart persistence is the
host's job; this module holds state in memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Module version.
CRDT_SET_VERSION = "crdt-set.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.crdt-set.v1"


class CRDTSetError(Exception):
    """Malformed input to the CRDT set (programming error)."""


def _check_replica_id(replica_id: object) -> str:
    if isinstance(replica_id, bool) or not isinstance(replica_id, str):
        raise CRDTSetError(f"replica_id must be a non-empty str, got {replica_id!r}")
    if not replica_id:
        raise CRDTSetError("replica_id must be non-empty")
    return replica_id


def _check_element(element: object) -> str:
    if isinstance(element, bool) or not isinstance(element, str):
        raise CRDTSetError(f"element must be a non-empty str, got {element!r}")
    if not element:
        raise CRDTSetError("element must be non-empty")
    return element


def _check_tag(tag: object) -> str:
    if isinstance(tag, bool) or not isinstance(tag, str):
        raise CRDTSetError(f"tag must be a non-empty str, got {tag!r}")
    if not tag:
        raise CRDTSetError("tag must be non-empty")
    return tag


def _check_clock(clock: object) -> int:
    if isinstance(clock, bool) or not isinstance(clock, int):
        raise CRDTSetError(f"clock must be a non-negative int, got {clock!r}")
    if clock < 0:
        raise CRDTSetError(f"clock must be non-negative, got {clock}")
    return clock


def _check_pairs(pairs: object, what: str) -> Tuple[Tuple[str, str], ...]:
    """Normalize an adds/tombstones collection to sorted tuple-of-tuples."""
    if isinstance(pairs, tuple):
        items = list(pairs)
    elif isinstance(pairs, (list, set, frozenset)):
        items = list(pairs)
    else:
        raise CRDTSetError(f"{what} must be a collection of (element, tag) pairs")
    normalized: List[Tuple[str, str]] = []
    seen = set()
    for entry in items:
        if (
            not isinstance(entry, (tuple, list))
            or len(entry) != 2
        ):
            raise CRDTSetError(f"malformed {what} entry: {entry!r}")
        element, tag = entry
        element = _check_element(element)
        tag = _check_tag(tag)
        pair = (element, tag)
        if pair in seen:
            raise CRDTSetError(f"duplicate {what} pair: {pair!r}")
        seen.add(pair)
        normalized.append(pair)
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class CRDTSet:
    """Observed-remove set.

    ``adds`` holds every observed ``(element, tag)`` pair; ``tombstones``
    holds the pairs a remove had observed. ``clock`` is this replica's
    logical clock, used to mint fresh tags; ``merge`` takes the maximum.
    """

    replica_id: str
    adds: Tuple[Tuple[str, str], ...] = ()
    tombstones: Tuple[Tuple[str, str], ...] = ()
    clock: int = 0

    def __post_init__(self) -> None:
        rid = _check_replica_id(self.replica_id)
        adds = _check_pairs(self.adds, "adds")
        tombstones = _check_pairs(self.tombstones, "tombstones")
        clock = _check_clock(self.clock)
        object.__setattr__(self, "replica_id", rid)
        object.__setattr__(self, "adds", adds)
        object.__setattr__(self, "tombstones", tombstones)
        object.__setattr__(self, "clock", clock)

    # -- membership -----------------------------------------------------

    def contains(self, element: str) -> bool:
        """True iff ``element`` has at least one non-tombstoned add-tag."""
        element = _check_element(element)
        tombstoned = set(self.tombstones)
        return any(
            e == element and (e, t) not in tombstoned for e, t in self.adds
        )

    @property
    def elements(self) -> Tuple[str, ...]:
        """Sorted tuple of currently present elements."""
        tombstoned = set(self.tombstones)
        present = {
            e for e, t in self.adds if (e, t) not in tombstoned
        }
        return tuple(sorted(present))

    # -- mutation (each returns a new set) --------------------------------

    def add(self, element: str, tag: Optional[str] = None) -> "CRDTSet":
        """Return a new set with ``element`` added.

        With ``tag=None`` a fresh tag ``"<replica_id>:<clock+1>"`` is minted
        and the clock advances. An explicit tag is recorded verbatim (the
        clock still advances, keeping local tags unique). Re-adding an
        identical ``(element, tag)`` pair is an idempotent no-op.
        """
        element = _check_element(element)
        if tag is None:
            clock = self.clock + 1
            tag = f"{self.replica_id}:{clock}"
        else:
            tag = _check_tag(tag)
            clock = self.clock + 1
        pair = (element, tag)
        if pair in self.adds:
            return self
        return CRDTSet(
            self.replica_id,
            self.adds + (pair,),
            self.tombstones,
            clock,
        )

    def remove(self, element: str) -> "CRDTSet":
        """Return a new set with ``element`` removed.

        Every ``(element, tag)`` pair observed so far is tombstoned. Adds
        this replica has *not* observed (concurrent adds) survive — the
        documented add-wins semantics. Removing an absent element is a
        no-op.
        """
        element = _check_element(element)
        observed = tuple(p for p in self.adds if p[0] == element)
        if not observed:
            return self
        tombstoned = set(self.tombstones)
        new_tombs = tuple(p for p in observed if p not in tombstoned)
        if not new_tombs:
            return self
        return CRDTSet(
            self.replica_id,
            self.adds,
            self.tombstones + new_tombs,
            self.clock,
        )

    # -- merge --------------------------------------------------------------

    def merge(self, other: "CRDTSet") -> "CRDTSet":
        """Return the least upper bound of both sets (pairwise union).

        Commutative, associative, and idempotent: any merge order converges
        to the same state. The result keeps *this* replica's id and the
        maximum of both clocks.
        """
        if not isinstance(other, CRDTSet):
            raise TypeError(
                f"can only merge CRDTSet with CRDTSet, got {type(other).__name__}"
            )
        adds = tuple(sorted(set(self.adds) | set(other.adds)))
        tombstones = tuple(sorted(set(self.tombstones) | set(other.tombstones)))
        return CRDTSet(
            self.replica_id,
            adds,
            tombstones,
            max(self.clock, other.clock),
        )

    # -- views -----------------------------------------------------------------

    def as_dict(self) -> dict:
        """JSON-safe record of this set."""
        return {
            "schema": SCHEMA_PIN,
            "kind": "crdt-set",
            "replica_id": self.replica_id,
            "adds": [{"element": e, "tag": t} for e, t in self.adds],
            "tombstones": [{"element": e, "tag": t} for e, t in self.tombstones],
            "clock": self.clock,
            "elements": list(self.elements),
        }


def crdt_set_audit_event(kind: str, crdt_set: CRDTSet, seq: int) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a CRDT-set operation.

    ``kind`` is a fixed vocabulary: ``add`` / ``remove`` / ``merge``.
    ``seq`` is the caller's sequence number (no wall-clock).
    """
    if kind not in ("add", "remove", "merge"):
        raise CRDTSetError(f"unknown audit kind: {kind!r}")
    if not isinstance(crdt_set, CRDTSet):
        raise TypeError(
            f"crdt_set must be CRDTSet, got {type(crdt_set).__name__}"
        )
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise CRDTSetError(f"seq must be a non-negative int, got {seq!r}")
    record = crdt_set.as_dict()
    record.update(
        {
            "event": "crdt-set",
            "kind": kind,
            "audit_seq": seq,
        }
    )
    return record


def main() -> None:
    """Self-check: two replicas converge regardless of merge order."""
    a = CRDTSet("a").add("x").add("y")
    b = CRDTSet("b").add("y").add("z")
    assert a.merge(b).elements == ("x", "y", "z")
    assert b.merge(a).elements == ("x", "y", "z")  # commutativity
    assert a.merge(a).elements == a.elements  # idempotence

    # Remove wins over observed adds; concurrent (unobserved) adds survive.
    c = CRDTSet("c").add("k")
    d = c.merge(CRDTSet("d"))  # d observes the add
    d_removed = d.remove("k")
    e = CRDTSet("e").add("k")  # concurrent add, tag never observed by d
    merged = d_removed.merge(e)
    assert merged.contains("k")  # add-wins for the unobserved tag
    assert not d_removed.merge(c.remove("k")).contains("k")  # observed remove wins

    ev = crdt_set_audit_event("merge", merged, seq=1)
    assert ev["schema"] == SCHEMA_PIN and ev["audit_seq"] == 1

    print("crdt-set OK: observed-remove set converges")


if __name__ == "__main__":
    main()
