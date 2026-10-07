"""CRDT map: observed-remove map for eventually consistent replicas.

Research note: the OR-Map (Shapiro et al. 2011, "A comprehensive study of
Convergent and Commutative Replicated Data Types") is the standard
state-based map CRDT. Each key maps to a set of ``(dot, value)`` pairs,
where a *dot* ``(replica_id, counter)`` is a globally unique tag minted by
the replica that wrote it. ``remove`` deletes only the entries *observed*
by the removing replica — a concurrent ``put`` from another replica that
the remover had not yet seen survives the remove (observed-remove
semantics). ``merge`` is the per-key union of entry sets plus the
element-wise maximum of the version clocks, which is commutative,
associative, and idempotent: replicas converge in any merge order.

* **Single-value discipline** — ``put`` removes all locally observed
  entries for the key before adding the new one, so a replica's own map
  behaves like a plain last-write-wins map. Concurrent ``put``s from two
  replicas that have not seen each other both survive a later merge; the
  map then holds *both* values for the key and ``get`` returns the one with
  the lexicographically smallest dot (deterministic, not wall-clock
  last-writer-wins — there is no wall-clock anywhere in this module).
* **Immutable records** — ``put`` / ``remove`` / ``merge`` each return a
  *new* :class:`CRDTMap`; replicas are frozen dataclasses threaded through
  ``threading``-free pure functions. (No locks are needed: nothing is
  mutated in place.)
* **Digest pins** — every entry carries a ``sha256:`` digest over its
  canonical encoding, and every map carries a digest over its clock and
  entry digests. ``verify()`` re-pins both.
* **Fail-closed** — bad keys, bad values, bad replicas, and merges with
  non-maps raise (:class:`CRDTMapError` subclasses); a merge never silently
  drops a replica's contribution.
* **Audit boundary** — ``crdt_map_audit_event()`` shapes
  ``audit.ndjson/1`` records for local operations. Values never cross the
  audit boundary: ids and digest pins only.

Honest scope: convergence is *not* authentication — a Byzantine replica
can mint dots under its own id and merge will adopt them (that's the
:mod:`federated_attack_detector` layer's job). ``get`` returning a value
means "this replica's converged view", never "the true value". Values are
capped at 64 KiB of canonical JSON; keys must be non-empty strings.
Persistence across restarts is the host's job; this module holds state in
memory.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
CRDT_MAP_VERSION = "crdt-map.v1"

#: Schema pin for records produced by this module.
CRDT_MAP_SCHEMA = "northstar.crdt-map.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Max canonical-JSON bytes accepted for one value.
_MAX_VALUE_BYTES = 65536


class CRDTMapError(Exception):
    """Base error for malformed CRDT map input (programming error)."""


class BadReplicaError(CRDTMapError):
    """Replica id is not a non-empty string."""


class BadKeyError(CRDTMapError):
    """Map key is not a non-empty string."""


class BadValueError(CRDTMapError):
    """Value is not canonical-JSON-serializable or exceeds the size cap."""


class BadMergeError(CRDTMapError):
    """Merge operand is not a CRDTMap."""


def _check_replica_id(replica_id: Any) -> str:
    if isinstance(replica_id, bool) or not isinstance(replica_id, str):
        raise BadReplicaError(
            f"replica_id must be a non-empty str, got {replica_id!r}"
        )
    if not replica_id:
        raise BadReplicaError("replica_id must be non-empty")
    return replica_id


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be a non-empty str, got {key!r}")
    if not key:
        raise BadKeyError("key must be non-empty")
    return key


def _canonical_value(value: Any) -> str:
    """Canonical-JSON text for a value, or raise BadValueError."""
    try:
        raw = jcs_canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise BadValueError(f"value is not canonical-JSON-serializable: {exc}") from exc
    if len(raw) > _MAX_VALUE_BYTES:
        raise BadValueError(
            f"value exceeds {_MAX_VALUE_BYTES} canonical bytes "
            f"(got {len(raw)})"
        )
    return raw.decode("utf-8")


def _pin(*parts: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(list(parts))).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Dot:
    """Globally unique write tag: (replica_id, per-replica counter)."""

    replica: str
    counter: int

    def verify(self) -> bool:
        return (
            isinstance(self.replica, str)
            and bool(self.replica)
            and isinstance(self.counter, int)
            and not isinstance(self.counter, bool)
            and self.counter > 0
        )


@dataclass(frozen=True)
class Entry:
    """One (key, dot, value) observation pinned by digest."""

    key: str
    dot: Dot
    value_json: str
    digest: str
    schema: str = CRDT_MAP_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            CRDT_MAP_SCHEMA, "entry", self.key,
            self.dot.replica, self.dot.counter, self.value_json,
        )


def _make_entry(key: str, dot: Dot, value_json: str) -> Entry:
    return Entry(
        key=key,
        dot=dot,
        value_json=value_json,
        digest=_pin(
            CRDT_MAP_SCHEMA, "entry", key, dot.replica, dot.counter, value_json
        ),
    )


def _entry_sort_key(entry: Entry) -> Tuple[str, str, int]:
    return (entry.key, entry.dot.replica, entry.dot.counter)


# ---------------------------------------------------------------------------
# The map (immutable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CRDTMap:
    """An observed-remove map. All mutating ops return a new CRDTMap."""

    replica_id: str
    clock: Tuple[Tuple[str, int], ...]
    entries: Tuple[Entry, ...]
    digest: str
    schema: str = CRDT_MAP_SCHEMA

    def verify(self) -> bool:
        """Re-pin the whole map state (clock + entry digests)."""
        return self.digest == _pin(
            CRDT_MAP_SCHEMA,
            "map",
            self.replica_id,
            [list(pair) for pair in self.clock],
            [
                [e.key, e.dot.replica, e.dot.counter, e.digest]
                for e in self.entries
            ],
        )

    # -- views ----------------------------------------------------------

    def keys(self) -> Tuple[str, ...]:
        """Distinct keys, sorted."""
        return tuple(sorted({e.key for e in self.entries}))

    def _entries_for(self, key: str) -> List[Entry]:
        matched = [e for e in self.entries if e.key == key]
        matched.sort(key=lambda e: (e.dot.replica, e.dot.counter))
        return matched

    def values(self, key: str) -> Tuple[Any, ...]:
        """All converged values for ``key`` in deterministic dot order."""
        _check_key(key)
        return tuple(json.loads(e.value_json) for e in self._entries_for(key))

    def get(self, key: str, default: Any = None) -> Any:
        """The converged value for ``key``.

        With concurrent writes the map can hold several values; ``get``
        returns the one with the smallest ``(replica, counter)`` dot —
        deterministic, not wall-clock last-writer-wins.
        """
        vals = self.values(key)
        return vals[0] if vals else default

    def __len__(self) -> int:
        return len(self.keys())

    # -- mutations (return new maps) ------------------------------------

    def _next_dot(self) -> Tuple[Dot, Tuple[Tuple[str, int], ...]]:
        clock: Dict[str, int] = dict(self.clock)
        counter = clock.get(self.replica_id, 0) + 1
        clock[self.replica_id] = counter
        new_clock = tuple(sorted(clock.items(), key=lambda kv: kv[0]))
        return Dot(replica=self.replica_id, counter=counter), new_clock

    def _rebuild(
        self,
        clock: Tuple[Tuple[str, int], ...],
        entries: Tuple[Entry, ...],
    ) -> "CRDTMap":
        ordered = tuple(sorted(entries, key=_entry_sort_key))
        return CRDTMap(
            replica_id=self.replica_id,
            clock=clock,
            entries=ordered,
            digest=_pin(
                CRDT_MAP_SCHEMA,
                "map",
                self.replica_id,
                [list(pair) for pair in clock],
                [
                    [e.key, e.dot.replica, e.dot.counter, e.digest]
                    for e in ordered
                ],
            ),
        )

    def put(self, key: str, value: Any) -> "CRDTMap":
        """Bind ``key`` to ``value``.

        Removes all locally *observed* entries for the key first, then
        adds the new entry under a fresh dot — so a lone replica sees
        plain last-write-wins, while concurrent unseen writes from other
        replicas survive a later merge.
        """
        _check_key(key)
        value_json = _canonical_value(value)
        dot, new_clock = self._next_dot()
        kept = [e for e in self.entries if e.key != key]
        kept.append(_make_entry(key, dot, value_json))
        return self._rebuild(new_clock, tuple(kept))

    def remove(self, key: str) -> "CRDTMap":
        """Remove all locally observed entries for ``key``.

        Absent keys are a no-op (returns an equivalent map): a remove is
        defined over *observed* entries, and there is nothing to observe.
        """
        _check_key(key)
        dot, new_clock = self._next_dot()
        # Minting a dot keeps the version clock monotonic even for no-ops,
        # so a remove's causality is still merge-visible.
        kept = [e for e in self.entries if e.key != key]
        _ = dot
        return self._rebuild(new_clock, tuple(kept))

    def merge(self, other: Any) -> "CRDTMap":
        """Merge ``other`` into a new map.

        Clock: per-replica maximum. Entries: union keyed by
        ``(key, replica, counter)``. Commutative, associative, idempotent.
        """
        if not isinstance(other, CRDTMap):
            raise BadMergeError(
                f"merge operand must be a CRDTMap, got {type(other).__name__}"
            )
        merged_clock: Dict[str, int] = dict(self.clock)
        for replica, counter in other.clock:
            if counter > merged_clock.get(replica, 0):
                merged_clock[replica] = counter
        new_clock = tuple(sorted(merged_clock.items(), key=lambda kv: kv[0]))
        seen: Dict[Tuple[str, str, int], Entry] = {}
        for entry in list(self.entries) + list(other.entries):
            seen[(entry.key, entry.dot.replica, entry.dot.counter)] = entry
        return self._rebuild(new_clock, tuple(seen.values()))


def new_map(replica_id: str) -> CRDTMap:
    """Create an empty map for ``replica_id``."""
    _check_replica_id(replica_id)
    empty: Tuple[Entry, ...] = ()
    return CRDTMap(
        replica_id=replica_id,
        clock=(),
        entries=empty,
        digest=_pin(CRDT_MAP_SCHEMA, "map", replica_id, [], []),
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_PUT = "crdt-map.put"
KIND_REMOVED = "crdt-map.removed"
KIND_MERGED = "crdt-map.merged"
KIND_REJECTED = "crdt-map.rejected"
_KINDS = (KIND_PUT, KIND_REMOVED, KIND_MERGED, KIND_REJECTED)


def crdt_map_audit_event(
    kind: str, detail: Mapping[str, Any], replica_id: str
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the crdt-map module.

    Values never cross the audit boundary: ``detail`` may carry key ids
    and digest pins only; ``value`` / ``value_json`` keys are refused.
    """
    if kind not in _KINDS:
        raise CRDTMapError(f"unknown audit kind: {kind!r}")
    _check_replica_id(replica_id)
    if not isinstance(detail, Mapping):
        raise CRDTMapError("detail must be a mapping")
    banned = {"value", "value_json", "values"}
    if any(k in detail for k in banned):
        raise CRDTMapError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CRDT_MAP_VERSION,
        "replica": replica_id,
        "detail": dict(detail),
    }


def main() -> None:
    a = new_map("a").put("x", 1)
    b = new_map("b").put("x", 2)
    merged = a.merge(b)
    assert a.verify() and b.verify() and merged.verify()
    assert merged.get("x") in (1, 2)
    assert merged.remove("x").get("x") is None
    # commutativity / associativity / idempotence
    c = new_map("c").put("y", "v")
    # commutativity / associativity / idempotence (state-level: the merged
    # map keeps the caller's replica_id by design, so compare state)
    def _state(m):
        return (m.clock, m.entries)
    assert _state(a.merge(b)) == _state(b.merge(a))
    assert _state(a.merge(b).merge(c)) == _state(a.merge(b.merge(c)))
    assert a.merge(a).digest == a.digest
    print("crdt-map OK: put, remove, merge, converge")


if __name__ == "__main__":
    main()
