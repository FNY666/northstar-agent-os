"""Bitemporal memory record model with supersession and decay.

P0 production wiring: memory write/read needs bitemporal semantics,
supersession, and decay — not just an append-only log.

Bitemporal model (no wall-clock; every time is a caller-supplied integer
sequence number):

* **valid_time** — when the fact was true in the world:
  ``valid_from_seq`` .. ``valid_to_seq`` (``None`` = still true).
* **transaction_time** — when the record entered the store: ``txn_seq``.

A record is *current* when ``valid_to_seq is None`` and not expired.
``get_valid(at_seq)`` answers "what did we believe was true at ``at_seq``?"
by filtering on valid_time, so history is queryable — supersession never
deletes, it only closes the old record's valid interval.

Supersession
------------
``supersede(old_id, new_content, txn_seq)`` closes the old record
(``valid_to_seq = txn_seq``) and mints a new record whose
``supersedes_id`` points at the old one. The old record stays in the store
for audit; ``history(id)`` walks the chain.

Decay
-----
A current record that has not been accessed for longer than
``decay_threshold`` sequence points is marked ``expired`` by
``apply_decay``. Expired records are excluded from ``get_valid`` but remain
in the store (auditability). ``access(id, at_seq)`` refreshes
``last_accessed_seq`` and prevents decay — reinforcement keeps memories
alive, neglect lets them fade.

Honest scope: decay is staleness-based, not semantic — a frequently
accessed falsehood does not decay, and a neglected truth does. This module
is the *lifecycle* layer; truth adjudication belongs to the write-path
admission gate, not here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


#: Schema pin for records minted by this module.
MEMORY_BITEMPORAL_VERSION = "memory-bitemporal.v1"


def _check_seq(name: str, value: Any) -> int:
    """Validate a sequence number: int, not bool, non-negative."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


@dataclass(frozen=True)
class MemoryRecord:
    """One bitemporal memory record. Immutable once minted."""

    id: str
    content: str
    valid_from_seq: int
    valid_to_seq: int | None  # None = still valid (open interval)
    txn_seq: int  # transaction time: when this record was written
    supersedes_id: str | None  # id of the record this one replaces, if any
    last_accessed_seq: int
    expired: bool = False

    def is_current(self) -> bool:
        """True when the record is still valid and not expired."""
        return self.valid_to_seq is None and not self.expired

    def valid_at(self, at_seq: int) -> bool:
        """True when this record's valid interval covers ``at_seq``."""
        _check_seq("at_seq", at_seq)
        if self.expired:
            return False
        if at_seq < self.valid_from_seq:
            return False
        if self.valid_to_seq is not None and at_seq >= self.valid_to_seq:
            return False
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "valid_from_seq": self.valid_from_seq,
            "valid_to_seq": self.valid_to_seq,
            "txn_seq": self.txn_seq,
            "supersedes_id": self.supersedes_id,
            "last_accessed_seq": self.last_accessed_seq,
            "expired": self.expired,
            "version": MEMORY_BITEMPORAL_VERSION,
        }


class MemoryNotFoundError(KeyError):
    """Raised when a record id is unknown to the store."""


class MemorySupersedeError(ValueError):
    """Raised when a supersede request is invalid (fail-closed)."""


class BitemporalMemoryStore:
    """In-memory bitemporal store with supersession and decay.

    All time is caller-supplied sequence numbers. The store never reads a
    clock. Records are immutable; supersession and decay produce *new*
    record objects that replace the old ones in the index — the old objects
    are never mutated, so a caller holding a reference sees a stable
    snapshot.
    """

    def __init__(self) -> None:
        self._records: dict[str, MemoryRecord] = {}
        self._counter: int = 0

    def _mint_id(self) -> str:
        self._counter += 1
        return f"mem-{self._counter}"

    def __len__(self) -> int:
        return len(self._records)

    def get(self, record_id: str) -> MemoryRecord:
        """Return the record, or raise ``MemoryNotFoundError``."""
        try:
            return self._records[record_id]
        except KeyError:
            raise MemoryNotFoundError(f"unknown memory record: {record_id!r}")

    def write(
        self,
        content: str,
        txn_seq: int,
        *,
        valid_from_seq: int | None = None,
    ) -> MemoryRecord:
        """Write a new independent record (no supersession link).

        ``valid_from_seq`` defaults to ``txn_seq``; it may be backdated
        (the fact was true before we recorded it) but never postdated
        beyond ``txn_seq``.
        """
        if not isinstance(content, str) or not content:
            raise ValueError("content must be a non-empty str")
        txn_seq = _check_seq("txn_seq", txn_seq)
        if valid_from_seq is None:
            valid_from_seq = txn_seq
        else:
            valid_from_seq = _check_seq("valid_from_seq", valid_from_seq)
        if valid_from_seq > txn_seq:
            raise ValueError(
                f"valid_from_seq ({valid_from_seq}) cannot be after "
                f"txn_seq ({txn_seq})"
            )
        record = MemoryRecord(
            id=self._mint_id(),
            content=content,
            valid_from_seq=valid_from_seq,
            valid_to_seq=None,
            txn_seq=txn_seq,
            supersedes_id=None,
            last_accessed_seq=txn_seq,
        )
        self._records[record.id] = record
        return record

    def supersede(
        self,
        old_id: str,
        new_content: str,
        txn_seq: int,
        *,
        valid_from_seq: int | None = None,
    ) -> MemoryRecord:
        """Replace ``old_id`` with a new record carrying ``new_content``.

        Fail-closed: the old record must exist, be currently valid
        (``valid_to_seq is None``), and not be expired. The old record is
        closed at ``txn_seq``; the new record links back via
        ``supersedes_id``.
        """
        if not isinstance(new_content, str) or not new_content:
            raise ValueError("new_content must be a non-empty str")
        txn_seq = _check_seq("txn_seq", txn_seq)
        old = self.get(old_id)
        if old.valid_to_seq is not None:
            raise MemorySupersedeError(
                f"cannot supersede {old_id!r}: already superseded "
                f"(valid_to_seq={old.valid_to_seq})"
            )
        if old.expired:
            raise MemorySupersedeError(
                f"cannot supersede {old_id!r}: record is expired"
            )
        if txn_seq < old.txn_seq:
            raise MemorySupersedeError(
                f"cannot supersede {old_id!r} at txn_seq={txn_seq}: "
                f"before the record's own txn_seq={old.txn_seq}"
            )
        if valid_from_seq is None:
            valid_from_seq = txn_seq
        else:
            valid_from_seq = _check_seq("valid_from_seq", valid_from_seq)
        if valid_from_seq > txn_seq:
            raise ValueError(
                f"valid_from_seq ({valid_from_seq}) cannot be after "
                f"txn_seq ({txn_seq})"
            )
        # Close the old record: valid interval ends at the superseding txn.
        closed_old = MemoryRecord(
            id=old.id,
            content=old.content,
            valid_from_seq=old.valid_from_seq,
            valid_to_seq=txn_seq,
            txn_seq=old.txn_seq,
            supersedes_id=old.supersedes_id,
            last_accessed_seq=old.last_accessed_seq,
            expired=old.expired,
        )
        self._records[old.id] = closed_old
        new = MemoryRecord(
            id=self._mint_id(),
            content=new_content,
            valid_from_seq=valid_from_seq,
            valid_to_seq=None,
            txn_seq=txn_seq,
            supersedes_id=old.id,
            last_accessed_seq=txn_seq,
        )
        self._records[new.id] = new
        return new

    def get_valid(self, at_seq: int) -> list[MemoryRecord]:
        """All non-expired records whose valid interval covers ``at_seq``.

        Deterministic order: by ``txn_seq``, then by id.
        """
        _check_seq("at_seq", at_seq)
        result = [r for r in self._records.values() if r.valid_at(at_seq)]
        result.sort(key=lambda r: (r.txn_seq, r.id))
        return result

    def get_current(self) -> list[MemoryRecord]:
        """All records that are still valid and not expired."""
        result = [r for r in self._records.values() if r.is_current()]
        result.sort(key=lambda r: (r.txn_seq, r.id))
        return result

    def history(self, record_id: str) -> list[MemoryRecord]:
        """The full supersession chain containing ``record_id``.

        Walks back via ``supersedes_id`` to the oldest ancestor, then
        forward to the newest descendant. Ordered oldest → newest.
        """
        node = self.get(record_id)
        # Walk back to the oldest ancestor.
        while node.supersedes_id is not None:
            node = self.get(node.supersedes_id)
        # Walk forward to the newest descendant.
        chain = [node]
        while True:
            children = [
                r for r in self._records.values() if r.supersedes_id == chain[-1].id
            ]
            if not children:
                break
            if len(children) > 1:
                # Should be impossible: supersede() closes the old record,
                # so only one live successor can exist. Fail loudly if the
                # invariant ever breaks.
                raise AssertionError(
                    f"multiple successors for {chain[-1].id!r}: "
                    f"{[c.id for c in children]}"
                )
            chain.append(children[0])
        return chain

    def access(self, record_id: str, at_seq: int) -> MemoryRecord:
        """Record an access: refresh ``last_accessed_seq`` (anti-decay).

        Returns the refreshed record. Accessing an expired record does not
        un-expire it — expiry is sticky; only a fresh write/supersede
        brings the content back.
        """
        at_seq = _check_seq("at_seq", at_seq)
        record = self.get(record_id)
        if at_seq < record.last_accessed_seq:
            raise ValueError(
                f"at_seq ({at_seq}) cannot go backwards from "
                f"last_accessed_seq ({record.last_accessed_seq})"
            )
        refreshed = MemoryRecord(
            id=record.id,
            content=record.content,
            valid_from_seq=record.valid_from_seq,
            valid_to_seq=record.valid_to_seq,
            txn_seq=record.txn_seq,
            supersedes_id=record.supersedes_id,
            last_accessed_seq=at_seq,
            expired=record.expired,
        )
        self._records[record.id] = refreshed
        return refreshed

    def apply_decay(
        self, current_seq: int, decay_threshold: int
    ) -> list[str]:
        """Expire current records idle longer than ``decay_threshold``.

        A record decays when
        ``current_seq - last_accessed_seq > decay_threshold``. Only
        *current* records (still valid, not already expired) are eligible —
        superseded history is audit, not live memory, and never decays.
        Returns the ids that were expired, in deterministic order.
        """
        current_seq = _check_seq("current_seq", current_seq)
        decay_threshold = _check_seq("decay_threshold", decay_threshold)
        expired_ids: list[str] = []
        for record in sorted(self._records.values(), key=lambda r: r.id):
            if not record.is_current():
                continue
            if current_seq - record.last_accessed_seq > decay_threshold:
                decayed = MemoryRecord(
                    id=record.id,
                    content=record.content,
                    valid_from_seq=record.valid_from_seq,
                    valid_to_seq=record.valid_to_seq,
                    txn_seq=record.txn_seq,
                    supersedes_id=record.supersedes_id,
                    last_accessed_seq=record.last_accessed_seq,
                    expired=True,
                )
                self._records[record.id] = decayed
                expired_ids.append(record.id)
        return expired_ids


def main() -> None:
    store = BitemporalMemoryStore()
    r1 = store.write("the sky is blue", txn_seq=10)
    r2 = store.supersede(r1.id, "the sky is gray", txn_seq=20)
    store.access(r2.id, at_seq=25)
    expired = store.apply_decay(current_seq=100, decay_threshold=50)
    print(
        f"memory-bitemporal OK: {len(store)} records, "
        f"{len(store.get_current())} current, "
        f"{len(expired)} decayed, "
        f"history({r2.id})={len(store.history(r2.id))}"
    )


if __name__ == "__main__":
    main()
