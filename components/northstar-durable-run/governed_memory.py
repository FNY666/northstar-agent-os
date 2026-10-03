"""Governed memory: memory writes/reads go through the receipt system.

Absorbed from csalamando/harness-sdlc's governed memory
(``spec/memory/`` with SHA-256 receipt gates): memory is not a free-form
scratch pad the agent narrates about — every write is content-addressed
and every read re-verifies the receipt before the data is returned.

Design:

* ``write`` stores the value and emits a receipt binding the canonical
  SHA-256 of the exact content written. The receipt id is returned to the
  caller; the caller presents it on every subsequent read.
* ``read`` requires the receipt id and re-derives the digest from the
  stored content. If the content changed (external mutation, corruption),
  the receipt is invalidated and the read fails closed — the caller gets
  an error, never silently-stale data.
* ``revoke`` removes a memory entry with a mandatory reason, invalidating
  its receipt. Reads after revocation fail closed.
* Append-only history: every write appends a history record
  ``(seq, key, digest, issued_at)`` so the evolution of a key is auditable
  without trusting the current value's narrative.

This unifies with :mod:`tool_receipt` (per-call receipts) and
:mod:`receipt_gate` (gate receipts): all three use the same canonical
SHA-256, so digests are directly comparable across the receipt family.
"""
from __future__ import annotations

from typing import Any

from receipt_gate import Receipt, ReceiptGate, ReceiptGateError


class GovernedMemoryError(ValueError):
    """A governed memory operation was refused."""


class GovernedMemory:
    """Content-addressed memory where reads verify write receipts.

    Not thread-safe: drive one operation at a time per instance.
    """

    def __init__(self) -> None:
        self._gate = ReceiptGate()
        self._store: dict[str, tuple[Any, str]] = {}
        self._history: list[dict[str, Any]] = []
        self._seq = 0

    def write(
        self,
        key: str,
        value: Any,
        *,
        role: str = "",
        approved_by: str = "",
        issued_at: int,
    ) -> Receipt:
        """Store ``value`` under ``key`` and emit its write receipt.

        Returns the receipt; the caller must present ``receipt.receipt_id``
        on every read of this key.
        """
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        if not isinstance(issued_at, int) or isinstance(issued_at, bool):
            raise ValueError("issued_at must be an integer")
        receipt = self._gate.emit(
            gate=f"memory.write:{key}",
            content=value,
            role=role,
            approved_by=approved_by,
            issued_at=issued_at,
        )
        self._store[key] = (value, receipt.receipt_id)
        self._seq += 1
        self._history.append(
            {
                "seq": self._seq,
                "key": key,
                "digest": receipt.content_digest,
                "receipt_id": receipt.receipt_id,
                "issued_at": issued_at,
                "role": role,
            }
        )
        return receipt

    def read(self, key: str, receipt_id: str, *, now: int) -> Any:
        """Read ``key``, verifying the write receipt first.

        Fails closed when the key is missing, the receipt is unknown /
        revoked / invalidated, or the stored content no longer matches the
        receipt's digest (external mutation or corruption).
        """
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        entry = self._store.get(key)
        if entry is None:
            raise GovernedMemoryError(f"no memory entry: {key}")
        value, stored_receipt_id = entry
        if stored_receipt_id != receipt_id:
            raise GovernedMemoryError(
                f"receipt {receipt_id} does not govern memory key {key}"
            )
        try:
            self._gate.verify(receipt_id, value, now=now)
        except ReceiptGateError as error:
            raise GovernedMemoryError(str(error)) from error
        return value

    def revoke(self, key: str, *, reason: str, now: int) -> Receipt:
        """Revoke a memory entry with a mandatory reason.

        The receipt is revoked and the entry removed; subsequent reads
        fail closed.
        """
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        entry = self._store.get(key)
        if entry is None:
            raise GovernedMemoryError(f"no memory entry: {key}")
        _, receipt_id = entry
        receipt = self._gate.revoke(receipt_id, reason=reason, now=now)
        del self._store[key]
        return receipt

    def history(self, key: str | None = None) -> tuple[dict[str, Any], ...]:
        """Append-only write history, optionally filtered by key."""
        if key is None:
            return tuple(self._history)
        return tuple(h for h in self._history if h["key"] == key)

    def receipt_for(self, key: str) -> Receipt | None:
        """Return the current write receipt for ``key``, if any."""
        entry = self._store.get(key)
        if entry is None:
            return None
        return self._gate.get(entry[1])
