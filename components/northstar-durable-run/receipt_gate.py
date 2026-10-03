"""SHA-256 receipt gates: critical operations require a valid receipt first.

Absorbed from csalamando/harness-sdlc's ``receipt.py`` (Spanish source, MIT):
the principle is "confiar en lo que el sistema puede derivar, no en la
narracion del agente" — trust what the system can derive, not the agent's
narrative. When a gate passes, a receipt is emitted carrying the SHA-256 of
the exact artifact. Downstream gates VERIFY the receipt: if the artifact
changed one byte, the receipt no longer applies and the approval is
automatically invalidated.

Northstar unification: this module generalizes the per-call tool receipts
(``tool_receipt.py``) into a gate pattern for *any* critical operation:

* ``emit`` — record a receipt when a prerequisite passes, binding the
  SHA-256 of the governed content.
* ``verify`` — before a critical operation proceeds, check the receipt
  exists, is ``valid``, and the content hash still matches. Any mismatch
  fails closed.
* ``revoke`` — manual revocation with a mandatory reason (a revocation
  without a declared cause is noise, not audit).
* Dependency tracking — an upstream change derivatively invalidates
  downstream receipts, so stale approvals cannot authorize new work.

Receipt states: ``valid`` → ``invalidated`` (content changed) or
``revoked`` (manual). A receipt never returns to ``valid``; re-approval
emits a new receipt. This is the same append-only discipline as the audit
hash chain: history is not rewritten.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


RECEIPT_GATE_SCHEMA_VERSION = "northstar.receipt-gate.v1"

_STATE_VALID = "valid"
_STATE_INVALIDATED = "invalidated"
_STATE_REVOKED = "revoked"


def canonical_sha256_hex(value: Any) -> str:
    """SHA-256 hex of the canonical JSON encoding of ``value``.

    Canonicalization matches :func:`tool_receipt.canonical_sha256_hex`
    (sorted keys, compact separators, UTF-8, non-ASCII unescaped) so
    digests computed here are directly comparable with tool receipts.
    """
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("value is not canonical JSON") from error
    return hashlib.sha256(encoded).hexdigest()


class ReceiptGateError(ValueError):
    """A receipt gate refused to let a critical operation proceed."""


@dataclass
class Receipt:
    """One SHA-256 receipt binding a gate decision to exact content."""

    receipt_id: str
    gate: str
    content_digest: str
    state: str = _STATE_VALID
    role: str = ""
    approved_by: str = ""
    issued_at: int = 0
    invalidated_at: int | None = None
    revoked_at: int | None = None
    revoke_reason: str = ""
    deps: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RECEIPT_GATE_SCHEMA_VERSION,
            "receipt_id": self.receipt_id,
            "gate": self.gate,
            "content_digest": self.content_digest,
            "state": self.state,
            "role": self.role,
            "approved_by": self.approved_by,
            "issued_at": self.issued_at,
            "invalidated_at": self.invalidated_at,
            "revoked_at": self.revoked_at,
            "revoke_reason": self.revoke_reason,
            "deps": dict(self.deps),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Receipt":
        if data.get("schema_version") != RECEIPT_GATE_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {RECEIPT_GATE_SCHEMA_VERSION}"
            )
        return cls(
            receipt_id=data["receipt_id"],
            gate=data["gate"],
            content_digest=data["content_digest"],
            state=data.get("state", _STATE_VALID),
            role=data.get("role", ""),
            approved_by=data.get("approved_by", ""),
            issued_at=data.get("issued_at", 0),
            invalidated_at=data.get("invalidated_at"),
            revoked_at=data.get("revoked_at"),
            revoke_reason=data.get("revoke_reason", ""),
            deps=dict(data.get("deps") or {}),
            metadata=dict(data.get("metadata") or {}),
        )


class ReceiptGate:
    """Gate registry: emit, verify, and revoke SHA-256 receipts.

    A critical operation calls :meth:`require` with the receipt id it
    depends on; the gate re-derives the content digest and fails closed on
    any mismatch. The gate itself never trusts a stored digest — it
    recomputes from the content presented at call time.
    """

    def __init__(self) -> None:
        self._receipts: dict[str, Receipt] = {}

    def emit(
        self,
        *,
        gate: str,
        content: Any,
        role: str = "",
        approved_by: str = "",
        issued_at: int,
        deps: dict[str, str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Receipt:
        """Emit a receipt when a gate passes, binding the content digest.

        ``content`` is the exact governed value (dict, list, or scalar);
        its canonical SHA-256 becomes the receipt's ``content_digest``.
        ``deps`` maps upstream receipt ids to their digests at emit time,
        so an upstream change derivatively invalidates this receipt.
        """
        if not isinstance(gate, str) or not gate:
            raise ValueError("gate must be a non-empty string")
        if not isinstance(issued_at, int) or isinstance(issued_at, bool):
            raise ValueError("issued_at must be an integer")
        digest = canonical_sha256_hex(content)
        receipt_id = f"gate:{gate}:{digest}"
        receipt = Receipt(
            receipt_id=receipt_id,
            gate=gate,
            content_digest=digest,
            role=role,
            approved_by=approved_by,
            issued_at=issued_at,
            deps=dict(deps) if deps else {},
            metadata=dict(metadata) if metadata else {},
        )
        self._receipts[receipt_id] = receipt
        return receipt

    def verify(
        self,
        receipt_id: str,
        content: Any,
        *,
        now: int,
        dep_contents: dict[str, Any] | None = None,
    ) -> Receipt:
        """Verify a receipt against the presented content; fail closed.

        Recomputes the content digest and compares it with the receipt.
        Also re-checks every declared dependency: an upstream change
        invalidates this receipt derivatively. Raises
        :class:`ReceiptGateError` on any mismatch; returns the receipt
        when everything checks out.
        """
        receipt = self._receipts.get(receipt_id)
        if receipt is None:
            raise ReceiptGateError(f"no receipt: {receipt_id}")
        if receipt.state == _STATE_REVOKED:
            raise ReceiptGateError(
                f"receipt revoked: {receipt_id} ({receipt.revoke_reason})"
            )
        if receipt.state == _STATE_INVALIDATED:
            raise ReceiptGateError(f"receipt invalidated: {receipt_id}")
        actual = canonical_sha256_hex(content)
        if actual != receipt.content_digest:
            receipt.state = _STATE_INVALIDATED
            receipt.invalidated_at = now
            raise ReceiptGateError(
                f"receipt invalidated: content changed since {receipt.gate} "
                f"approval (expected {receipt.content_digest[:16]}..., "
                f"got {actual[:16]}...)"
            )
        # Derivative invalidation: an upstream dependency changed.
        for dep_id, old_digest in receipt.deps.items():
            dep_content = (dep_contents or {}).get(dep_id)
            if dep_content is None:
                receipt.state = _STATE_INVALIDATED
                receipt.invalidated_at = now
                raise ReceiptGateError(
                    f"receipt invalidated: dependency {dep_id} content "
                    "not presented for re-verification"
                )
            if canonical_sha256_hex(dep_content) != old_digest:
                receipt.state = _STATE_INVALIDATED
                receipt.invalidated_at = now
                raise ReceiptGateError(
                    f"receipt invalidated derivatively: upstream "
                    f"dependency {dep_id} changed since approval"
                )
        return receipt

    def require(self, receipt_id: str, content: Any, *, now: int) -> Receipt:
        """Alias for :meth:`verify` — the gate a critical operation calls."""
        return self.verify(receipt_id, content, now=now)

    def revoke(self, receipt_id: str, *, reason: str, now: int) -> Receipt:
        """Revoke a receipt. ``reason`` is mandatory — a revocation without
        a declared cause is noise, not audit (harness-sdlc ADR-004)."""
        if not isinstance(reason, str) or not reason:
            raise ValueError("revoke requires a non-empty reason")
        receipt = self._receipts.get(receipt_id)
        if receipt is None:
            raise ReceiptGateError(f"no receipt: {receipt_id}")
        receipt.state = _STATE_REVOKED
        receipt.revoked_at = now
        receipt.revoke_reason = reason
        return receipt

    def get(self, receipt_id: str) -> Receipt | None:
        """Return the receipt, if any (no verification performed)."""
        return self._receipts.get(receipt_id)

    def status(self) -> list[dict[str, Any]]:
        """List all receipts with their state (operational overview)."""
        return [r.to_dict() for r in self._receipts.values()]
