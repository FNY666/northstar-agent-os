"""Compaction guard that never masks approval receipts.

Composition of ``compaction_masking`` (observation redaction for
compaction) and ``signed_receipt_reflux`` (signed approval receipts with
reflux delivery).

The invariant: when a transcript is compacted, the audit trail — every
approval receipt — must survive byte-identical. Masking exists for
*observations* (tool outputs, user pastes); receipts are *evidence* and
are exempt. A masking rule that rewrites an approver identity or a
request id (``human:alice@example.com`` matches the email pattern,
``req-sk-...`` matches the api-key pattern) would silently corrupt the
audit trail, so receipt records bypass masking entirely.

Design:

* **HistoryEntry** — frozen record. ``kind`` is ``"narrative"`` (free
  text, maskable) or ``"receipt"`` (an approval record, never masked).
  Receipt entries carry ``request_id``; narrative entries must not.
* **CompactionApprovalGuard** — constructed with the approver's Ed25519
  public key. Receipts are registered first (``register_receipt``);
  registration verifies the signature and refuses anything
  unverifiable (fail closed). ``compact`` then:
    1. masks narrative entries through
       ``compaction_masking.CompactionGate``,
    2. re-emits receipt entries from the *registry* in canonical form
       (the registry is the source of truth, so a caller cannot smuggle
       a forged receipt record through the payload),
    3. re-verifies every emitted receipt against the approver key as a
       post-condition — a receipt that no longer verifies aborts the
       compaction loudly (that would be a guard bug, not a policy
       decision).
  A receipt entry whose ``request_id`` was never registered is refused:
  compacting an approval record the guard never saw would silently drop
  evidence.
* **Audit trail** — the guard keeps an append-only, caller-sequenced
  log of its own decisions (registrations, compactions, refusals).
  Audit records are structured data and are never masked.
* **verify_output** — pure function: re-verify every receipt record in
  a ``GuardedCompaction`` against a public key. Downstream consumers
  can confirm the audit trail survived without trusting the guard.

Honest scope: this protects the *record* of approvals through
compaction. It does not defend against a compromised approver key
(whoever holds the secret can mint receipts — see
``signed_receipt_reflux``), and it only sees receipt entries the
caller labels as such: a receipt pasted as narrative text is masked
like any other observation. Hosts must route approval records through
the ``"receipt"`` kind.

No wall-clock reads anywhere; all sequence numbers are caller-supplied.
Deterministic: same inputs, same bytes, same verdict. Stdlib-only
apart from the two sibling modules and ``ed25519`` (via the receipt
module).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import signed_receipt_reflux as srr
from compaction_masking import CompactionGate


#: Version of this composition. Bump when the guard semantics change.
COMPACTION_APPROVAL_VERSION = "compaction-approval-combo.v1"

#: Schema pin for the guard's own records.
SCHEMA_PIN = "northstar.compaction-approval-combo.v1"

#: History entry kinds.
NARRATIVE = "narrative"
RECEIPT = "receipt"


class CompactionGuardError(ValueError):
    """The guard refused to compact: missing receipt, bad entry, or a
    post-condition failure. Raised loudly — silently dropping or
    rewriting approval evidence would corrupt the audit trail."""


def _check_pubkey(pubkey: Any) -> bytes:
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        raise srr.ReceiptError("approver public key must be 32 bytes")
    return bytes(pubkey)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def serialize_receipt(receipt: srr.SignedReceipt) -> str:
    """Canonical string form of a receipt for the compacted record.

    Deterministic: the same receipt always serializes to the same
    string, so a downstream verifier can byte-compare.
    """
    if not isinstance(receipt, srr.SignedReceipt):
        raise CompactionGuardError(
            f"can only serialize a SignedReceipt, got {type(receipt).__name__}"
        )
    return _canonical_json(receipt.as_dict())


def _receipt_from_record(text: str) -> Optional[srr.SignedReceipt]:
    """Parse a canonical receipt record back into a SignedReceipt.

    Returns None (never raises) on anything unparseable — the caller is
    a verifier and verifiers fail closed, not loudly.
    """
    try:
        d = json.loads(text)
        return srr.SignedReceipt(
            request_id=d["request_id"],
            action=d["action"],
            approver=d["approver"],
            approved_at_seq=d["approved_at_seq"],
            signature=bytes.fromhex(d["signature"]),
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HistoryEntry:
    """One unit of history presented to the guard.

    ``kind`` is ``"narrative"`` (maskable free text) or ``"receipt"``
    (an approval record, passed through verbatim). Receipt entries must
    carry ``request_id``; narrative entries must not.
    """

    kind: str
    payload: str
    request_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind not in (NARRATIVE, RECEIPT):
            raise CompactionGuardError(
                f"kind must be {NARRATIVE!r} or {RECEIPT!r}, got {self.kind!r}"
            )
        if not isinstance(self.payload, str):
            raise TypeError(
                f"payload must be str, got {type(self.payload).__name__}"
            )
        if self.kind == RECEIPT:
            if not isinstance(self.request_id, str) or not self.request_id:
                raise CompactionGuardError(
                    "receipt entries must carry a non-empty request_id"
                )
        elif self.request_id is not None:
            raise CompactionGuardError(
                "narrative entries must not carry a request_id"
            )


@dataclass(frozen=True)
class GuardAuditEvent:
    """One append-only audit record of the guard's own decisions."""

    seq: int
    kind: str  # "receipt-registered" | "compaction-completed" | "receipt-refused"
    request_id: str
    detail: str

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:
            raise CompactionGuardError("seq must be a non-negative int")
        if not isinstance(self.kind, str) or not self.kind:
            raise CompactionGuardError("kind must be a non-empty str")
        if not isinstance(self.request_id, str):
            raise CompactionGuardError("request_id must be str")
        if not isinstance(self.detail, str):
            raise CompactionGuardError("detail must be str")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "request_id": self.request_id,
            "detail": self.detail,
            "schema": SCHEMA_PIN,
            "version": COMPACTION_APPROVAL_VERSION,
        }


@dataclass(frozen=True)
class GuardedCompaction:
    """The compacted history: narratives masked, receipts verbatim."""

    entries: Tuple[HistoryEntry, ...]
    masked_any: bool
    redaction_counts: Tuple[Tuple[str, int], ...]
    receipt_request_ids: Tuple[str, ...]
    receipt_digests: Tuple[str, ...]
    masking_version: str
    guard_version: str = COMPACTION_APPROVAL_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entries": len(self.entries),
            "masked_any": self.masked_any,
            "redaction_counts": dict(self.redaction_counts),
            "receipt_request_ids": list(self.receipt_request_ids),
            "receipt_digests": list(self.receipt_digests),
            "masking_version": self.masking_version,
            "guard_version": self.guard_version,
            "schema": SCHEMA_PIN,
        }


# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------


class CompactionApprovalGuard:
    """Masks history for compaction while keeping approval receipts intact.

    Construct with the approver's 32-byte Ed25519 public key. Register
    every receipt that may appear in the history *before* compacting;
    the registry is the source of truth for what a receipt record
    contains.
    """

    def __init__(self, approver_pubkey: bytes, *, masking_enabled: bool = True) -> None:
        self._pubkey = _check_pubkey(approver_pubkey)
        self._gate = CompactionGate(enabled=masking_enabled)
        self._receipts: Dict[str, srr.SignedReceipt] = {}
        self._audit: List[GuardAuditEvent] = []
        self._seq = 0

    def _log(self, kind: str, request_id: str, detail: str) -> None:
        self._audit.append(
            GuardAuditEvent(seq=self._seq, kind=kind,
                            request_id=request_id, detail=detail)
        )
        self._seq += 1

    def register_receipt(self, receipt: srr.SignedReceipt) -> str:
        """Register a receipt the guard may later emit.

        The signature is verified now; an unverifiable receipt is
        refused (fail closed). Returns the receipt digest pin. Replacing
        an already-registered request id is refused — a receipt
        authorizes exactly one action.
        """
        if not isinstance(receipt, srr.SignedReceipt):
            raise CompactionGuardError(
                f"can only register a SignedReceipt, got {type(receipt).__name__}"
            )
        if not srr.verify_receipt(receipt, self._pubkey):
            self._log("receipt-refused", getattr(receipt, "request_id", "?"),
                      "signature verification failed at registration")
            raise CompactionGuardError(
                f"refusing to register unverifiable receipt for "
                f"{receipt.request_id!r}"
            )
        if receipt.request_id in self._receipts:
            raise CompactionGuardError(
                f"request_id {receipt.request_id!r} already registered"
            )
        self._receipts[receipt.request_id] = receipt
        digest = srr.receipt_digest(receipt)
        self._log("receipt-registered", receipt.request_id, digest)
        return digest

    def registered(self) -> Tuple[str, ...]:
        """Request ids with registered receipts, in registration order."""
        return tuple(self._receipts.keys())

    def receipt_digests(self) -> Tuple[str, ...]:
        """Digest pins of all registered receipts, in registration order."""
        return tuple(srr.receipt_digest(r) for r in self._receipts.values())

    def audit_events(self) -> Tuple[GuardAuditEvent, ...]:
        """The guard's append-only audit trail (never masked)."""
        return tuple(self._audit)

    def compact(self, history: Sequence[HistoryEntry]) -> GuardedCompaction:
        """Compact ``history``: mask narratives, pass receipts through.

        Raises :class:`CompactionGuardError` if a receipt entry names an
        unregistered request id, or if a post-compaction re-verification
        fails (the latter indicates a guard bug — it is raised loudly,
        never swallowed).
        """
        entries = tuple(history)
        for entry in entries:
            if not isinstance(entry, HistoryEntry):
                raise TypeError(
                    f"history entries must be HistoryEntry, "
                    f"got {type(entry).__name__}"
                )

        # Mask narratives through the masking gate; keep order alignment.
        narrative_idx = [i for i, e in enumerate(entries) if e.kind == NARRATIVE]
        masked_narratives = self._gate.approve_for_compaction(
            [entries[i].payload for i in narrative_idx]
        )

        out: List[HistoryEntry] = [None] * len(entries)  # type: ignore[list-item]
        for pos, i in enumerate(narrative_idx):
            out[i] = HistoryEntry(kind=NARRATIVE,
                                  payload=masked_narratives.entries[pos])

        receipt_ids: List[str] = []
        for i, entry in enumerate(entries):
            if entry.kind != RECEIPT:
                continue
            assert entry.request_id is not None
            receipt = self._receipts.get(entry.request_id)
            if receipt is None:
                self._log("receipt-refused", entry.request_id,
                          "compaction referenced an unregistered request_id")
                raise CompactionGuardError(
                    f"no registered receipt for request_id {entry.request_id!r}; "
                    f"refusing to compact rather than drop approval evidence"
                )
            # Emit from the registry, not the caller's payload: the guard
            # cannot be used to smuggle a forged receipt record.
            out[i] = HistoryEntry(kind=RECEIPT,
                                  payload=serialize_receipt(receipt),
                                  request_id=entry.request_id)
            receipt_ids.append(entry.request_id)

        result = GuardedCompaction(
            entries=tuple(out),
            masked_any=masked_narratives.masked_any,
            redaction_counts=masked_narratives.redaction_counts,
            receipt_request_ids=tuple(receipt_ids),
            receipt_digests=tuple(
                srr.receipt_digest(self._receipts[r]) for r in receipt_ids
            ),
            masking_version=masked_narratives.masking_version,
        )

        # Post-condition: every emitted receipt still verifies. This is
        # the composition's proof that masking never touched the evidence.
        if not verify_output(result, self._pubkey):
            raise CompactionGuardError(
                "post-compaction receipt re-verification failed"
            )
        self._log("compaction-completed", ",".join(receipt_ids) or "-",
                  f"{len(entries)} entries, {len(receipt_ids)} receipts, "
                  f"masked_any={masked_narratives.masked_any}")
        return result


def verify_output(compaction: GuardedCompaction,
                  approver_pubkey: bytes) -> bool:
    """Re-verify every receipt record in a GuardedCompaction.

    Returns True only if each ``"receipt"`` entry parses as a
    SignedReceipt and verifies under ``approver_pubkey``. Never raises
    on policy (fail-closed); raises TypeError on a non-compaction
    input (programming error).
    """
    if not isinstance(compaction, GuardedCompaction):
        raise TypeError(
            f"verify_output expects GuardedCompaction, "
            f"got {type(compaction).__name__}"
        )
    try:
        pubkey = _check_pubkey(approver_pubkey)
    except srr.ReceiptError:
        return False
    for entry in compaction.entries:
        if entry.kind != RECEIPT:
            continue
        receipt = _receipt_from_record(entry.payload)
        if receipt is None:
            return False
        if not srr.verify_receipt(receipt, pubkey):
            return False
    return True


def main() -> None:
    """Self-check: register, compact, verify."""
    import ed25519

    secret = bytes(range(32))
    pubkey = ed25519.public_key(secret)
    guard = CompactionApprovalGuard(pubkey)
    # Approver identity and request id deliberately contain maskable shapes.
    receipt = srr.issue_receipt("req-sk-1234567890abcdef",
                                "tool:delete:/tmp/x",
                                "human:alice@example.com", 7, secret)
    guard.register_receipt(receipt)
    history = [
        HistoryEntry(kind=NARRATIVE,
                     payload="the api key is sk-abcDEF1234567890 for the account"),
        HistoryEntry(kind=RECEIPT, payload="ignored-smuggled-payload",
                     request_id="req-sk-1234567890abcdef"),
    ]
    out = guard.compact(history)
    assert out.entries[0].payload == \
        "the api key is [REDACTED:api_key] for the account"
    assert "alice@example.com" in out.entries[1].payload  # verbatim, not masked
    assert "req-sk-1234567890abcdef" in out.entries[1].payload
    assert verify_output(out, pubkey)
    assert len(guard.audit_events()) == 2  # registered + compaction-completed
    print("compaction-approval-combo OK: receipts survive compaction verbatim")


if __name__ == "__main__":
    main()
