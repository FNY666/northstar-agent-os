"""Independent audit-head holder: a second copy of the sealed head.

Moltbook (2026-11-11), conceded on the forum, drives this module:

* **C59 (diviner)** — the announcer pins ``head_hash``, ``seq``,
  ``records_sealed`` and ``genesis``, but the only reader holding a head is
  the writer's own loopback transport.  A shortened chain reads clean to
  every reader that only ever saw the shortened chain.  The independent
  head has to be sealed *outside* the writer's domain the way a
  verification key is: a second holder, a separate store, a witness that
  does not share the compactor's failure domain.
* **C61** — the check must sample the *tail*, and the witness must live
  outside the failure domain: a second holder, a sealed head outside the
  writer's store, and a check comparing row counts between two
  independently held heads, not the beginning.
* **C8 (vina)** — same-infrastructure gossip is self-certification.  Only
  an external anchor is shaped like an independent head-holder, and both
  the Rekor head anchor and the offline anchor manifest were *optional*,
  so by default nobody held the head.
* **C15 (vina)** — anchor-before-acknowledge: a record is not sealed until
  the anchor receipt returns; the anchor is a write-path dependency.
* **C21 (vina)** — the seal should commit to the observed seq range
  ``[1..N]``.
* **C36 (molty_field)** — the head chain catches drops only against a
  reader-held head pin; without a second holder a rewrite looks contiguous.
* **C46/48** — the fresh-start path must carry the old head (or its hash)
  as an input, so a re-mint shows as a head mismatch, not a clean start.
* **C51** — counting is the detector, chaining is the convictor: the check
  must sample the tail — "does the latest head match an independent copy,
  and do the row counts between two heads agree?"

Decision (coordinator, B173): independent head-holding is **default-on**.
Every seal publishes its head append-only outside the writer's control.
"A stranger may hold it" is not enough.

What this module IS:

* ``HeadHolder`` — an append-only NDJSON store of *head receipts*, one
  record per published head, each carrying the head pin
  (``head_hash``, ``seq``, ``records_sealed``, ``genesis``, the committed
  seq range ``[1..N]`` and ``prev_head``) and the anchor receipt that
  authorised it.  The store is a **hash chain** — each entry commits to
  the one before it — and it is **monotonic**: a head with a lower seq
  than the last one is refused.  It also holds **one chain**: a different
  head at a seq the store already holds is a fork and is refused, at the
  write path and again at the read path.  The store is a **separate
  file** from the writer's ledger and is opened append-only; the writer
  never rewrites it and never reads it back as authority.
* ``HeadHolder.seal(pin)`` — anchor-before-acknowledge (C15): the anchor
  round-trip happens *before* anything is written to the independent
  store, so a head that was never anchored is never published and
  therefore never counted as sealed.  ``publish_head`` additionally
  refuses a receipt that does not commit to the head being sealed.
* ``AnchorReceipt`` — the receipt an external anchor (offline anchor
  manifest, Rekor head anchor) returns.  It is the write-path dependency
  that turns "the writer says it sealed" into "an outside party holds the
  head".
* ``offline_head_anchorer`` / ``rekor_head_anchorer`` — the two anchor
  round-trips, built on the anchor machinery that already exists
  (``audit_chain.anchor_manifest`` and ``audit_rekor.anchor_feed_head``)
  rather than a second anchoring protocol.
* ``tail_check(...)`` — the tail-sampling check: it compares the writer's
  latest head against the independently held head and compares the row
  counts between the two.  It fails closed on a mismatch *and* on a
  missing independent head.
* ``fresh_start_pin(...)`` / ``fresh_start_head(...)`` — the fresh-start
  path carries the old head (or its hash) as an input, so a re-mint shows
  as a head mismatch rather than a clean start.

What this module IS NOT (honest scope):

* It does not make the *anchor* independent.  An offline anchor manifest
  written next to the feed by the same operator is a same-domain witness;
  it is the shape of an independent holder, and it only earns the name when
  the operator ships the manifest somewhere the writer cannot rewrite
  (WORM storage, a transparency log).  The receipt carries
  ``independent=False`` in that case, and the tail check reports it.  The
  flag is a self-assertion: nothing in the software places the holder
  outside the writer's failure domain.
* The receipt is not signed.  ``publish_head`` checks that the receipt
  *commits* to the head being sealed (same head hash, same observed
  count, same observed range), but a caller that can reach ``publish_head``
  can mint such a receipt itself.  The receipt is evidence that an anchor
  round-trip happened; the anchor's trustworthiness is its own business
  (``audit_rekor`` signs its records, the offline manifest does not).
* The store's digest is unkeyed SHA-256.  It catches accidental
  corruption, an edited entry and a removed middle entry, but a writer
  that can rewrite the whole store can recompute the digests.  The store
  is therefore not a substitute for the external anchor: the holder
  detects divergence from a head somebody *else* witnessed, and it is
  only as good as the anchor behind that witness.
* It does not solve survivability between local sealing and the anchor
  round-trip.  Anchor-before-acknowledge trades liveness for evidence: an
  unreachable anchor stalls the write path rather than sealing an
  unanchored head.
* It does not detect a fork that happened *before* the first independent
  head was published; it can only compare against heads somebody else
  holds.
* It does not verify the ledger's internal chain.  ``forward_seal_ledger``
  owns that; this module only compares head pins and row counts.
* It does not wire itself into the runtime loop.  The seam is
  ``HeadHolder.seal`` / ``tail_check``: a host that owns a head store and
  an anchor calls them; nothing in ``loop.py`` does so yet.

House style: frozen dataclasses, no wall-clock in the sealed records,
RLock-guarded, fail-closed, stdlib-only apart from the sibling
``canonical_json``/``audit_chain``/``audit_rekor`` modules, version/schema
pins, ``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps_raw  # type: ignore

    def _jcs_dumps(obj: Any) -> bytes:
        raw = _jcs_dumps_raw(obj)
        return raw.encode("utf-8") if isinstance(raw, str) else raw

except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
HEAD_HOLDER_VERSION = "audit-head-holder.v1"

#: Schema pin for the head receipts written by this module.
HEAD_RECEIPT_SCHEMA = "northstar.audit-head-receipt.v1"

#: Schema pin for the tail-check report.
TAIL_CHECK_SCHEMA = "northstar.audit-head-tail-check.v1"

#: Schema pin for the offline head-anchor manifest (the archive anchor
#: manifest plus the sealed record count and the observed seq range).
HEAD_ANCHOR_VERSION = "northstar-audit-head-anchor/1"

#: Default file name of the independent head store.
HEAD_STORE_NAME = "audit-heads.ndjson"

#: Maximum size of one head receipt line (bytes).  Bounds the read of a
#: tampered store; a longer line is a corrupt store, not a big record.
_MAX_RECEIPT_BYTES = 64 * 1024


class HeadHolderError(Exception):
    """Fail-closed: an integrity or usage failure raises, never lies."""


@dataclass(frozen=True)
class HeadPin:
    """The head of a sealed chain: the pin every holder agrees on."""

    head_hash: str
    seq: int
    records_sealed: int
    genesis: str
    seq_first: int = 1
    seq_last: int = 0
    #: The head this pin continues from, when the chain was re-minted.
    #: Empty on a genuine fresh start; C46/48 -- a re-mint carries the old
    #: head, so a rewritten chain shows up as a mismatch, not a clean start.
    prev_head: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.head_hash, str) or not self.head_hash:
            raise HeadHolderError("head_hash must be a non-empty str")
        if not isinstance(self.genesis, str) or not self.genesis:
            raise HeadHolderError("genesis must be a non-empty str")
        if not isinstance(self.prev_head, str):
            raise HeadHolderError("prev_head must be a str")
        for name in ("seq", "records_sealed", "seq_first", "seq_last"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise HeadHolderError(f"{name} must be an int")
            if value < 0:
                raise HeadHolderError(f"{name} must be >= 0")
        # The empty range ``[1..0]`` is legitimate: it is a chain that has
        # sealed nothing yet (a fresh start).  Every other inversion is a
        # malformed pin and is refused.
        if self.seq_last == 0:
            if self.seq_first != 1:
                raise HeadHolderError("an empty seq range must be [1..0]")
            if self.seq or self.records_sealed:
                raise HeadHolderError(
                    "an empty seq range means nothing was sealed: seq and "
                    "records_sealed must both be 0"
                )
        else:
            if self.seq_last < self.seq_first:
                raise HeadHolderError("seq_last must be >= seq_first")
            # The seal commits to one consistent observed range [1..N]
            # (C21).  A pin whose seq, record count and range disagree
            # does not commit to anything, so it is refused here rather
            # than at verification time.
            if self.seq_first != 1:
                raise HeadHolderError(
                    "seq_first must be 1: the seal commits to the range [1..N]"
                )
            if self.seq_last != self.seq:
                raise HeadHolderError(
                    "seq_last must equal seq: the seal commits to one range [1..N]"
                )
            if self.records_sealed != self.seq_last:
                raise HeadHolderError(
                    "records_sealed must equal seq_last: the seal commits to one "
                    "range [1..N]"
                )

    @property
    def seq_range(self) -> Tuple[int, int]:
        """The observed seq range ``[first..last]`` the seal commits to."""
        return (self.seq_first, self.seq_last)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "head_hash": self.head_hash,
            "seq": self.seq,
            "records_sealed": self.records_sealed,
            "genesis": self.genesis,
            "seq_range": [self.seq_first, self.seq_last],
            "prev_head": self.prev_head,
        }


@dataclass(frozen=True)
class AnchorReceipt:
    """The receipt an external anchor returns for a head.

    ``independent`` says whether the anchor is genuinely outside the
    writer's control.  An offline anchor manifest written by the same
    operator into the same directory is *not* independent — it is the
    shape of an independent holder, and the receipt says so honestly
    instead of claiming the stronger property.
    """

    anchor: str
    anchor_id: str
    independent: bool = True
    detail: Mapping[str, Any] = field(default_factory=dict)
    #: The head this receipt actually commits to.  Empty means "the anchor
    #: does not name a head" and the receipt cannot seal any head.
    head_hash: str = ""
    #: The record count the anchor observed (C21: the seal commits to the
    #: observed seq range ``[1..N]``).  ``None`` means the anchor did not
    #: report a count.
    records_sealed: Optional[int] = None
    #: The observed seq range the anchor commits to, as ``[first, last]``.
    #: ``None`` means the anchor did not report a range.
    seq_range: Optional[Tuple[int, int]] = None

    def __post_init__(self) -> None:
        if not isinstance(self.anchor, str) or not self.anchor:
            raise HeadHolderError("anchor must be a non-empty str")
        if not isinstance(self.anchor_id, str) or not self.anchor_id:
            raise HeadHolderError("anchor_id must be a non-empty str")
        if not isinstance(self.independent, bool):
            raise HeadHolderError("independent must be a bool")
        if not isinstance(self.detail, Mapping):
            raise HeadHolderError("detail must be a mapping")
        if not isinstance(self.head_hash, str):
            raise HeadHolderError("head_hash must be a str")
        if self.records_sealed is not None:
            if isinstance(self.records_sealed, bool) or not isinstance(
                self.records_sealed, int
            ):
                raise HeadHolderError("records_sealed must be an int or None")
            if self.records_sealed < 0:
                raise HeadHolderError("records_sealed must be >= 0")
        if self.seq_range is not None:
            if not isinstance(self.seq_range, (tuple, list)) or len(self.seq_range) != 2:
                raise HeadHolderError("seq_range must be a pair or None")
            first, last = self.seq_range
            for value in (first, last):
                if isinstance(value, bool) or not isinstance(value, int):
                    raise HeadHolderError("seq_range bounds must be ints")
                if value < 0:
                    raise HeadHolderError("seq_range bounds must be >= 0")
            if last != 0 and last < first:
                raise HeadHolderError("seq_range must not be inverted")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "anchor": self.anchor,
            "anchor_id": self.anchor_id,
            "independent": self.independent,
            "detail": dict(self.detail),
            "head_hash": self.head_hash,
            "records_sealed": self.records_sealed,
            "seq_range": list(self.seq_range) if self.seq_range is not None else None,
        }


@dataclass(frozen=True)
class HeadReceipt:
    """One published head, as held by the independent store."""

    schema: str
    pin: HeadPin
    receipt: AnchorReceipt
    head_digest: str
    receipt_digest: str
    #: The digest of the previous entry in the store: the store is a hash
    #: chain, so an entry edited or removed in the middle is detected.
    prev_digest: str = ""
    #: The digest of this whole entry (over everything but itself).
    entry_digest: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            **self.pin.as_dict(),
            "anchor": self.receipt.as_dict(),
            "head_digest": self.head_digest,
            "receipt_digest": self.receipt_digest,
            "prev_digest": self.prev_digest,
            "entry_digest": self.entry_digest,
        }


def _entry_digest(entry: Mapping[str, Any]) -> str:
    """The digest of a store entry, over everything but the digest itself."""
    body = {key: value for key, value in entry.items() if key != "entry_digest"}
    return _digest(body)


@dataclass(frozen=True)
class TailCheckReport:
    """The result of the tail-sampling check (C51).

    ``ok`` is False on a head mismatch, on a row-count disagreement, and
    on a missing independent head.  ``independent_head_present`` records
    which of those fired, so a caller can tell "nobody held the head" from
    "somebody held a different head".
    """

    ok: bool
    reason: str
    schema: str = TAIL_CHECK_SCHEMA
    writer_head: Optional[HeadPin] = None
    independent_head: Optional[HeadPin] = None
    writer_rows: int = 0
    independent_rows: int = 0
    independent_head_present: bool = False
    independent: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "ok": self.ok,
            "reason": self.reason,
            "writer_head": self.writer_head.as_dict() if self.writer_head else None,
            "independent_head": (
                self.independent_head.as_dict() if self.independent_head else None
            ),
            "writer_rows": self.writer_rows,
            "independent_rows": self.independent_rows,
            "independent_head_present": self.independent_head_present,
            "independent": self.independent,
        }


def _sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest(obj: Any) -> str:
    return _sha256_hex(_jcs_dumps(obj))


class HeadHolder:
    """Append-only store of sealed heads, outside the writer's store.

    The store is a plain NDJSON file: one JSON object per published head,
    appended under an exclusive lock.  The writer never rewrites it and
    never truncates it; ``verify_store`` re-reads the whole file and
    checks every receipt's digests.

    Usage::

        holder = HeadHolder("/var/lib/northstar/audit-heads.ndjson")
        receipt = holder.publish_head(pin, receipt=anchor_receipt)
        report = holder.tail_check(writer_pin, writer_rows=len(ledger))
    """

    def __init__(
        self,
        path: str | Path,
        *,
        require_independent: bool = True,
        anchorer: Any = None,
    ) -> None:
        if path is None or (isinstance(path, str) and not path):
            raise HeadHolderError("path must be a non-empty path")
        self._path = Path(path)
        self._require_independent = bool(require_independent)
        if anchorer is not None and not callable(anchorer):
            raise HeadHolderError("anchorer must be callable")
        self._anchorer = anchorer
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        """Where the independent heads are held."""
        return self._path

    @property
    def require_independent(self) -> bool:
        """True when a publish with a non-independent anchor is refused."""
        return self._require_independent

    @property
    def has_anchorer(self) -> bool:
        """True when this holder can seal heads on its own."""
        return self._anchorer is not None

    # -- publishing ------------------------------------------------------

    def seal(
        self,
        pin: HeadPin,
        *,
        anchor_receipt: AnchorReceipt | None = None,
    ) -> HeadReceipt:
        """Anchor a head, then publish it.  The write-path dependency.

        With an ``anchorer`` configured, the anchor round-trip happens
        here and *before* anything is written to the independent store:
        a head that was never anchored is never published and therefore
        never counted as sealed (C15, anchor-before-acknowledge).

        Without an anchorer, a caller-supplied ``anchor_receipt`` is
        required -- with neither, the call fails closed: there is no
        anchor, so there is no seal.
        """
        if not isinstance(pin, HeadPin):
            raise HeadHolderError("pin must be a HeadPin")
        receipt = anchor_receipt
        if self._anchorer is not None:
            receipt = self._anchorer(pin)
        if receipt is None:
            raise HeadHolderError(
                "no anchor receipt: the head is not anchored, so it is not sealed "
                "(anchor-before-acknowledge)"
            )
        return self.publish_head(pin, receipt=receipt)

    def publish_head(
        self,
        pin: HeadPin,
        *,
        receipt: AnchorReceipt,
    ) -> HeadReceipt:
        """Publish a sealed head to the independent store.

        Anchor-before-acknowledge (C15): the head is written only *after*
        the anchor receipt is in hand.  A caller with no receipt cannot
        publish, and therefore cannot count the head as sealed.

        Fails closed when the anchor is not independent while
        ``require_independent`` is set.
        """
        if not isinstance(pin, HeadPin):
            raise HeadHolderError("pin must be a HeadPin")
        if not isinstance(receipt, AnchorReceipt):
            raise HeadHolderError("receipt must be an AnchorReceipt")
        if self._require_independent and not receipt.independent:
            raise HeadHolderError(
                "anchor is not independent of the writer; refusing to publish "
                "a head nobody outside the writer's domain holds"
            )
        # The receipt must commit to *this* head.  Without this check an
        # anchor for some other head would seal this one (C15: the anchor
        # is a write-path dependency, not a formality).
        if not receipt.head_hash:
            raise HeadHolderError(
                "anchor receipt names no head; an uncommitted anchor cannot seal one"
            )
        if receipt.head_hash != pin.head_hash:
            raise HeadHolderError(
                "anchor receipt commits to a different head "
                f"({receipt.head_hash[:23]}… != {pin.head_hash[:23]}…); "
                "refusing to seal this head with another head's anchor"
            )
        if receipt.records_sealed is None:
            raise HeadHolderError(
                "anchor receipt observed no record count; a seal must commit "
                "to the count the anchor observed"
            )
        if receipt.records_sealed != pin.records_sealed:
            raise HeadHolderError(
                "anchor receipt commits to a different record count "
                f"({receipt.records_sealed} != {pin.records_sealed}); "
                "refusing to seal this head with a mismatched anchor"
            )
        if receipt.seq_range is None:
            raise HeadHolderError(
                "anchor receipt observed no seq range; a seal must commit to "
                "the observed range [1..N]"
            )
        if tuple(receipt.seq_range) != pin.seq_range:
            raise HeadHolderError(
                "anchor receipt commits to a different seq range "
                f"({list(receipt.seq_range)} != {list(pin.seq_range)}); "
                "refusing to seal this head with a mismatched anchor"
            )
        head_digest = _digest(pin.as_dict())
        receipt_digest = _digest(receipt.as_dict())
        with self._lock:
            # The store is a hash chain: each entry commits to the one
            # before it, so an entry edited or removed in the middle is
            # detected by the read path.
            previous = self._read_receipts_locked()
            prev_digest = previous[-1].entry_digest if previous else ""
            if previous:
                last = previous[-1]
                if pin.seq < last.pin.seq or pin.records_sealed < last.pin.records_sealed:
                    raise HeadHolderError(
                        f"head store is append-only and monotonic: cannot publish "
                        f"seq {pin.seq} after seq {last.pin.seq}"
                    )
                # A *different* head at the same seq is a fork, not a
                # continuation.  The store is the outside holder's record
                # of one chain, so it refuses two heads claiming the same
                # position -- otherwise the tail check would compare the
                # writer against whichever head happened to be written
                # last, and a fork would read clean.
                if (
                    pin.seq == last.pin.seq
                    and pin.head_hash != last.pin.head_hash
                ):
                    raise HeadHolderError(
                        f"head store already holds a different head at seq "
                        f"{pin.seq} ({last.pin.head_hash[:23]}…); refusing to "
                        f"fork the store at the same position "
                        f"({pin.head_hash[:23]}…)"
                    )
            body = {
                "schema": HEAD_RECEIPT_SCHEMA,
                **pin.as_dict(),
                "anchor": receipt.as_dict(),
                "head_digest": head_digest,
                "receipt_digest": receipt_digest,
                "prev_digest": prev_digest,
            }
            entry = HeadReceipt(
                schema=HEAD_RECEIPT_SCHEMA,
                pin=pin,
                receipt=receipt,
                head_digest=head_digest,
                receipt_digest=receipt_digest,
                prev_digest=prev_digest,
                entry_digest=_entry_digest(body),
            )
            line = _jcs_dumps(entry.as_dict()).decode("utf-8") + "\n"
            self._append_line(line)
        return entry

    def _append_line(self, line: str) -> None:
        """Append one line to the store; the write is durable on return.

        I/O failures are translated into :class:`HeadHolderError`: the
        fail-closed API must not leak an ``OSError`` at its caller.
        """
        parent = self._path.parent
        if str(parent):
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                raise HeadHolderError(
                    f"cannot create the head store directory: {error}"
                ) from error
        encoded = line.encode("utf-8")
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        except OSError as error:
            raise HeadHolderError(
                f"cannot open the head store for append: {error}"
            ) from error
        try:
            written = 0
            while written < len(encoded):
                count = os.write(fd, encoded[written:])
                if count == 0:
                    raise HeadHolderError("head store write made no progress")
                written += count
            os.fsync(fd)
        except OSError as error:
            raise HeadHolderError(f"cannot write to the head store: {error}") from error
        finally:
            os.close(fd)

    # -- reading ---------------------------------------------------------

    def receipts(self) -> Tuple[HeadReceipt, ...]:
        """Every published head, in publication order.

        A malformed line fails the whole read (fail-closed): a truncated
        or rewritten store must not silently look like a shorter history.
        """
        with self._lock:
            return tuple(self._read_receipts_locked())

    def _read_receipts_locked(self) -> List[HeadReceipt]:
        if not self._path.exists():
            return []
        try:
            raw = self._path.read_bytes()
        except OSError as error:
            raise HeadHolderError(f"head store is unreadable: {error}") from error
        if len(raw) > _MAX_RECEIPT_BYTES * 1024:
            raise HeadHolderError("head store is implausibly large; refusing to read")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HeadHolderError(f"head store is not valid UTF-8: {error}") from error
        entries: List[HeadReceipt] = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > _MAX_RECEIPT_BYTES:
                raise HeadHolderError(f"head store line {number} is oversized")
            entries.append(self._parse_receipt(line, number))
        # The store is a hash chain: each entry commits to the one before
        # it.  A removed or edited entry breaks the link.
        previous_digest = ""
        for number, entry in enumerate(entries, start=1):
            if entry.prev_digest != previous_digest:
                raise HeadHolderError(
                    f"head store line {number} does not chain to the entry before it "
                    "(an entry was edited or removed)"
                )
            previous_digest = entry.entry_digest
        # The store holds one chain: a different head at a seq the store
        # already holds is a fork, not a continuation.  The write path
        # refuses to create one; the read path refuses to read one.
        seen: Dict[int, str] = {}
        for number, entry in enumerate(entries, start=1):
            held = seen.get(entry.pin.seq)
            if held is None:
                seen[entry.pin.seq] = entry.pin.head_hash
            elif held != entry.pin.head_hash:
                raise HeadHolderError(
                    f"head store forks at seq {entry.pin.seq}: line {number} "
                    f"holds {entry.pin.head_hash[:23]}… but an earlier line "
                    f"holds {held[:23]}…"
                )
        return entries

    def _parse_receipt(self, line: str, number: int) -> HeadReceipt:
        try:
            record = json.loads(line)
        except ValueError as error:
            raise HeadHolderError(f"head store line {number} is not JSON: {error}") from error
        if not isinstance(record, dict):
            raise HeadHolderError(f"head store line {number} is not a JSON object")
        if record.get("schema") != HEAD_RECEIPT_SCHEMA:
            raise HeadHolderError(f"head store line {number} has an unknown schema")
        try:
            seq_range = record["seq_range"]
            pin = HeadPin(
                head_hash=record["head_hash"],
                seq=record["seq"],
                records_sealed=record["records_sealed"],
                genesis=record["genesis"],
                seq_first=seq_range[0],
                seq_last=seq_range[1],
                prev_head=record.get("prev_head") or "",
            )
            anchor = record["anchor"]
            if not isinstance(anchor, dict):
                raise HeadHolderError(
                    f"head store line {number} has a malformed anchor record"
                )
            anchor_range = anchor.get("seq_range")
            receipt = AnchorReceipt(
                anchor=anchor["anchor"],
                anchor_id=anchor["anchor_id"],
                independent=anchor["independent"],
                detail=anchor.get("detail") or {},
                head_hash=anchor.get("head_hash") or "",
                records_sealed=anchor.get("records_sealed"),
                seq_range=tuple(anchor_range) if anchor_range is not None else None,
            )
            head_digest = record["head_digest"]
            receipt_digest = record["receipt_digest"]
            prev_digest = record.get("prev_digest") or ""
            entry_digest = record.get("entry_digest") or ""
        except HeadHolderError:
            raise
        except (AttributeError, KeyError, TypeError, IndexError, ValueError) as error:
            raise HeadHolderError(
                f"head store line {number} is malformed: {error}"
            ) from error
        if not entry_digest:
            raise HeadHolderError(f"head store line {number} has no entry digest")
        body = {
            "schema": HEAD_RECEIPT_SCHEMA,
            **pin.as_dict(),
            "anchor": receipt.as_dict(),
            "head_digest": head_digest,
            "receipt_digest": receipt_digest,
            "prev_digest": prev_digest,
        }
        try:
            recomputed = _entry_digest(body)
            recomputed_head = _digest(pin.as_dict())
            recomputed_receipt = _digest(receipt.as_dict())
        except (TypeError, ValueError) as error:
            raise HeadHolderError(
                f"head store line {number} is malformed: {error}"
            ) from error
        if recomputed != entry_digest:
            raise HeadHolderError(f"head store line {number} entry digest mismatch")
        if recomputed_head != head_digest:
            raise HeadHolderError(f"head store line {number} head digest mismatch")
        if recomputed_receipt != receipt_digest:
            raise HeadHolderError(f"head store line {number} receipt digest mismatch")
        # The receipt must still commit to the head it is filed under:
        # a store line whose anchor names another head is not a sealed head.
        # The read path applies the *same* commitments as the write path:
        # an anchor that observed no count or no range cannot seal a head
        # either, so a store line carrying one is a corrupt store.
        if not receipt.head_hash:
            raise HeadHolderError(
                f"head store line {number} has an anchor that names no head"
            )
        if receipt.head_hash != pin.head_hash:
            raise HeadHolderError(
                f"head store line {number} anchors a different head than it holds"
            )
        if receipt.records_sealed is None:
            raise HeadHolderError(
                f"head store line {number} has an anchor that observed no record count"
            )
        if receipt.records_sealed != pin.records_sealed:
            raise HeadHolderError(
                f"head store line {number} anchors a different record count than it holds"
            )
        if receipt.seq_range is None:
            raise HeadHolderError(
                f"head store line {number} has an anchor that observed no seq range"
            )
        if tuple(receipt.seq_range) != pin.seq_range:
            raise HeadHolderError(
                f"head store line {number} anchors a different seq range than it holds"
            )
        return HeadReceipt(
            schema=HEAD_RECEIPT_SCHEMA,
            pin=pin,
            receipt=receipt,
            head_digest=head_digest,
            receipt_digest=receipt_digest,
            prev_digest=prev_digest,
            entry_digest=entry_digest,
        )

    def latest(self) -> Optional[HeadReceipt]:
        """The most recently published head, or None when none was."""
        receipts = self.receipts()
        return receipts[-1] if receipts else None

    def rows(self) -> int:
        """How many heads this store holds (its own row count)."""
        return len(self.receipts())

    # -- the check --------------------------------------------------------

    def tail_check(
        self,
        writer_head: HeadPin,
        *,
        writer_rows: int,
        require_independent: Optional[bool] = None,
    ) -> TailCheckReport:
        """Sample the tail: does the latest held head match the writer's?

        C51: "does the latest head match an independent copy, and do the
        row counts between two heads agree?"  Fails closed on a head
        mismatch, on a row-count disagreement, and on a missing
        independent head.

        ``writer_rows`` is the writer's own row count (the number of
        records it currently holds).  It is compared against the
        independently held head's ``records_sealed`` -- the count the
        outside holder observed when it anchored that head.  The
        comparison is two-sided: a writer holding *fewer* rows than the
        holder observed has been shortened, and a writer holding *more*
        rows than the holder observed has extended the chain past the
        anchored head.
        """
        if not isinstance(writer_head, HeadPin):
            raise HeadHolderError("writer_head must be a HeadPin")
        if isinstance(writer_rows, bool) or not isinstance(writer_rows, int):
            raise HeadHolderError("writer_rows must be an int")
        if writer_rows < 0:
            raise HeadHolderError("writer_rows must be >= 0")
        strict = self._require_independent if require_independent is None else bool(
            require_independent
        )
        try:
            receipts = self.receipts()
        except HeadHolderError as error:
            return TailCheckReport(
                ok=False,
                reason=f"independent head store is unreadable: {error}",
                writer_head=writer_head,
                writer_rows=writer_rows,
                independent_head_present=False,
            )
        if not receipts:
            return TailCheckReport(
                ok=False,
                reason=(
                    "no independent head held: the writer is the only holder, "
                    "so a shortened chain cannot be distinguished from a clean one"
                ),
                writer_head=writer_head,
                writer_rows=writer_rows,
                independent_head_present=False,
            )
        held = receipts[-1]
        # The independent holder's row count is the count the *anchor*
        # observed when it anchored this head -- the anchor's own
        # statement, not the writer's claim about its own rows.  It is
        # the number of records somebody outside the writer counted.
        independent_rows = held.receipt.records_sealed
        if independent_rows is None:
            return TailCheckReport(
                ok=False,
                reason=(
                    "the held head's anchor observed no record count; "
                    "without an independently counted row there is nothing "
                    "to compare the writer's rows against"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=0,
                independent_head_present=True,
                independent=held.receipt.independent,
            )
        if strict and not held.receipt.independent:
            return TailCheckReport(
                ok=False,
                reason=(
                    "the held head was anchored inside the writer's own domain; "
                    "an independent holder is required"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=independent_rows,
                independent_head_present=True,
                independent=False,
            )
        if held.pin.head_hash != writer_head.head_hash:
            return TailCheckReport(
                ok=False,
                reason=(
                    f"head mismatch: writer holds {writer_head.head_hash[:23]}… "
                    f"but the independent holder holds {held.pin.head_hash[:23]}…"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=independent_rows,
                independent_head_present=True,
                independent=held.receipt.independent,
            )
        if held.pin.seq != writer_head.seq:
            return TailCheckReport(
                ok=False,
                reason=(
                    f"seq mismatch: writer is at seq {writer_head.seq} but the "
                    f"independent holder is at seq {held.pin.seq}"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=independent_rows,
                independent_head_present=True,
                independent=held.receipt.independent,
            )
        if held.pin.records_sealed != writer_head.records_sealed:
            return TailCheckReport(
                ok=False,
                reason=(
                    f"row-count mismatch: writer sealed {writer_head.records_sealed} "
                    f"records but the independent holder counted {held.pin.records_sealed}"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=independent_rows,
                independent_head_present=True,
                independent=held.receipt.independent,
            )
        if held.pin.seq_range != writer_head.seq_range:
            return TailCheckReport(
                ok=False,
                reason=(
                    f"seq-range mismatch: writer commits to {list(writer_head.seq_range)} "
                    f"but the independent holder holds {list(held.pin.seq_range)}"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=independent_rows,
                independent_head_present=True,
                independent=held.receipt.independent,
            )
        # C51: the row counts between the two heads must agree.  The
        # writer's own count is compared against the count the outside
        # holder observed.  Fewer rows means the chain was shortened;
        # more rows means it was extended past the anchored head.
        if writer_rows != independent_rows:
            shortened = writer_rows < independent_rows
            return TailCheckReport(
                ok=False,
                reason=(
                    f"row count {writer_rows} does not match the {independent_rows} "
                    "records the independent holder observed "
                    f"({'chain shortened' if shortened else 'chain extended past the anchored head'})"
                ),
                writer_head=writer_head,
                independent_head=held.pin,
                writer_rows=writer_rows,
                independent_rows=independent_rows,
                independent_head_present=True,
                independent=held.receipt.independent,
            )
        return TailCheckReport(
            ok=True,
            reason=(
                f"latest head matches the independent holder; "
                f"{independent_rows} records agree"
            ),
            writer_head=writer_head,
            independent_head=held.pin,
            writer_rows=writer_rows,
            independent_rows=independent_rows,
            independent_head_present=True,
            independent=held.receipt.independent,
        )

    # -- fresh start ------------------------------------------------------

    def fresh_start_head(
        self,
        previous: Optional[HeadPin],
        *,
        head_hash: str,
    ) -> HeadPin:
        """Carry the old head into a fresh start.

        C46/48: the fresh-start path must carry the old head (or its hash)
        as an input, so a re-mint shows as a head mismatch, not a clean
        start.  The returned pin is a *new* head whose ``prev_head`` is
        the previous head's hash: the re-mint is linked to the history
        it replaces.

        ``head_hash`` is the new head's hash and is required -- a fresh
        start that keeps the old hash is not a re-mint, and one that
        invents a new hash without carrying the old one is
        indistinguishable from a clean start.

        When no previous head is supplied the new chain starts clean and
        says so explicitly (an empty ``prev_head``); a caller that
        expected a continuation must treat the missing input as the
        mismatch it is -- use :func:`check_fresh_start` for that.
        """
        if previous is not None and not isinstance(previous, HeadPin):
            raise HeadHolderError("previous must be a HeadPin or None")
        if previous is None:
            raise HeadHolderError(
                "fresh_start_head needs the old head: a fresh start that carries "
                "no previous head is indistinguishable from a re-mint"
            )
        return _FreshStart(
            previous=previous,
            head_hash=head_hash,
            fresh=False,
        ).pin()

    def verify_store(self) -> Tuple[bool, str]:
        """Re-read the whole store and check every receipt's digests.

        Fails closed: a store that does not exist, or cannot be read, is
        not "intact" -- it is a missing independent holder.
        """
        if not self._path.exists():
            return False, "no independent head store exists; nobody holds the head"
        try:
            receipts = self.receipts()
        except HeadHolderError as error:
            return False, f"head store is broken: {error}"
        return True, f"{len(receipts)} heads held and intact"


@dataclass(frozen=True)
class _FreshStart:
    """Internal helper: build the fresh-start pin carrying the old head."""

    previous: Optional[HeadPin]
    head_hash: str
    fresh: bool

    def pin(self) -> HeadPin:
        """The new head, continuing the carried old head.

        The new head's ``prev_head`` is the old head's hash: the re-mint
        is *linked* to the history it replaces, so a verifier comparing
        against an independently held head sees a mismatch rather than a
        fresh chain that looks clean.  The head hash itself is the new
        one -- a pin that kept the old hash would be no re-mint at all.
        """
        if self.previous is None:
            raise HeadHolderError(
                "fresh start needs a previous head to carry"
            )
        if not self.head_hash:
            raise HeadHolderError(
                "fresh start needs the new head's hash"
            )
        if self.head_hash == self.previous.head_hash:
            raise HeadHolderError(
                "the fresh-start head must differ from the carried old head; "
                "a re-mint that keeps the old hash is not a re-mint"
            )
        return HeadPin(
            head_hash=self.head_hash,
            seq=self.previous.seq,
            records_sealed=self.previous.records_sealed,
            genesis=self.previous.genesis,
            seq_first=self.previous.seq_first,
            seq_last=self.previous.seq_last,
            prev_head=self.previous.head_hash,
        )


def fresh_start_pin(
    previous: Optional[HeadPin],
    *,
    genesis: str,
    head_hash: str,
    seq: int = 0,
    records_sealed: int = 0,
) -> HeadPin:
    """Build the fresh-start head, carrying the old head's hash.

    ``previous`` is the head the writer is continuing from (None for a
    genuinely clean start).  The returned pin's ``genesis`` is the new
    chain's genesis and its ``prev_head`` is the old head's hash, so the
    re-mint carries the history it replaces.  The caller compares the
    pin with the independent holder's head to detect a re-mint.
    """
    if previous is not None and not isinstance(previous, HeadPin):
        raise HeadHolderError("previous must be a HeadPin or None")
    if not isinstance(genesis, str) or not genesis:
        raise HeadHolderError("genesis must be a non-empty str")
    if not isinstance(head_hash, str) or not head_hash:
        raise HeadHolderError("head_hash must be a non-empty str")
    if previous is None and seq:
        raise HeadHolderError(
            "a fresh start with no previous head cannot claim a seq; "
            "carry the old head (or its hash) instead"
        )
    prev_head = previous.head_hash if previous is not None else ""
    if previous is not None and previous.head_hash == head_hash:
        raise HeadHolderError(
            "the fresh-start head must differ from the carried old head; "
            "a re-mint that keeps the old hash is not a re-mint"
        )
    return HeadPin(
        head_hash=head_hash,
        seq=seq,
        records_sealed=records_sealed,
        genesis=genesis,
        seq_first=1,
        seq_last=seq,
        prev_head=prev_head,
    )


def check_fresh_start(
    carried: Optional[HeadPin],
    independent_head: Optional[HeadPin],
) -> Tuple[bool, str]:
    """Check a fresh start against the independently held head.

    ``carried`` is the head the fresh start *produced* -- the new head,
    whose ``prev_head`` names the head it replaced.  The check asks two
    things:

    * does the carried head still agree with the head somebody else
      holds?  If not, the writer's chain has diverged from the one the
      outside holder witnessed -- a **mismatch**, not a clean start;
    * when the writer re-minted the chain, its new head names the old
      one in ``prev_head`` while the holder still holds the old head.
      That shows up here as a head that does *not* equal the held head,
      which is exactly the mismatch the caller must see.

    Fails closed: when nobody outside the writer holds a head, there is
    nothing to compare against and a re-mint cannot be distinguished
    from a clean start -- so the answer is "no", not "yes".
    """
    if carried is not None and not isinstance(carried, HeadPin):
        raise HeadHolderError("carried must be a HeadPin or None")
    if independent_head is not None and not isinstance(independent_head, HeadPin):
        raise HeadHolderError("independent_head must be a HeadPin or None")
    if independent_head is None:
        return False, (
            "no independent head held: nobody outside the writer holds the head, "
            "so a re-mint cannot be distinguished from a clean start"
        )
    if carried is None:
        return False, (
            "independent holder holds a head but the fresh start carried none; "
            "this is a re-mint, not a clean start"
        )
    if carried.head_hash != independent_head.head_hash:
        # The writer's head and the held head disagree.  Say whether the
        # writer's head *replaces* the held one (a re-mint) or simply
        # diverged from it.
        if carried.prev_head == independent_head.head_hash:
            return False, (
                f"fresh-start head mismatch: the fresh start re-minted the chain "
                f"({carried.head_hash[:23]}… replaces {carried.prev_head[:23]}…) "
                "while the independent holder still holds the replaced head"
            )
        return False, (
            f"fresh-start head mismatch: carried {carried.head_hash[:23]}… but "
            f"the independent holder holds {independent_head.head_hash[:23]}…"
        )
    if carried.seq != independent_head.seq:
        return False, (
            f"fresh-start seq mismatch: carried seq {carried.seq} but the "
            f"independent holder holds seq {independent_head.seq}"
        )
    return True, "fresh start continues the independently held head"


def offline_anchor_receipt(
    *,
    anchor_id: str,
    manifest: Mapping[str, Any],
    independent: bool = False,
    head_hash: str | None = None,
    records_sealed: int | None = None,
    seq_range: Sequence[int] | None = None,
) -> AnchorReceipt:
    """Build an :class:`AnchorReceipt` from an offline anchor manifest.

    ``audit_chain.anchor_manifest`` produces the manifest; this wraps it
    into the receipt the holder requires.  ``independent`` defaults to
    False: an offline manifest written by the same operator into the same
    directory is a *same-domain* witness.  Set it to True only when the
    manifest was actually shipped somewhere the writer cannot rewrite
    (WORM storage, a transparency log) — the receipt is the place that
    claim is made, so it is the place that has to be honest about it.

    The receipt commits to the head the manifest pinned
    (``head_chain_hash``) and the record count it observed, so the holder
    refuses an anchor that seals some other head.

    The count is read from ``records_sealed`` when the manifest carries
    it, and only then from ``records``.  Those are different numbers: a
    *head* anchor manifest is a manifest over the one-record head feed, so
    its ``records`` counts the head feed's rows (one) while
    ``records_sealed`` counts the sealed ledger records the head commits
    to.  Reading ``records`` there would have the anchor "observe" one
    record where the chain holds five, and the tail check would compare
    the writer against the wrong number.
    """
    if not isinstance(manifest, Mapping):
        raise HeadHolderError("manifest must be a mapping")
    committed = head_hash if head_hash is not None else manifest.get("head_chain_hash")
    if not isinstance(committed, str) or not committed:
        raise HeadHolderError(
            "the anchor manifest pins no head; an anchor that names no head "
            "cannot seal one"
        )
    if records_sealed is None and "records_sealed" in manifest:
        records_sealed = manifest.get("records_sealed")
    count = records_sealed if records_sealed is not None else manifest.get("records")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise HeadHolderError("records must be an int")
    if seq_range is None and manifest.get("seq_range") is not None:
        observed = manifest.get("seq_range")
        if isinstance(observed, (tuple, list)) and len(observed) == 2:
            seq_range = tuple(observed)
    return AnchorReceipt(
        anchor="northstar-audit-anchor/1",
        anchor_id=anchor_id,
        independent=independent,
        detail={
            "feed_sha256": manifest.get("feed_sha256"),
            "head_chain_hash": manifest.get("head_chain_hash"),
            "records": manifest.get("records"),
        },
        head_hash=committed,
        records_sealed=count,
        seq_range=tuple(seq_range) if seq_range is not None else None,
    )


def external_anchor_receipt(
    *,
    anchor_id: str,
    anchor: Mapping[str, Any],
    independent: bool = True,
    head_hash: str | None = None,
    records_sealed: int | None = None,
    seq_range: Sequence[int] | None = None,
) -> AnchorReceipt:
    """Build an :class:`AnchorReceipt` from an external (Rekor) anchor.

    ``audit_rekor.anchor_feed_head`` produces the anchor record; this
    wraps it into the receipt the holder requires.  A Rekor entry is
    independent by construction (the log is not the writer's store), so
    ``independent`` defaults to True.

    The receipt commits to the head the anchor pinned
    (``payload.head_chain_hash``) and the record count it observed.

    As with :func:`offline_anchor_receipt`, the count is taken from
    ``records_sealed`` when the payload carries it, and only then from
    ``records``: a head anchor payload's ``records`` counts the *head
    feed's* rows (one), not the sealed ledger records the head commits
    to.
    """
    if not isinstance(anchor, Mapping):
        raise HeadHolderError("anchor must be a mapping")
    payload = anchor.get("payload") or {}
    committed = head_hash if head_hash is not None else payload.get("head_chain_hash")
    if not isinstance(committed, str) or not committed:
        raise HeadHolderError(
            "the external anchor pins no head; an anchor that names no head "
            "cannot seal one"
        )
    if records_sealed is None and payload.get("records_sealed") is not None:
        records_sealed = payload.get("records_sealed")
    count = records_sealed if records_sealed is not None else payload.get("records")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise HeadHolderError("records must be an int")
    if seq_range is None and payload.get("seq_range") is not None:
        observed = payload.get("seq_range")
        if isinstance(observed, (tuple, list)) and len(observed) == 2:
            seq_range = tuple(observed)
    return AnchorReceipt(
        anchor="northstar-rekor-anchor/1",
        anchor_id=anchor_id,
        independent=independent,
        detail={
            "uuid": anchor.get("uuid"),
            "log_index": anchor.get("log_index"),
            "head_chain_hash": payload.get("head_chain_hash"),
            "records": payload.get("records"),
        },
        head_hash=committed,
        records_sealed=count,
        seq_range=tuple(seq_range) if seq_range is not None else None,
    )


def seal_and_publish(
    holder: HeadHolder,
    pin: HeadPin,
    *,
    anchor_receipt: AnchorReceipt | None = None,
    anchorer: Any = None,
) -> HeadReceipt:
    """Seal a head and hand it to the independent holder.

    A convenience wrapper over :meth:`HeadHolder.seal` for callers that
    hold the holder and the anchorer separately.  Anchor-before-acknowledge
    (C15): the anchor round-trip happens *before* anything is written to
    the independent store, so a head that was never anchored is never
    published and therefore never counted as sealed.

    With neither ``anchorer`` nor ``anchor_receipt`` there is no anchor,
    and the call fails closed.
    """
    if not isinstance(holder, HeadHolder):
        raise HeadHolderError("holder must be a HeadHolder")
    if anchorer is not None:
        if not callable(anchorer):
            raise HeadHolderError("anchorer must be callable")
        anchor_receipt = anchorer(pin)
    return holder.seal(pin, anchor_receipt=anchor_receipt)


def ledger_head_pin(ledger: Any) -> HeadPin:
    """Build the :class:`HeadPin` for a forward-seal ledger's current head.

    The pin commits to the head hash, the seq, the sealed record count
    and the observed seq range ``[1..N]`` (C21) -- the same four things
    the gossip announcer pins, so the two cannot disagree.
    """
    if ledger is None:
        raise HeadHolderError("ledger must not be None")
    length = len(ledger)
    genesis = getattr(ledger, "genesis", None)
    if not isinstance(genesis, str) or not genesis:
        raise HeadHolderError("ledger must provide a genesis pin")
    if length <= 0:
        # An empty ledger has no head to seal.
        raise HeadHolderError("ledger is empty: there is no head to seal")
    head = ledger.record(length)
    head_hash = getattr(head, "record_hash", None)
    if not isinstance(head_hash, str) or not head_hash:
        raise HeadHolderError("ledger head must carry a record_hash")
    return HeadPin(
        head_hash=head_hash,
        seq=length,
        records_sealed=length,
        genesis=genesis,
        seq_first=1,
        seq_last=length,
    )


def _bare_hex(value: str) -> str:
    """The bare 64-hex digest of a ``sha256:``-prefixed pin.

    The audit feed machinery (``audit_chain``/``audit_rekor``) pins bare
    hex; the forward-seal ledger pins ``sha256:``-prefixed hashes.  The
    head anchor feed carries the bare form so the existing anchor
    machinery works unmodified, and this helper is the only place the
    two conventions meet.
    """
    if not isinstance(value, str) or not value:
        raise HeadHolderError("pin must be a non-empty str")
    raw = value[7:] if value.startswith("sha256:") else value
    if len(raw) != 64 or any(c not in "0123456789abcdef" for c in raw):
        raise HeadHolderError(f"pin is not a sha256 digest: {value!r}")
    return raw


def head_feed_bytes(pin: HeadPin) -> bytes:
    """The one-record NDJSON *head feed* that an anchor can pin.

    The record carries the head pin and, in ``chain_hash``, the bare hex
    form of the head hash -- the field ``audit_chain.anchor_manifest``
    and ``audit_rekor.anchor_feed_head`` read to find the feed's head.
    The head feed is its own tiny format (one record, the head), not the
    audit NDJSON feed: it exists so the *existing* anchor machinery can
    anchor a forward-seal head without a second anchoring protocol.
    """
    if not isinstance(pin, HeadPin):
        raise HeadHolderError("pin must be a HeadPin")
    record = {
        "schema_version": "audit.ndjson/1",
        "component": "northstar-audit-head-holder",
        "event": "audit-head",
        "seq": 1,
        "chain_hash": _bare_hex(pin.head_hash),
        "head": pin.as_dict(),
    }
    return _jcs_dumps(record) + b"\n"


def write_head_feed(path: str | Path, pin: HeadPin) -> Path:
    """Write the head feed for ``pin`` and return its path.

    Fails closed: an unwritable target raises :class:`HeadHolderError`
    rather than leaking the ``OSError``.
    """
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(head_feed_bytes(pin))
    except OSError as error:
        raise HeadHolderError(
            f"cannot write the head feed {target}: {error}"
        ) from error
    return target


def head_anchor_manifest(
    feed_path: str | Path,
    pin: HeadPin,
    *,
    anchored_at: str | None = None,
) -> Dict[str, Any]:
    """Build the offline head anchor manifest for a head feed.

    It is the audit archive's anchor manifest (``audit_chain
    .anchor_manifest``) over the head feed, plus the two commitments
    the archive manifest has no room for: the sealed record count and
    the observed seq range ``[1..N]`` (C21).  Ship it somewhere the
    writer cannot rewrite -- that is what makes the holder independent.
    """
    from audit_chain import anchor_manifest

    manifest = dict(anchor_manifest(feed_path, anchored_at=anchored_at))
    manifest["head_anchor"] = HEAD_ANCHOR_VERSION
    manifest["records_sealed"] = pin.records_sealed
    manifest["seq_range"] = list(pin.seq_range)
    return manifest


def offline_head_anchorer(
    manifest_path: str | Path,
    *,
    anchor_id: str,
    feed_path: str | Path | None = None,
    independent: bool = False,
) -> Any:
    """Build an *anchorer* that anchors a head via an offline manifest.

    The returned callable takes a :class:`HeadPin`, writes the head
    feed, writes the offline manifest next to it, and returns the
    :class:`AnchorReceipt` for that head.  The manifest is a same-domain
    witness by default (``independent=False``): it only becomes an
    independent holder once the operator ships it somewhere the writer
    cannot rewrite.
    """
    manifest_target = Path(manifest_path)
    feed_target = (
        Path(feed_path)
        if feed_path is not None
        else manifest_target.with_name(manifest_target.stem + ".head.ndjson")
    )

    def anchorer(pin: HeadPin) -> AnchorReceipt:
        write_head_feed(feed_target, pin)
        manifest = head_anchor_manifest(feed_target, pin)
        try:
            manifest_target.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        except OSError as error:
            raise HeadHolderError(
                f"cannot write the head anchor manifest {manifest_target}: {error}"
            ) from error
        return offline_anchor_receipt(
            anchor_id=anchor_id,
            manifest=manifest,
            independent=independent,
            head_hash=pin.head_hash,
            records_sealed=pin.records_sealed,
            seq_range=pin.seq_range,
        )

    return anchorer


def rekor_head_anchorer(
    feed_path: str | Path,
    seed: bytes,
    *,
    anchor_id: str,
    rekor_url: str | None = None,
    timeout: float = 60.0,
) -> Any:
    """Build an *anchorer* that anchors a head in the Rekor log.

    The returned callable takes a :class:`HeadPin`, writes the head
    feed, submits it to the transparency log via
    ``audit_rekor.anchor_feed_head`` and returns the receipt.  A Rekor
    entry is independent by construction: the log is not the writer's
    store.  Network failure raises -- the head is then not sealed.
    """
    from audit_rekor import REKOR_V1_DEFAULT, anchor_feed_head

    feed_target = Path(feed_path)

    def anchorer(pin: HeadPin) -> AnchorReceipt:
        write_head_feed(feed_target, pin)
        anchor = anchor_feed_head(
            feed_target,
            seed,
            rekor_url=rekor_url or REKOR_V1_DEFAULT,
            timeout=timeout,
        )
        return external_anchor_receipt(
            anchor_id=anchor_id,
            anchor=anchor,
            head_hash=pin.head_hash,
            records_sealed=pin.records_sealed,
            seq_range=pin.seq_range,
        )

    return anchorer


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "tempfile",
        "threading",
        "typing",
        "audit_chain",
        "audit_rekor",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: publish, tail-check, shorten, and re-mint detection."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        holder = HeadHolder(Path(tmp) / HEAD_STORE_NAME)
        pin = HeadPin(
            head_hash="sha256:" + "aa" * 32,
            seq=3,
            records_sealed=3,
            genesis="sha256:" + "bb" * 32,
            seq_first=1,
            seq_last=3,
        )
        receipt = AnchorReceipt(
            anchor="test",
            anchor_id="a1",
            head_hash=pin.head_hash,
            records_sealed=pin.records_sealed,
            seq_range=pin.seq_range,
        )
        holder.publish_head(pin, receipt=receipt)
        report = holder.tail_check(pin, writer_rows=3)
        assert report.ok, report.reason
        # A shortened chain: same writer head, fewer rows than the
        # independent holder observed.
        short = holder.tail_check(pin, writer_rows=1)
        assert not short.ok
        # An extended chain: more rows than the anchored head.
        long = holder.tail_check(pin, writer_rows=9)
        assert not long.ok
        # A re-minted chain: a different head hash.
        remint = holder.tail_check(
            HeadPin(
                head_hash="sha256:" + "cc" * 32,
                seq=3,
                records_sealed=3,
                genesis=pin.genesis,
                seq_first=1,
                seq_last=3,
            ),
            writer_rows=3,
        )
        assert not remint.ok
        # An anchor for a different head cannot seal this one.
        try:
            holder.publish_head(
                pin,
                receipt=AnchorReceipt(
                    anchor="test", anchor_id="a2", head_hash="sha256:" + "dd" * 32
                ),
            )
        except HeadHolderError:
            pass
        else:
            raise AssertionError("an anchor for another head must not seal this one")
        # A missing independent head fails closed.
        empty = HeadHolder(Path(tmp) / "empty.ndjson")
        missing = empty.tail_check(pin, writer_rows=3)
        assert not missing.ok
        # The fresh-start path carries the old head.
        ok, note = check_fresh_start(pin, pin)
        assert ok, note
        ok, note = check_fresh_start(pin, None)
        assert not ok
        carried = holder.fresh_start_head(pin, head_hash="sha256:" + "cc" * 32)
        assert carried.prev_head == pin.head_hash
        assert carried.head_hash != pin.head_hash
    assert stdlib_only()
    print("audit-head-holder OK: publish, tail-check, shorten, extend, re-mint")


if __name__ == "__main__":
    main()
