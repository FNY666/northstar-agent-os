"""Fragile watermark interface: tamper-evident marking for byte carriers.

Research basis (second-hand):

- Wong (1998) "A Public Key Watermark for Image Verification and
  Authentication" partitions an image into independent blocks and embeds a
  block-wise authentication tag: any modification breaks the tag of the
  block it touched, so tampering is *localized* to the affected blocks.
- Tian (2003) "Reversible Data Embedding Using a Difference Expansion"
  shows how authentication data can ride inside the signal itself
  (difference expansion); reversibility is dropped here, the block-tag
  idea is kept.
- Lin & Chang (2001) on semi-fragile watermarks distinguishes *malicious*
  tampering (tag breaks) from *incidental* processing (tag survives); this
  module is fully fragile: any single-bit change breaks its block's tag.
  That is the point of a fragile watermark - it is a tripwire, not a
  survivor.

This module is the interface + bookkeeping half of the Wong-style idea,
simulated on byte arrays:

1. **Embed channel** (``FragileWatermark.embed``): the carrier is split
   into fixed-size blocks; each block's last byte is replaced by a
   key-derived tag ``HMAC-SHA256(key, block-index || content)[0]``.
   Returns a *new* byte string; the caller's carrier is never mutated.
2. **Tamper channel** (``FragileWatermark.tamper``): a deterministic
   simulated attacker that flips / zeroes / ones a byte range. Pure
   function - it models the adversary, books nothing, needs no key.
3. **Locate channel** (``FragileWatermark.locate``): re-derives every
   block tag from the presented bytes and reports exactly which blocks
   failed as *data* (``tampered`` bool, ``affected`` tuple). Tampering is
   reported, never raised.

Security properties:

- Without the key, tag bytes are indistinguishable from random
  (HMAC-SHA256 stream); block positions are fixed, so the tag layout is
  public but the tags themselves are not forgeable.
- The key never appears in any record, report, or audit event; only a
  ``sha256:`` key-id fingerprint is published.
- ``embed`` never mutates the caller's carrier; it returns new bytes.

Detector, not defense: a clean ``locate`` means "no tampering detected
since embed", not "the content is true". A flagged block means "this
block changed", never "the attacker is X". Presenting bytes watermarked
under a *different* key flags every block - that is key mismatch, not
proof of tampering.

Honest scope: in-memory simulation on byte arrays. No images, no DCT,
no measured localization precision curves. The block math is real and
deterministic; localization granularity equals the block size by
construction. Do not use the simulated channel as a legal-grade
forensics proof; real deployment needs the media-specific embedding
(Wong block auth in the pixel/DCT domain), which drops behind this API
without changing call sites.

No wall-clock anywhere. ``embed`` is deterministic: same (key,
carrier, block size) gives byte-identical marked output.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple
import threading

#: Version pin for the interface described here.
FRAGILE_WATERMARK_VERSION = "fragile-watermark.v1"

#: Schema pin stamped on structured outputs.
SCHEMA_PIN = "northstar.fragile-watermark.v1"

#: Domain separation prefix for all HMAC derivations.
_DOMAIN = b"northstar.fragile-watermark.v1"

#: Default block size in bytes (last byte of each block carries the tag).
DEFAULT_BLOCK_SIZE = 64

#: Smallest block size that still leaves content bytes beside the tag.
MIN_BLOCK_SIZE = 8

#: Largest block size (keeps per-block tag tables bounded).
MAX_BLOCK_SIZE = 1 << 16

#: Guardrail: refuse carriers larger than this (DoS protection for the host).
MAX_CARRIER_BYTES = 1 << 26  # 64 MiB

#: Pinned tamper-mode vocabulary for tamper().
TAMPER_MODES = ("flip", "zero", "one")

#: Fixed audit vocabulary for fragile_watermark_audit_event().
_AUDIT_KINDS = frozenset({"embedded", "located", "rejected"})

#: Keys that must never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {"key", "raw_key", "secret", "password", "carrier", "marked", "content"}
)


class FragileWatermarkError(Exception):
    """Base error for the fragile watermark interface."""


class BadKeyError(FragileWatermarkError):
    """Raised when the key is not a non-empty str."""


class BadCarrierError(FragileWatermarkError):
    """Raised when the carrier is not usable bytes of the right shape."""


class BadBlockError(FragileWatermarkError):
    """Raised when the block size is out of range or inconsistent."""


class BadOffsetError(FragileWatermarkError):
    """Raised when a tamper offset is out of range."""


class BadLengthError(FragileWatermarkError):
    """Raised when a tamper length is out of range."""


class BadModeError(FragileWatermarkError):
    """Raised when a tamper mode is not in the pinned vocabulary."""


class SeqOrderError(FragileWatermarkError):
    """Raised when a caller seq is not a strictly increasing int."""


class AuditKindError(FragileWatermarkError):
    """Raised when an unknown audit kind is requested."""


def _check_seq(seq: object) -> int:
    """Validate a caller seq shape; return it as int."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _key_id(key: str) -> str:
    """Public fingerprint of the key; the key itself never leaves."""
    return "sha256:" + hashlib.sha256(
        _DOMAIN + b"|key-id|" + key.encode("utf-8")
    ).hexdigest()


def _block_tag(key: str, index: int, content: bytes) -> int:
    """Derive one tag byte for block ``index`` over its content bytes."""
    mac = hmac.new(
        key.encode("utf-8"),
        _DOMAIN + b"|tag|" + index.to_bytes(8, "big") + content,
        hashlib.sha256,
    )
    return mac.digest()[0]


def _digest_pin(label: str, payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(
        _DOMAIN + b"|" + label.encode("utf-8") + b"|" + payload
    ).hexdigest()


def fragile_watermark_audit_event(
    kind: str, seq: int, **fields: object
) -> dict:
    """Shape a fragile-watermark outcome as an audit.ndjson/1 record.

    Caller-supplied seq; the key itself is never included, only key_id.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    for name in fields:
        if name in _BANNED_AUDIT_KEYS:
            raise ValueError(f"key {name!r} is banned from the audit boundary")
    record = {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "event": f"fragile-watermark.{kind}",
        "watermarker": FRAGILE_WATERMARK_VERSION,
    }
    record.update(fields)
    return record


@dataclass(frozen=True)
class EmbedRecord:
    """Booked outcome of one embed(): the marked carrier's pins."""

    key_id: str
    block_size: int
    total_blocks: int
    carrier_len: int
    tag_digest: str
    carrier_digest: str
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "key_id": self.key_id,
            "block_size": self.block_size,
            "total_blocks": self.total_blocks,
            "carrier_len": self.carrier_len,
            "tag_digest": self.tag_digest,
            "carrier_digest": self.carrier_digest,
            "seq": self.seq,
        }

    def verify(self, marked: bytes) -> bool:
        """Recompute the carrier pin; True iff ``marked`` matches."""
        return _digest_pin("carrier", bytes(marked)) == self.carrier_digest


@dataclass(frozen=True)
class TamperReport:
    """Booked outcome of one locate(): where the tripwire fired, as data."""

    tampered: bool
    affected: Tuple[int, ...]
    affected_count: int
    first_affected: int
    last_affected: int
    total_blocks: int
    block_size: int
    carrier_digest: str
    report_digest: str
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "tampered": self.tampered,
            "affected": list(self.affected),
            "affected_count": self.affected_count,
            "first_affected": self.first_affected,
            "last_affected": self.last_affected,
            "total_blocks": self.total_blocks,
            "block_size": self.block_size,
            "carrier_digest": self.carrier_digest,
            "report_digest": self.report_digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        """Recompute the report pin from the booked fields."""
        payload = (
            str(self.tampered).encode()
            + b"|"
            + b",".join(str(i).encode() for i in self.affected)
            + b"|"
            + str(self.total_blocks).encode()
            + b"|"
            + self.carrier_digest.encode()
        )
        return _digest_pin("tamper-report", payload) == self.report_digest


class FragileWatermark:
    """Keyed fragile-watermark tripwire over byte carriers.

    The key is held in memory only and never appears in any record,
    report, or audit event - only its ``sha256:`` key-id fingerprint.
    """

    def __init__(self, key: str) -> None:
        if not isinstance(key, str) or not key:
            raise BadKeyError("key must be a non-empty str")
        self._key = key
        self._key_id = _key_id(key)
        self._lock = threading.RLock()
        self._last_seq = 0
        self._block_size = DEFAULT_BLOCK_SIZE
        self._embed_record: EmbedRecord | None = None
        self._audit: list = []

    # -- internal discipline -------------------------------------------------

    def _claim(self, seq: object) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        return seq

    def _emit(self, audit_kind: str, seq: int, **fields: object) -> None:
        self._audit.append(
            fragile_watermark_audit_event(audit_kind, seq, **fields)
        )

    def _burn(self, seq: int, op: str) -> None:
        """Book a rejected row for a failed mutation that claimed its seq."""
        self._last_seq = seq
        self._emit("rejected", seq, op=op, key_id=self._key_id)

    # -- channels ------------------------------------------------------------

    def embed(
        self, carrier: bytes, seq: int, block_size: int = DEFAULT_BLOCK_SIZE
    ) -> tuple:
        """Embed the fragile watermark; return ``(marked, EmbedRecord)``.

        ``marked`` is a new byte string: each block's last byte is replaced
        by the key-derived tag for that block's content. The caller's
        carrier is never mutated.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if not isinstance(block_size, int) or isinstance(
                    block_size, bool
                ):
                    raise BadBlockError("block_size must be int")
                if not (MIN_BLOCK_SIZE <= block_size <= MAX_BLOCK_SIZE):
                    raise BadBlockError(
                        f"block_size out of range [{MIN_BLOCK_SIZE}, "
                        f"{MAX_BLOCK_SIZE}]"
                    )
                if not isinstance(carrier, (bytes, bytearray)):
                    raise BadCarrierError("carrier must be bytes")
                carrier = bytes(carrier)
                if len(carrier) == 0:
                    raise BadCarrierError("carrier must not be empty")
                if len(carrier) > MAX_CARRIER_BYTES:
                    raise BadCarrierError("carrier exceeds size guardrail")
                if len(carrier) % block_size != 0:
                    raise BadCarrierError(
                        "carrier length must be a multiple of block_size"
                    )
                if self._embed_record is not None and (
                    block_size != self._block_size
                ):
                    raise BadBlockError(
                        "block_size is pinned by the first embed"
                    )
            except FragileWatermarkError:
                self._burn(seq, "embed")
                raise
            n = len(carrier) // block_size
            out = bytearray(carrier)
            tags = bytearray()
            for i in range(n):
                base = i * block_size
                content = bytes(out[base : base + block_size - 1])
                tag = _block_tag(self._key, i, content)
                out[base + block_size - 1] = tag
                tags.append(tag)
            marked = bytes(out)
            record = EmbedRecord(
                key_id=self._key_id,
                block_size=block_size,
                total_blocks=n,
                carrier_len=len(marked),
                tag_digest=_digest_pin("tags", bytes(tags)),
                carrier_digest=_digest_pin("carrier", marked),
                seq=seq,
            )
            self._block_size = block_size
            self._embed_record = record
            self._last_seq = seq
            self._emit(
                "embedded",
                seq,
                key_id=self._key_id,
                block_size=block_size,
                total_blocks=n,
                tag_digest=record.tag_digest,
                carrier_digest=record.carrier_digest,
            )
            return marked, record

    @staticmethod
    def tamper(
        marked: bytes, offset: int, length: int, mode: str = "flip"
    ) -> bytes:
        """Simulated attacker: deterministically damage a byte range.

        Pure function - models the adversary, books nothing, needs no key.
        ``mode`` is one of ``flip`` (xor 0xff), ``zero``, ``one``.
        """
        if not isinstance(marked, (bytes, bytearray)):
            raise BadCarrierError("marked must be bytes")
        marked = bytes(marked)
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise BadOffsetError("offset must be int")
        if isinstance(length, bool) or not isinstance(length, int):
            raise BadLengthError("length must be int")
        if offset < 0 or offset >= len(marked):
            raise BadOffsetError("offset out of range")
        if length <= 0 or offset + length > len(marked):
            raise BadLengthError("length out of range")
        if mode not in TAMPER_MODES:
            raise BadModeError(f"mode must be one of {TAMPER_MODES}")
        out = bytearray(marked)
        for j in range(offset, offset + length):
            if mode == "flip":
                out[j] ^= 0xFF
            elif mode == "zero":
                out[j] = 0
            else:
                out[j] = 0xFF
        return bytes(out)

    def locate(self, marked: bytes, seq: int) -> TamperReport:
        """Re-derive every block tag; report broken blocks as data.

        Tampering is reported, never raised. An intact carrier yields
        ``tampered=False`` with an empty ``affected`` tuple.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if not isinstance(marked, (bytes, bytearray)):
                    raise BadCarrierError("marked must be bytes")
                marked = bytes(marked)
                if len(marked) == 0:
                    raise BadCarrierError("marked must not be empty")
                if len(marked) % self._block_size != 0:
                    raise BadCarrierError(
                        "marked length must be a multiple of block_size"
                    )
            except FragileWatermarkError:
                self._burn(seq, "locate")
                raise
            bs = self._block_size
            n = len(marked) // bs
            affected: list = []
            for i in range(n):
                base = i * bs
                content = marked[base : base + bs - 1]
                expected = _block_tag(self._key, i, content)
                if marked[base + bs - 1] != expected:
                    affected.append(i)
            affected_t = tuple(affected)
            tampered = bool(affected_t)
            payload = (
                str(tampered).encode()
                + b"|"
                + b",".join(str(i).encode() for i in affected_t)
                + b"|"
                + str(n).encode()
                + b"|"
                + _digest_pin("carrier", marked).encode()
            )
            report = TamperReport(
                tampered=tampered,
                affected=affected_t,
                affected_count=len(affected_t),
                first_affected=affected_t[0] if affected_t else -1,
                last_affected=affected_t[-1] if affected_t else -1,
                total_blocks=n,
                block_size=bs,
                carrier_digest=_digest_pin("carrier", marked),
                report_digest=_digest_pin("tamper-report", payload),
                seq=seq,
            )
            self._last_seq = seq
            self._emit(
                "located",
                seq,
                key_id=self._key_id,
                tampered=tampered,
                affected_count=len(affected_t),
                report_digest=report.report_digest,
            )
            return report

    # -- views ----------------------------------------------------------------

    def embed_record(self) -> EmbedRecord | None:
        """The last booked EmbedRecord, or None before any embed."""
        with self._lock:
            return self._embed_record

    def audit_log(self) -> tuple:
        """Booked audit rows, oldest first (key material never included)."""
        with self._lock:
            return tuple(self._audit)

    def stats(self) -> dict:
        """Ledger counters as data."""
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "embeds": sum(
                    1 for r in self._audit if r["event"] == "fragile-watermark.embedded"
                ),
                "locates": sum(
                    1 for r in self._audit if r["event"] == "fragile-watermark.located"
                ),
                "rejected": sum(
                    1 for r in self._audit if r["event"] == "fragile-watermark.rejected"
                ),
                "last_seq": self._last_seq,
            }


def main() -> None:
    fw = FragileWatermark("owner-key-1")
    carrier = bytes(range(256)) * 2  # 512 bytes = 8 blocks of 64
    marked, rec = fw.embed(carrier, seq=1)
    assert marked is not carrier and len(marked) == len(carrier)
    assert bytes(carrier) == bytes(range(256)) * 2, "input must not mutate"
    assert rec.verify(marked)
    clean = fw.locate(marked, seq=2)
    assert not clean.tampered and clean.affected == ()
    assert clean.verify()
    # one flipped bit inside block 2 -> exactly block 2 flagged
    damaged = FragileWatermark.tamper(marked, 2 * 64 + 10, 1)
    rep = fw.locate(damaged, seq=3)
    assert rep.tampered and rep.affected == (2,), rep.affected
    assert rep.first_affected == 2 and rep.last_affected == 2
    assert rep.verify()
    # tamper crossing a block boundary flags both blocks
    damaged2 = FragileWatermark.tamper(marked, 63, 2)
    rep2 = fw.locate(damaged2, seq=4)
    assert rep2.affected == (0, 1), rep2.affected
    # wrong key flags every block (key mismatch, not proven tampering)
    rep3 = FragileWatermark("wrong-key").locate(marked, seq=1)
    assert rep3.affected_count == 8
    # the key never crosses a record boundary
    for row in fw.audit_log():
        assert "key" not in row and "owner-key-1" not in str(row.values())
    print("fragile-watermark OK: embed, tamper, locate, key-mismatch, audit")


if __name__ == "__main__":
    main()
