"""Probabilistic membership testing: a Bloom filter answers "seen before?" cheaply.

A Bloom filter is a space-efficient probabilistic set: ``add(item)``
records an item and ``might_contain(item)`` answers True if the item
*may* have been added, or False if it *definitely* was not. False
positives are possible; false negatives are impossible. The expected
false-positive rate is a constructor parameter; the filter tells you
the rate it is currently operating at via :meth:`BloomFilter.false_positive_rate`.

Hashing is deterministic double-hashing over SHA-256 (stdlib only):
``h_i(item) = (h1 + i*h2) mod m`` for ``i in range(k)``, with ``h2``
forced odd so the probe sequence covers the whole array. No ``random``
module, no seed coupling, no wall-clock -- two filters built with the
same ``(capacity, error_rate)`` and the same adds are bit-identical,
which makes audit snapshots and replays exact.

Capacity semantics (fail-closed, never silently degraded):

* adding beyond ``capacity`` is refused with ``CapacityExceeded`` --
  the false-positive guarantee would otherwise silently collapse;
* ``add`` returns True when the item was definitely new (at least one
  bit flipped), False when it was already (probably) present --
  the return value is advisory, not a proof;
* state serializes via :meth:`BloomFilter.to_bytes` with a ``sha256:``
  digest pin; :meth:`BloomFilter.from_bytes` verifies the pin before
  restoring -- tampered snapshots are refused, not trusted.

Item canonicalization is type-tagged: ``"1"`` (str), ``1`` (int) and
``b"1"`` (bytes) hash as *different* keys, so a type confusion in the
caller can never make an unseen item look seen. Only ``str``, ``bytes``
and ``int`` are accepted; ``bool`` is rejected as ``TypeError`` (a
bool is not a number here), everything else raises ``TypeError``.

Honest scope: a Bloom filter answers membership, nothing else. True
means "probably added, with the current estimated false-positive
rate"; False means "definitely never added". It cannot count, cannot
delete (a counting variant would), cannot enumerate members, and an
adversary who observes the bit array can tune items to force false
positives -- the filter is a memory-saver for honest workloads, not a
security boundary. State is in-memory; persistence is the host's job
(via :meth:`to_bytes` / :meth:`from_bytes`).
"""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Optional


#: Version pin for this module's record shape.
BLOOM_FILTER_VERSION = "bloom-filter.v1"

#: Schema pin carried on audit records.
BLOOM_FILTER_SCHEMA = "northstar.bloom-filter.v1"

#: ln(2), used in the optimal-parameter formulas.
_LN2 = math.log(2.0)

#: Wire-format magic + version byte for to_bytes / from_bytes.
_WIRE_MAGIC = b"NSBF"
_WIRE_VERSION = 1

#: Maximum capacity guardrail (prevents absurd allocations).
_MAX_CAPACITY = 10_000_000


class BloomFilterError(Exception):
    """Base error for bloom-filter failures."""


class CapacityExceeded(BloomFilterError):
    """Raised when an add would exceed the declared capacity."""

    def __init__(self, capacity: int, inserted: int):
        self.capacity = capacity
        self.inserted = inserted
        super().__init__(
            f"bloom filter capacity exceeded: capacity={capacity}, "
            f"inserted={inserted}"
        )


def _optimal_bits(capacity: int, error_rate: float) -> int:
    """Optimal bit-array size m = ceil(-n*ln(p) / (ln2)^2)."""
    return max(1, math.ceil(-capacity * math.log(error_rate) / (_LN2 * _LN2)))


def _optimal_hashes(bits: int, capacity: int) -> int:
    """Optimal hash count k = ceil((m/n) * ln2), at least 1."""
    return max(1, math.ceil((bits / capacity) * _LN2))


def _canonicalize(item) -> bytes:
    """Type-tagged canonical encoding of a supported item.

    Only str, bytes, int are accepted. bool is rejected: ``True`` is
    an int subclass and would silently collide with ``1``.
    """
    if isinstance(item, bool):
        raise TypeError("bloom filter item must be str, bytes or int; bool rejected")
    if isinstance(item, str):
        return b"s\x00" + item.encode("utf-8")
    if isinstance(item, bytes):
        return b"b\x00" + item
    if isinstance(item, int):
        if item < 0:
            raise ValueError("bloom filter int items must be non-negative")
        length = max(1, (item.bit_length() + 7) // 8)
        return b"i\x00" + item.to_bytes(length, "big")
    raise TypeError(
        f"bloom filter item must be str, bytes or int, not {type(item).__name__}"
    )


def _hash_positions(key: bytes, bits: int, hashes: int) -> tuple[int, ...]:
    """Deterministic double-hash probe positions (stdlib, no randomness)."""
    h1 = int.from_bytes(
        hashlib.sha256(b"bloom-filter.v1\x00h1\x00" + key).digest(), "big"
    )
    h2 = int.from_bytes(
        hashlib.sha256(b"bloom-filter.v1\x00h2\x00" + key).digest(), "big"
    )
    # Force odd so the (h1 + i*h2) walk covers the whole array even
    # when h2 would otherwise share a factor with m.
    h2 |= 1
    return tuple((h1 + i * h2) % bits for i in range(hashes))


@dataclass(frozen=True)
class BloomFilterConfig:
    """Frozen construction record; also the serializable identity."""

    capacity: int
    error_rate: float
    bits: int
    hashes: int

    def as_dict(self) -> dict:
        return {
            "schema": BLOOM_FILTER_SCHEMA,
            "version": BLOOM_FILTER_VERSION,
            "capacity": self.capacity,
            "error_rate": self.error_rate,
            "bits": self.bits,
            "hashes": self.hashes,
        }


class BloomFilter:
    """Probabilistic membership set with a pinned false-positive budget.

    Construct with :meth:`create`; add items with :meth:`add`; query
    with :meth:`might_contain`.
    """

    __slots__ = ("_config", "_array", "_inserted")

    def __init__(self, config: BloomFilterConfig):
        self._config = config
        self._array = bytearray((config.bits + 7) // 8)
        self._inserted = 0

    # -- construction -------------------------------------------------

    @classmethod
    def create(cls, capacity: int, error_rate: float) -> "BloomFilter":
        """Build a filter sized for ``capacity`` items at ``error_rate`` FP.

        Raises TypeError on wrong types (bool rejected for both args),
        ValueError on non-positive capacity, capacity above the guardrail,
        or error_rate outside (0, 1).
        """
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("capacity must be an int")
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if capacity > _MAX_CAPACITY:
            raise ValueError(f"capacity exceeds guardrail {_MAX_CAPACITY}")
        if isinstance(error_rate, bool) or not isinstance(error_rate, (int, float)):
            raise TypeError("error_rate must be a number")
        error_rate = float(error_rate)
        if not 0.0 < error_rate < 1.0:
            raise ValueError("error_rate must be in (0, 1)")
        bits = _optimal_bits(capacity, error_rate)
        hashes = _optimal_hashes(bits, capacity)
        return cls(
            BloomFilterConfig(
                capacity=capacity,
                error_rate=error_rate,
                bits=bits,
                hashes=hashes,
            )
        )

    # -- views --------------------------------------------------------

    @property
    def config(self) -> BloomFilterConfig:
        return self._config

    @property
    def capacity(self) -> int:
        return self._config.capacity

    @property
    def bits(self) -> int:
        return self._config.bits

    @property
    def hashes(self) -> int:
        return self._config.hashes

    @property
    def inserted(self) -> int:
        """Distinct add calls accepted (not a cardinality estimate)."""
        return self._inserted

    def fill_fraction(self) -> float:
        """Fraction of bits currently set, in [0, 1]."""
        set_bits = sum(bin(byte).count("1") for byte in self._array)
        return set_bits / self._config.bits

    def false_positive_rate(self) -> float:
        """Estimated current false-positive rate: (1 - e^(-k*n/m))^k.

        Uses the actual inserted count, so it tracks the filter's real
        operating point. 0.0 when empty; callers comparing against the
        constructor's error_rate should do so at capacity.
        """
        if self._inserted == 0:
            return 0.0
        k = self._config.hashes
        m = self._config.bits
        n = self._inserted
        return (1.0 - math.exp(-k * n / m)) ** k

    def theoretical_error_rate(self) -> float:
        """The design-time false-positive rate (the constructor promise)."""
        return self._config.error_rate

    # -- operations ---------------------------------------------------

    def _check_capacity(self) -> None:
        if self._inserted >= self._config.capacity:
            raise CapacityExceeded(self._config.capacity, self._inserted)

    def add(self, item) -> bool:
        """Record an item. Returns True if it was definitely new.

        False means "already (probably) present". Raises CapacityExceeded
        past capacity -- the filter refuses to silently degrade.
        """
        key = _canonicalize(item)
        self._check_capacity()
        positions = _hash_positions(key, self._config.bits, self._config.hashes)
        was_new = False
        for pos in positions:
            byte_idx, bit_idx = divmod(pos, 8)
            mask = 1 << bit_idx
            if not self._array[byte_idx] & mask:
                was_new = True
                self._array[byte_idx] |= mask
        self._inserted += 1
        return was_new

    def might_contain(self, item) -> bool:
        """True if the item may have been added; False if definitely not."""
        key = _canonicalize(item)
        positions = _hash_positions(key, self._config.bits, self._config.hashes)
        for pos in positions:
            byte_idx, bit_idx = divmod(pos, 8)
            if not self._array[byte_idx] & (1 << bit_idx):
                return False
        return True

    # -- serialization ------------------------------------------------

    def state_digest(self) -> str:
        """``sha256:`` pin of the exact filter state (config + bits + count)."""
        h = hashlib.sha256()
        h.update(_WIRE_MAGIC)
        h.update(struct.pack(">I", _WIRE_VERSION))
        h.update(struct.pack(">Q", self._config.capacity))
        h.update(struct.pack(">d", self._config.error_rate))
        h.update(struct.pack(">Q", self._config.bits))
        h.update(struct.pack(">Q", self._config.hashes))
        h.update(struct.pack(">Q", self._inserted))
        h.update(bytes(self._array))
        return "sha256:" + h.hexdigest()

    def to_bytes(self) -> bytes:
        """Serialize the filter; ends with a digest pin of the body."""
        body = bytearray()
        body += _WIRE_MAGIC
        body += struct.pack(">I", _WIRE_VERSION)
        body += struct.pack(">Q", self._config.capacity)
        body += struct.pack(">d", self._config.error_rate)
        body += struct.pack(">Q", self._config.bits)
        body += struct.pack(">Q", self._config.hashes)
        body += struct.pack(">Q", self._inserted)
        body += struct.pack(">Q", len(self._array))
        body += bytes(self._array)
        digest = hashlib.sha256(bytes(body)).digest()
        return bytes(body) + digest

    @classmethod
    def from_bytes(cls, data: bytes) -> "BloomFilter":
        """Restore a filter; fail-closed on malformed or tampered input.

        Raises TypeError on non-bytes, BloomFilterError on any structural
        problem or digest mismatch.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("snapshot must be bytes")
        data = bytes(data)
        min_len = 4 + 4 + 8 + 8 + 8 + 8 + 8 + 8 + 32
        if len(data) < min_len:
            raise BloomFilterError("snapshot too short")
        body, pin = data[:-32], data[-32:]
        if hashlib.sha256(body).digest() != pin:
            raise BloomFilterError("snapshot digest mismatch (tampered or corrupt)")
        off = 0
        if body[off:off + 4] != _WIRE_MAGIC:
            raise BloomFilterError("bad snapshot magic")
        off += 4
        (version,) = struct.unpack(">I", body[off:off + 4])
        off += 4
        if version != _WIRE_VERSION:
            raise BloomFilterError(f"unsupported snapshot version {version}")
        (capacity,) = struct.unpack(">Q", body[off:off + 8])
        off += 8
        (error_rate,) = struct.unpack(">d", body[off:off + 8])
        off += 8
        (bits,) = struct.unpack(">Q", body[off:off + 8])
        off += 8
        (hashes,) = struct.unpack(">Q", body[off:off + 8])
        off += 8
        (inserted,) = struct.unpack(">Q", body[off:off + 8])
        off += 8
        (array_len,) = struct.unpack(">Q", body[off:off + 8])
        off += 8
        if len(body) != off + array_len:
            raise BloomFilterError("snapshot length mismatch")
        config = BloomFilterConfig(
            capacity=capacity, error_rate=error_rate, bits=bits, hashes=hashes
        )
        filt = cls(config)
        filt._array = bytearray(body[off:off + array_len])
        filt._inserted = inserted
        return filt

    # -- audit ----------------------------------------------------------

    def bloom_audit_event(self, kind: str, seq: int) -> dict:
        """Shape a filter lifecycle event as an ``audit.ndjson/1`` record.

        ``kind`` is one of ``created`` / ``added`` / ``snapshot`` /
        ``restored`` / ``capacity-exceeded``.
        """
        valid = ("created", "added", "snapshot", "restored", "capacity-exceeded")
        if kind not in valid:
            raise ValueError(f"unknown audit kind {kind!r}")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError("seq must be a non-negative int")
        return {
            "schema": "audit.ndjson/1",
            "kind": f"bloom-filter.{kind}",
            "module": BLOOM_FILTER_SCHEMA,
            "version": BLOOM_FILTER_VERSION,
            "seq": seq,
            "capacity": self._config.capacity,
            "inserted": self._inserted,
            "false_positive_rate": self.false_positive_rate(),
            "state_digest": self.state_digest(),
        }


def main() -> None:
    filt = BloomFilter.create(capacity=1000, error_rate=0.01)
    assert not filt.might_contain("hello")
    assert filt.add("hello") is True
    assert filt.might_contain("hello") is True
    assert filt.false_positive_rate() > 0.0
    restored = BloomFilter.from_bytes(filt.to_bytes())
    assert restored.might_contain("hello") is True
    assert restored.state_digest() == filt.state_digest()
    print("bloom-filter OK: add/query, estimated FP rate, snapshot round-trip")


if __name__ == "__main__":
    main()
