"""Tamper-evident append-only ordering: a hash chain for audit trails.

A hash chain answers "in what order did these records land, and has any
of them been altered since?". Each :meth:`HashChain.append` binds the new
payload's digest to the previous link's digest:

``link_hash = sha256(prev_hash || data_digest || seq)``

so changing any earlier payload (or its position) breaks every later
link -- tampering is detectable by :meth:`HashChain.verify` walking the
chain head-to-tail. The first link binds to a fixed ``genesis`` pin, so
a chain's identity is ``genesis || first link`` and two hosts that start
from the same genesis and append the same payloads in the same order
compute bit-identical chains (no wall-clock, no randomness).

Payload canonicalization is local to this module (stdlib only, no
sibling imports): mappings are sorted by key, sequences keep order,
``str``/``bytes`` are hashed as-is with distinct domain tags, integers
are encoded exactly (arbitrary precision). ``float('nan')`` /
``inf`` are refused, and integral floats beyond 2**53 are refused --
they cannot round-trip through JSON without silent loss (the same
caveat documented in ``secure_aggregation``; see its ``_hexint``
pattern for the host-side workaround).

Honest scope: a hash chain proves *ordering* and *tamper-evidence*,
nothing else. It cannot prove the payloads were true (the host chose
them), cannot prove the chain is complete (the host may simply not
append), and cannot detect a fork -- a host that shows two different
chains to two different verifiers looks fine to each one. Fork
detection needs a shared broadcast or checkpoint the host cannot
equivocate against (e.g. publishing the head digest to an append-only
log the verifier trusts). State is in-memory; persistence is the
host's job.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple


#: Version pin for this module's record shape.
HASH_CHAIN_VERSION = "hash-chain.v1"

#: Schema pin carried on audit records.
HASH_CHAIN_SCHEMA = "northstar.hash-chain.v1"

#: Fixed genesis pin: a chain's identity starts here. All zeros means
#: "no prior link" and is never a valid link_hash (which is 32 bytes of
#: sha256 output -- all-zeros would require a preimage).
_GENESIS = "sha256:" + "00" * 32

#: Domain-separation tags so "1" (str) != 1 (int) != b"1" (bytes).
_TAG_STR = b"\x01"
_TAG_BYTES = b"\x02"
_TAG_INT = b"\x03"
_TAG_FLOAT = b"\x04"
_TAG_BOOL = b"\x05"
_TAG_NULL = b"\x06"
_TAG_LIST = b"\x07"
_TAG_MAP = b"\x08"

#: Largest integer exactly representable in a JSON float.
_MAX_SAFE_INTEGER = 2**53


class HashChainError(Exception):
    """Base error for hash-chain failures."""


class ChainVerificationError(HashChainError):
    """Raised by :meth:`HashChain.verify_strict` when a link is broken."""

    def __init__(self, index: int, reason: str):
        self.index = index
        self.reason = reason
        super().__init__(f"chain broken at link {index}: {reason}")


def _canonical_digest(data: Any) -> bytes:
    """Return the raw sha256 digest of the canonical encoding of ``data``."""
    h = hashlib.sha256()
    _canonical_into(h, data)
    return h.digest()


def _canonical_into(h: Any, data: Any) -> None:
    """Feed a deterministic byte encoding of ``data`` into ``h``."""
    if data is None:
        h.update(_TAG_NULL)
    elif isinstance(data, bool):
        h.update(_TAG_BOOL + (b"\x01" if data else b"\x00"))
    elif isinstance(data, int):
        h.update(_TAG_INT + str(data).encode("ascii") + b"\x00")
    elif isinstance(data, float):
        if math.isnan(data) or math.isinf(data):
            raise HashChainError("NaN/inf payloads are not canonicalizable")
        if data.is_integer() and abs(data) > _MAX_SAFE_INTEGER:
            raise HashChainError(
                "integral float beyond 2**53 cannot round-trip JSON; "
                "pass an int instead"
            )
        h.update(_TAG_FLOAT + repr(data).encode("ascii") + b"\x00")
    elif isinstance(data, str):
        h.update(_TAG_STR + data.encode("utf-8") + b"\x00")
    elif isinstance(data, (bytes, bytearray)):
        h.update(_TAG_BYTES + bytes(data) + b"\x00")
    elif isinstance(data, Mapping):
        keys = list(data.keys())
        if any(not isinstance(k, str) for k in keys):
            raise HashChainError("mapping keys must be str for canonical order")
        h.update(_TAG_MAP)
        for k in sorted(keys):
            h.update(k.encode("utf-8") + b"\x00")
            _canonical_into(h, data[k])
        h.update(b"\xff")
    elif isinstance(data, (list, tuple)):
        h.update(_TAG_LIST)
        for item in data:
            _canonical_into(h, item)
        h.update(b"\xff")
    else:
        raise HashChainError(
            f"payload type {type(data).__name__} is not canonicalizable"
        )


def _pin(digest: bytes) -> str:
    return "sha256:" + digest.hex()


def _link_hash(prev_pin: str, data_pin: str, seq: int) -> str:
    """Compute the link binding: sha256(prev || data || seq)."""
    if prev_pin == _GENESIS:
        prev_raw = b"\x00" * 32
    else:
        if not prev_pin.startswith("sha256:"):
            raise HashChainError(f"bad prev pin {prev_pin!r}")
        prev_raw = bytes.fromhex(prev_pin[len("sha256:"):])
    data_raw = bytes.fromhex(data_pin[len("sha256:"):])
    h = hashlib.sha256()
    h.update(b"northstar.hash-chain.v1\x00")
    h.update(prev_raw)
    h.update(data_raw)
    h.update(seq.to_bytes(8, "big", signed=False))
    return _pin(h.digest())


@dataclass(frozen=True)
class ChainLink:
    """One immutable link in the chain."""

    seq: int
    data_digest: str
    prev_hash: str
    link_hash: str

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int):
            raise HashChainError("seq must be an int")
        if self.seq < 0:
            raise HashChainError("seq must be non-negative")
        for name, pin in (
            ("data_digest", self.data_digest),
            ("prev_hash", self.prev_hash),
            ("link_hash", self.link_hash),
        ):
            if not isinstance(pin, str) or not pin.startswith("sha256:"):
                raise HashChainError(f"{name} must be a 'sha256:' pin")
            if len(pin) != len("sha256:") + 64:
                raise HashChainError(f"{name} has wrong length")

    def as_dict(self) -> dict:
        return {
            "schema": HASH_CHAIN_SCHEMA,
            "version": HASH_CHAIN_VERSION,
            "seq": self.seq,
            "data_digest": self.data_digest,
            "prev_hash": self.prev_hash,
            "link_hash": self.link_hash,
        }


class HashChain:
    """Append-only tamper-evident chain of payload digests."""

    def __init__(self) -> None:
        self._links: list[ChainLink] = []

    def __len__(self) -> int:
        return len(self._links)

    def append(self, data: Any, seq: int) -> ChainLink:
        """Append ``data`` at ``seq``; returns the new frozen link.

        ``seq`` is caller-supplied (no wall-clock): it must be exactly
        the next expected value (0, 1, 2, ...) -- gaps and rewinds are
        refused fail-closed.
        """
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise HashChainError("seq must be an int")
        if seq != len(self._links):
            raise HashChainError(
                f"seq must be {len(self._links)} (next in chain), got {seq}"
            )
        data_digest = _pin(_canonical_digest(data))
        prev = self._links[-1].link_hash if self._links else _GENESIS
        link = ChainLink(
            seq=seq,
            data_digest=data_digest,
            prev_hash=prev,
            link_hash=_link_hash(prev, data_digest, seq),
        )
        self._links.append(link)
        return link

    def head(self) -> Optional[ChainLink]:
        """The newest link, or None on an empty chain."""
        return self._links[-1] if self._links else None

    def head_digest(self) -> str:
        """The head link's hash (``_GENESIS`` on an empty chain)."""
        head = self.head()
        return head.link_hash if head is not None else _GENESIS

    def links(self) -> Tuple[ChainLink, ...]:
        return tuple(self._links)

    def link(self, seq: int) -> ChainLink:
        """Fetch the link at ``seq`` (IndexError if out of range)."""
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise HashChainError("seq must be an int")
        return self._links[seq]

    def verify(self) -> bool:
        """Walk the chain; True iff every link is intact and continuous."""
        prev = _GENESIS
        for i, link in enumerate(self._links):
            if link.seq != i:
                return False
            if link.prev_hash != prev:
                return False
            if link.link_hash != _link_hash(link.prev_hash, link.data_digest, link.seq):
                return False
            prev = link.link_hash
        return True

    def verify_strict(self) -> None:
        """Like :meth:`verify` but raises :class:`ChainVerificationError`."""
        prev = _GENESIS
        for i, link in enumerate(self._links):
            if link.seq != i:
                raise ChainVerificationError(i, f"seq {link.seq} != position {i}")
            if link.prev_hash != prev:
                raise ChainVerificationError(i, "prev_hash does not match prior link")
            expected = _link_hash(link.prev_hash, link.data_digest, link.seq)
            if link.link_hash != expected:
                raise ChainVerificationError(i, "link_hash mismatch (tampered)")
            prev = link.link_hash

    def contains_data(self, data: Any) -> bool:
        """True iff a link carries exactly this payload's digest."""
        digest = _pin(_canonical_digest(data))
        return any(link.data_digest == digest for link in self._links)


def hash_chain_audit_event(kind: str, chain: HashChain, seq: int) -> dict:
    """Shape a hash-chain lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("created", "appended", "verified", "verification-failed")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if not isinstance(chain, HashChain):
        raise TypeError("chain must be a HashChain")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"hash-chain.{kind}",
        "module": HASH_CHAIN_SCHEMA,
        "version": HASH_CHAIN_VERSION,
        "seq": seq,
        "length": len(chain),
        "head_digest": chain.head_digest(),
    }


def main() -> None:
    chain = HashChain()
    assert chain.verify() is True
    assert chain.head_digest() == _GENESIS
    a = chain.append({"op": "put", "key": "k1"}, 0)
    b = chain.append({"op": "put", "key": "k2"}, 1)
    assert b.prev_hash == a.link_hash
    assert chain.verify() is True
    chain.verify_strict()
    assert chain.contains_data({"key": "k1", "op": "put"}) is True
    assert chain.contains_data({"key": "nope"}) is False
    tampered = list(chain.links())
    object.__setattr__(tampered[0], "data_digest", tampered[1].data_digest)
    evil = HashChain()
    evil._links = tampered
    assert evil.verify() is False
    print("hash-chain OK: append, ordering, tamper detection")


if __name__ == "__main__":
    main()
