"""Time-lock puzzles for future-dated decryption: timelock encryption.

A timelock encrypts a payload so it *cannot be read before* a caller-chosen
sequence number. In Northstar there is no wall-clock (all timing is caller
seqs), so "time" here means audit/ledger sequence: ``encrypt(data,
unlock_seq)`` seals the payload, and ``decrypt`` refuses to open it while
``current_seq < unlock_seq``. The interface models the Rivest--Shamir--Wagner
(1996) time-lock puzzle:

``solution = sha256^(unlock_seq)(seed)`` -- exactly ``unlock_seq``
sequential hashes; no shortcut exists because each step feeds the next.

``key  = sha256(DOM_KEY || solution)``
``pad  = sha256(key || i)`` for each 32-byte block ``i`` (a stream cipher)

``tag  = sha256(DOM_TAG || key || ciphertext)`` -- embedded integrity pin

Encryption is deterministic: same ``(data, unlock_seq)`` inputs produce
bit-identical ciphertexts (no wall-clock, no randomness -- audit-snapshot
safe, same convention as ``bloom_filter``). The puzzle seed binds the data
digest and the unlock sequence, so a ciphertext cannot be silently
re-pinned to an earlier ``unlock_seq``.

Honest scope: this is a *simulated* time-lock, not cryptographic
enforcement. The generator performs the same ``unlock_seq`` squarings as
the solver (there is no trapdoor asymmetry -- a real RSW deployment keeps
a secret modulus so encryption is fast while solving is slow), and the
early-decrypt refusal is *procedural policy*: the interface will not
decrypt before ``unlock_seq``, but nothing physical stops a caller that
recomputes the key itself. Pair with ``vdf_interface`` for verifiable
delay, or a real RSW modulus (encryptor holds the trapdoor) for genuine
time-lock semantics. Solving cost is one hash per step, so
``MAX_PUZZLE_STEPS`` (default 100_000) keeps encryption/decryption from
becoming a host DoS vector. The stream cipher and tag are integrity
scaffolding for the simulation, not an AEAD claim.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple


#: Version pin for this module's record shape.
TIMELOCK_ENC_VERSION = "timelock-enc.v1"

#: Schema pin carried on audit records.
TIMELOCK_ENC_SCHEMA = "northstar.timelock-enc.v1"

#: Domain separators.
_DOM_SEED = b"northstar.timelock-enc.v1/seed"
_DOM_KEY = b"northstar.timelock-enc.v1/key"
_DOM_TAG = b"northstar.timelock-enc.v1/tag"

#: Wire-format magic + version byte.
_WIRE_MAGIC = b"TLCK"
_WIRE_VERSION = b"\x01"

#: Largest puzzle this implementation will run (fail-closed above it).
DEFAULT_MAX_PUZZLE_STEPS = 100_000

#: SHA-256 output length, bytes.
_DIGEST_LEN = 32


class TimelockEncError(Exception):
    """Base error for timelock-encryption failures."""


class TooEarlyError(TimelockEncError):
    """Raised by :meth:`TimelockEnc.decrypt` before ``unlock_seq``."""

    def __init__(self, unlock_seq: int, current_seq: int):
        self.unlock_seq = unlock_seq
        self.current_seq = current_seq
        super().__init__(
            f"ciphertext unlocks at seq {unlock_seq}, "
            f"current seq is {current_seq}"
        )


class IntegrityError(TimelockEncError):
    """Raised when a ciphertext's integrity tag does not verify."""


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _solve_puzzle(seed: bytes, steps: int) -> bytes:
    """Run the sequential puzzle: ``steps`` chained hashes from ``seed``."""
    state = seed
    for _ in range(steps):
        state = hashlib.sha256(state).digest()
    return state


def _derive_key(solution: bytes) -> bytes:
    return _sha256(_DOM_KEY, solution)


def _xor_stream(key: bytes, data: bytes) -> bytes:
    """Encrypt/decrypt ``data`` with the key-derived pad (symmetric)."""
    out = bytearray(len(data))
    block = 0
    pos = 0
    while pos < len(data):
        pad = _sha256(key, _u64(block))
        take = min(_DIGEST_LEN, len(data) - pos)
        for i in range(take):
            out[pos + i] = data[pos + i] ^ pad[i]
        pos += take
        block += 1
    return bytes(out)


def _compute_tag(key: bytes, ciphertext: bytes) -> bytes:
    return _sha256(_DOM_TAG, key, ciphertext)


@dataclass(frozen=True)
class TimelockCiphertext:
    """A sealed payload: decryptable only at or after ``unlock_seq``.

    ``seed`` is *public* puzzle input (like the modulus of an RSW
    time-lock puzzle): the sequential work lives in the hash chain from
    seed to solution, not in the seed's secrecy. The seed binds
    ``sha256(data)``, so a solved key cannot be transplanted onto a
    different payload.
    """

    ciphertext: bytes
    unlock_seq: int
    seed: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes")
        if isinstance(self.unlock_seq, bool) or not isinstance(
            self.unlock_seq, int
        ):
            raise TypeError("unlock_seq must be an int")
        if self.unlock_seq < 0:
            raise ValueError("unlock_seq must be non-negative")
        if not isinstance(self.seed, (bytes, bytearray)) or len(self.seed) != _DIGEST_LEN:
            raise ValueError("seed must be a 32-byte digest")
        if not isinstance(self.tag, (bytes, bytearray)) or len(self.tag) != _DIGEST_LEN:
            raise ValueError("tag must be a 32-byte digest")

    def digest(self) -> str:
        """Pin this ciphertext's exact state: ``sha256:<hex>``."""
        return "sha256:" + _sha256(
            _DOM_TAG,
            _u64(self.unlock_seq),
            bytes(self.seed),
            bytes(self.ciphertext),
            bytes(self.tag),
        ).hex()

    def as_dict(self) -> dict:
        return {
            "schema": TIMELOCK_ENC_SCHEMA,
            "version": TIMELOCK_ENC_VERSION,
            "unlock_seq": self.unlock_seq,
            "seed": "sha256:" + bytes(self.seed).hex(),
            "ciphertext_hex": bytes(self.ciphertext).hex(),
            "tag": "sha256:" + bytes(self.tag).hex(),
            "digest": self.digest(),
        }

    def to_bytes(self) -> bytes:
        """Wire format; ends with a SHA-256 pin of the body."""
        body = (
            _WIRE_MAGIC
            + _WIRE_VERSION
            + _u64(self.unlock_seq)
            + bytes(self.seed)
            + _u64(len(self.ciphertext))
            + bytes(self.ciphertext)
            + bytes(self.tag)
        )
        return body + _sha256(body)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "TimelockCiphertext":
        """Restore from :meth:`to_bytes`; verifies the pin first."""
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError("raw must be bytes")
        raw = bytes(raw)
        min_len = 4 + 1 + 8 + _DIGEST_LEN + 8 + _DIGEST_LEN + _DIGEST_LEN
        if len(raw) < min_len:
            raise TimelockEncError("wire bytes too short")
        body, pin = raw[:-_DIGEST_LEN], raw[-_DIGEST_LEN:]
        if not hmac.compare_digest(_sha256(body), pin):
            raise IntegrityError("wire pin mismatch: bytes tampered")
        magic, version = body[:4], body[4:5]
        if magic != _WIRE_MAGIC or version != _WIRE_VERSION:
            raise TimelockEncError("bad wire magic/version")
        unlock_seq = int.from_bytes(body[5:13], "big")
        seed = body[13 : 13 + _DIGEST_LEN]
        ct_len = int.from_bytes(body[13 + _DIGEST_LEN : 21 + _DIGEST_LEN], "big")
        base = 21 + _DIGEST_LEN
        if len(body) != base + ct_len + _DIGEST_LEN:
            raise TimelockEncError("wire length mismatch")
        ct = body[base : base + ct_len]
        tag = body[base + ct_len : base + ct_len + _DIGEST_LEN]
        return cls(ciphertext=ct, unlock_seq=unlock_seq, seed=seed, tag=tag)


class TimelockEnc:
    """Timelock puzzle engine: seal to a future seq, refuse early opens."""

    def __init__(self, max_puzzle_steps: int = DEFAULT_MAX_PUZZLE_STEPS):
        if isinstance(max_puzzle_steps, bool) or not isinstance(
            max_puzzle_steps, int
        ):
            raise TypeError("max_puzzle_steps must be an int")
        if max_puzzle_steps <= 0:
            raise ValueError("max_puzzle_steps must be positive")
        self.max_puzzle_steps = max_puzzle_steps

    # -- sealing ------------------------------------------------------
    def encrypt(self, data: bytes, unlock_seq: int) -> TimelockCiphertext:
        """Seal ``data`` so it opens only at ``unlock_seq`` or later."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        if isinstance(unlock_seq, bool) or not isinstance(unlock_seq, int):
            raise TypeError("unlock_seq must be an int")
        if unlock_seq < 0:
            raise ValueError("unlock_seq must be non-negative")
        if unlock_seq > self.max_puzzle_steps:
            raise ValueError(
                f"unlock_seq {unlock_seq} exceeds max_puzzle_steps "
                f"{self.max_puzzle_steps}"
            )
        data = bytes(data)
        seed = _sha256(_DOM_SEED, _sha256(data), _u64(unlock_seq))
        key = _derive_key(_solve_puzzle(seed, unlock_seq))
        ciphertext = _xor_stream(key, data)
        return TimelockCiphertext(
            ciphertext=ciphertext,
            unlock_seq=unlock_seq,
            seed=seed,
            tag=_compute_tag(key, ciphertext),
        )

    # -- opening ------------------------------------------------------
    def decrypt(
        self, record: TimelockCiphertext, current_seq: int
    ) -> bytes:
        """Open ``record``; raises :class:`TooEarlyError` before unlock."""
        if not isinstance(record, TimelockCiphertext):
            raise TypeError("record must be a TimelockCiphertext")
        if isinstance(current_seq, bool) or not isinstance(current_seq, int):
            raise TypeError("current_seq must be an int")
        if current_seq < 0:
            raise ValueError("current_seq must be non-negative")
        if current_seq < record.unlock_seq:
            raise TooEarlyError(record.unlock_seq, current_seq)
        # Re-run the sequential puzzle from the public seed (same cost
        # the sealer paid), derive the key, then verify before opening.
        key = _derive_key(_solve_puzzle(bytes(record.seed), record.unlock_seq))
        if not hmac.compare_digest(
            _compute_tag(key, bytes(record.ciphertext)), bytes(record.tag)
        ):
            raise IntegrityError("ciphertext tag does not verify")
        return _xor_stream(key, bytes(record.ciphertext))


def timelock_enc_audit_event(
    kind: str, unlock_seq: int, seq: int
) -> dict:
    """Shape a timelock lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("encrypted", "decrypted", "decrypt-refused", "integrity-failed")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if isinstance(unlock_seq, bool) or not isinstance(unlock_seq, int):
        raise TypeError("unlock_seq must be an int")
    if unlock_seq < 0:
        raise ValueError("unlock_seq must be non-negative")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"timelock-enc.{kind}",
        "module": TIMELOCK_ENC_SCHEMA,
        "version": TIMELOCK_ENC_VERSION,
        "unlock_seq": unlock_seq,
        "seq": seq,
    }


def main() -> None:
    engine = TimelockEnc()
    sealed = engine.encrypt(b"future payload", 50)
    try:
        engine.decrypt(sealed, 49)
        raise AssertionError("early decrypt must refuse")
    except TooEarlyError:
        pass
    assert engine.decrypt(sealed, 50) == b"future payload"
    assert engine.decrypt(sealed, 500) == b"future payload"
    print("timelock-enc OK: seal, early refusal, on-time open")


if __name__ == "__main__":
    main()
