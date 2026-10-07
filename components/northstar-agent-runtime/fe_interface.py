"""Functional encryption interface (Boneh-Sahai-Waters style, simulated).

Research motivation: functional encryption (Boneh, Sahai, Waters 2011)
generalizes public-key encryption: a function key ``fsk_f`` issued for a
function ``f`` decrypts a ciphertext of ``x`` to ``f(x)`` - and *nothing
else*. The key holder learns the function's output without ever seeing the
raw plaintext. Inner-product FE (Abdalla et al. 2015) is the practical
workhorse: the function is a dot product with a pinned vector, used for
privacy-preserving aggregation (weighted sums, means) over encrypted
telemetry.

This module is the *interface mechanics* half, so the plumbing the runtime
depends on is pinned:

- ``FE.setup(label)`` -- deterministic per-label authority: derives master
  key material as ``SHA-256(domain || "msk:" || label)``. The label is the
  caller's deployment pin; same label always yields the same authority,
  different labels are disjoint (cross-authority keys and ciphertexts are
  fail-closed).
- ``FE.keygen(function_id, seq)`` -- issues a frozen ``FunctionKey`` bound
  to ``(authority_id, function_id)`` by a digest pin. The function must be
  in the pinned vocabulary; unknown functions are refused fail-closed.
- ``FE.encrypt(data, seq)`` -- seals a list of numbers under a
  SHA-256 keystream keyed by the master secret, with a ``sha256:`` data
  pin and an integrity MAC. The nonce is derived deterministically from a
  per-authority counter (no randomness, replayable).
- ``FE.decrypt(fsk, ct, seq)`` -- verifies the key belongs to this
  authority, verifies the ciphertext MAC (tampering is fail-closed,
  never silently decrypted), unseals, and evaluates the *pinned*
  function. It returns ``f(data)`` only - raw data is never exposed to
  the caller.

Function vocabulary (pure, deterministic, pinned by id):

- ``"sum"``   -- sum of the list (empty -> 0.0)
- ``"mean"``  -- arithmetic mean (empty -> FEError, no honest value)
- ``"max"`` / ``"min"`` -- extrema (empty -> FEError)
- ``"count"`` -- list length

Data model: a flat list of ints/floats. Booleans are rejected
(``True == 1`` would alias values), NaN/inf are rejected (no canonical
encoding), and non-list / non-numeric inputs are rejected fail-closed.

Public API:

- ``FE`` -- authority object (``setup`` classmethod, ``keygen``,
  ``encrypt``, ``decrypt``).
- ``FunctionKey`` -- frozen: ``authority_id``, ``function_id``,
  ``function_digest``, ``key_id`` pins.
- ``Ciphertext`` -- frozen: ``authority_id``, ``nonce``, ``sealed``,
  ``data_pin``, ``mac`` pins.
- ``FUNCTIONS`` -- the pinned function vocabulary (id -> callable).
- ``fe_audit_event(kind, seq)`` -- ``audit.ndjson/1``-shaped records
  (``setup`` / ``key-issued`` / ``encrypted`` / ``decrypted`` /
  ``decrypt-rejected``).

Honest scope:

- Simulated cryptography: the "encryption" is a SHA-256 keystream XOR -
  a real symmetric cipher shape, not a security boundary. Real FE needs
  pairings or LWE; collusion resistance (two function keys combining to
  learn more than either function reveals) is *not* provided here, because
  the simulation's authority holds the master secret. Do not use where an
  adversary holds keys.
- What the interface *does* pin: function restriction (a key for ``sum``
  computes exactly ``sum``, never raw data and never ``mean``),
  ciphertext integrity (tampering fails closed), authority isolation
  (keys/ciphertexts do not cross authorities), and deterministic,
  reproducible behavior.
- The raw-data hiding is a *policy* of ``decrypt``, not a cryptographic
  guarantee: the host running this code also holds the master secret.
  Treat this as interface bookkeeping for the pipeline, not as a
  confidentiality primitive.

No wall-clock anywhere. stdlib only (``hashlib``, ``hmac``,
``dataclasses``, ``typing``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass
from typing import Callable, Dict, List, Sequence

#: Version pin for the functional-encryption interface described here.
FE_VERSION = "fe-interface.v1"
#: Schema pin carried by audit records and frozen records.
FE_SCHEMA = "northstar.fe-interface.v1"

_DOMAIN = b"northstar-fe-interface.v1"


class FEError(Exception):
    """Base error for the functional-encryption interface."""


class CiphertextIntegrityError(FEError):
    """Raised when a ciphertext fails its integrity check (tampered)."""


def _is_number(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _validate_data(data: object) -> List[float]:
    """Validate a plaintext payload: flat list of finite numbers."""
    if isinstance(data, bool) or not isinstance(data, (list, tuple)):
        raise FEError("data must be a list of numbers")
    out: List[float] = []
    for item in data:
        if not _is_number(item):
            raise FEError(f"data items must be int/float, got {type(item).__name__}")
        if isinstance(item, float) and (math.isnan(item) or math.isinf(item)):
            raise FEError("NaN/inf have no canonical encoding")
        out.append(item)
    return list(out)


def _canonical_number(x: float) -> str:
    # repr is exact round-trip for ints and floats (no 2^53 loss).
    return repr(x)


def _canonical_data(data: Sequence[float]) -> bytes:
    return ("[" + ",".join(_canonical_number(x) for x in data) + "]").encode("ascii")


def _data_pin(data: Sequence[float]) -> str:
    return "sha256:" + hashlib.sha256(_DOMAIN + b":data:" + _canonical_data(data)).hexdigest()


def _keystream(key_material: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            key_material + b":stream:" + nonce + counter.to_bytes(4, "big")
        ).digest()
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _fn_sum(data: Sequence[float]) -> float:
    return float(sum(data))


def _fn_mean(data: Sequence[float]) -> float:
    if not data:
        raise FEError("mean of empty data is undefined")
    return float(sum(data)) / len(data)


def _fn_max(data: Sequence[float]) -> float:
    if not data:
        raise FEError("max of empty data is undefined")
    return float(max(data))


def _fn_min(data: Sequence[float]) -> float:
    if not data:
        raise FEError("min of empty data is undefined")
    return float(min(data))


def _fn_count(data: Sequence[float]) -> int:
    return len(data)


#: Pinned function vocabulary: function id -> pure implementation.
FUNCTIONS: Dict[str, Callable[[Sequence[float]], object]] = {
    "sum": _fn_sum,
    "mean": _fn_mean,
    "max": _fn_max,
    "min": _fn_min,
    "count": _fn_count,
}


def _function_digest(function_id: str) -> str:
    return "sha256:" + hashlib.sha256(_DOMAIN + b":fn:" + function_id.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class FunctionKey:
    """A function key: bound to one authority and one function id."""

    authority_id: str
    function_id: str
    function_digest: str
    key_id: str

    def as_dict(self) -> dict:
        return {
            "schema": FE_SCHEMA,
            "version": FE_VERSION,
            "authority_id": self.authority_id,
            "function_id": self.function_id,
            "function_digest": self.function_digest,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class Ciphertext:
    """A sealed FE ciphertext."""

    authority_id: str
    nonce: bytes
    sealed: bytes
    data_pin: str
    mac: str

    def as_dict(self) -> dict:
        return {
            "schema": FE_SCHEMA,
            "version": FE_VERSION,
            "authority_id": self.authority_id,
            "nonce": self.nonce.hex(),
            "sealed": self.sealed.hex(),
            "data_pin": self.data_pin,
            "mac": self.mac,
        }


class FE:
    """A functional-encryption authority (simulated).

    Holds the master secret internally; ``decrypt`` is the only path from
    ciphertext to information, and it returns ``f(data)`` only.
    """

    def __init__(self, label: str) -> None:
        if not isinstance(label, str) or not label:
            raise FEError("label must be a non-empty str")
        self._label = label
        self._msk = hashlib.sha256(_DOMAIN + b":msk:" + label.encode("utf-8")).digest()
        self._authority_id = "sha256:" + hashlib.sha256(
            _DOMAIN + b":authority:" + label.encode("utf-8")
        ).hexdigest()
        self._encrypt_counter = 0

    @classmethod
    def setup(cls, label: str) -> "FE":
        """Create the authority for ``label`` (deterministic)."""
        return cls(label)

    @property
    def authority_id(self) -> str:
        return self._authority_id

    @property
    def master_public_pin(self) -> str:
        """Public pin identifying this authority (no secret material)."""
        return "sha256:" + hashlib.sha256(
            _DOMAIN + b":mpk:" + self._label.encode("utf-8")
        ).hexdigest()

    def keygen(self, function_id: str) -> FunctionKey:
        """Issue a function key for a vocabulary function id."""
        if not isinstance(function_id, str) or function_id not in FUNCTIONS:
            raise FEError(f"unknown function id {function_id!r}")
        fn_digest = _function_digest(function_id)
        key_id = "sha256:" + hashlib.sha256(
            _DOMAIN + b":key:" + self._authority_id.encode("ascii") + b":" + fn_digest.encode("ascii")
        ).hexdigest()
        return FunctionKey(
            authority_id=self._authority_id,
            function_id=function_id,
            function_digest=fn_digest,
            key_id=key_id,
        )

    def encrypt(self, data: Sequence[float]) -> Ciphertext:
        """Seal ``data`` into a ciphertext (flat list of numbers)."""
        values = _validate_data(data)
        plaintext = _canonical_data(values)
        nonce = hashlib.sha256(
            self._msk + b":nonce:" + self._encrypt_counter.to_bytes(8, "big")
        ).digest()[:16]
        self._encrypt_counter += 1
        sealed = _xor(plaintext, _keystream(self._msk, nonce, len(plaintext)))
        pin = _data_pin(values)
        mac = "sha256:" + hashlib.sha256(
            self._msk + b":mac:" + nonce + sealed + pin.encode("ascii")
        ).hexdigest()
        return Ciphertext(
            authority_id=self._authority_id,
            nonce=nonce,
            sealed=sealed,
            data_pin=pin,
            mac=mac,
        )

    def decrypt(self, fsk: FunctionKey, ct: Ciphertext):
        """Evaluate the key's pinned function over the ciphertext's data.

        Returns ``f(data)`` only; raw data is never returned.
        """
        if not isinstance(fsk, FunctionKey):
            raise FEError("fsk must be a FunctionKey")
        if not isinstance(ct, Ciphertext):
            raise FEError("ct must be a Ciphertext")
        if fsk.authority_id != self._authority_id:
            raise FEError("function key belongs to another authority")
        if ct.authority_id != self._authority_id:
            raise FEError("ciphertext belongs to another authority")
        expected_mac = "sha256:" + hashlib.sha256(
            self._msk + b":mac:" + ct.nonce + ct.sealed + ct.data_pin.encode("ascii")
        ).hexdigest()
        if not hmac.compare_digest(expected_mac.encode("ascii"), ct.mac.encode("ascii")):
            raise CiphertextIntegrityError("ciphertext integrity check failed")
        plaintext = _xor(ct.sealed, _keystream(self._msk, ct.nonce, len(ct.sealed)))
        try:
            raw = json.loads(plaintext.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CiphertextIntegrityError("ciphertext payload undecodable") from exc
        values = _validate_data(raw)
        if _data_pin(values) != ct.data_pin:
            raise CiphertextIntegrityError("ciphertext data pin mismatch")
        fn = FUNCTIONS[fsk.function_id]
        return fn(values)


def fe_audit_event(kind: str, seq: int) -> dict:
    """Shape an FE lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("setup", "key-issued", "encrypted", "decrypted", "decrypt-rejected")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"fe-interface.{kind}",
        "module": FE_SCHEMA,
        "version": FE_VERSION,
        "seq": seq,
    }


def main() -> None:
    fe = FE.setup("self-check")
    assert fe.authority_id.startswith("sha256:")
    data = [1.0, 2.0, 3.0, 4.0]
    ct = fe.encrypt(data)
    assert fe.decrypt(fe.keygen("sum"), ct) == 10.0
    assert fe.decrypt(fe.keygen("mean"), ct) == 2.5
    assert fe.decrypt(fe.keygen("count"), ct) == 4
    assert fe.decrypt(fe.keygen("max"), ct) == 4.0
    assert fe.decrypt(fe.keygen("min"), ct) == 1.0
    # Raw data is never exposed: count key returns a count, not the list.
    assert fe.decrypt(fe.keygen("count"), ct) != data
    print("fe-interface OK: setup, keygen, encrypt, decrypt, function restriction")


if __name__ == "__main__":
    main()
