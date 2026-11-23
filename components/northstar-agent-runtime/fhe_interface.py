"""Fully homomorphic encryption interface (simulated).

Research datum: FHE lets an untrusted host compute on data it cannot read
- the server evaluates a circuit over ciphertexts and only the key holder
decrypts the result. That is the right shape for private agent inference,
delegated analytics over sensitive memory, and confidential multi-party
agent workflows: ``keygen -> encrypt -> evaluate -> decrypt``.

This module is the *scheme-level interface* contract, distinct from
``fhe_wrapper`` (which is a single-key evaluator object without key
management). It pins:

- ``keygen(seed)`` -> frozen ``KeyPair`` (public/secret pins, deterministic
  from the caller seed).
- ``FHE(seed)`` session holder: ``encrypt(value, seq)``,
  ``decrypt(ciphertext)``, ``add(ct1, ct2)``, ``multiply(ct1, ct2)``, and
  ``evaluate(program, inputs, seq)`` - a pinned op DAG so the host's
  circuit is auditable, not an opaque lambda.
- A *noise budget*: fresh ciphertexts carry noise 0; homomorphic adds
  accumulate noise additively and multiplies compound it; ``decrypt``
  fail-closes past ``MAX_NOISE``. This is the load-bearing FHE invariant
  (multiplicative depth is bounded; real schemes bootstrap past it).
- Integrity digests over every ciphertext (HMAC with the secret pin),
  so a host that tampers with a ciphertext gets a fail-closed
  ``IntegrityError`` instead of a wrong plaintext.

Honest scope (read before relying on this):

- Simulated cryptography: the plaintext value is carried *in the record*
  under an integrity digest so the noise model and the API shape can be
  exercised. The process sees the plaintext; this provides zero
  confidentiality and is NOT a security boundary.
- Exact integer arithmetic only (BFV/BGV style); CKKS approximate-float
  semantics are not simulated.
- The noise model is deliberately simple (documented constants below).
  Real noise growth is subtler and scheme-dependent.
- Deterministic: same seed, value, and op sequence always produce the
  same ciphertexts. ``keygen`` takes a caller seed so two deployments
  cannot silently share a key.
- Values are bounded by ``PLAINTEXT_BOUND`` (|v| < 2^63); overflows
  fail-closed at eval time rather than wrapping silently.

No wall-clock anywhere (caller-supplied int seqs). stdlib only
(``hashlib``, ``hmac``, ``dataclasses``, ``typing``).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Sequence, Tuple

#: Version pin for the interface described here.
FHE_INTERFACE_VERSION = "fhe-interface.v1"

#: Schema pin stamped on ciphertexts and audit records.
FHE_INTERFACE_SCHEMA = "northstar.fhe-interface.v1"

#: Maximum accumulated noise a ciphertext may carry and still decrypt.
MAX_NOISE = 100

#: Noise added by one homomorphic addition, on top of operand noise.
ADD_NOISE = 1

#: Noise contributed by one homomorphic multiplication.
MUL_NOISE = 8

#: Plaintext bound: |value| must be < 2**63. Overflows fail closed.
PLAINTEXT_BOUND = 2**63

#: Fixed domain string mixed into every key and digest derivation.
_DOMAIN = b"northstar.fhe-interface.v1"


class FHEError(ValueError):
    """Raised for malformed FHE inputs (fail-closed)."""


class IntegrityError(FHEError):
    """Raised when a ciphertext digest does not verify."""


class NoiseExceededError(FHEError):
    """Raised when a ciphertext is too noisy to decrypt."""


class KeyMismatchError(FHEError):
    """Raised when combining ciphertexts from different keys."""


def _check_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    return value


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return seq


def _check_seed(seed: object) -> bytes:
    if not isinstance(seed, bytes) or len(seed) == 0:
        raise TypeError("seed must be non-empty bytes")
    if len(seed) > 1024:
        raise ValueError("seed must be at most 1024 bytes")
    return seed


def _check_bound(name: str, value: int) -> int:
    if abs(value) >= PLAINTEXT_BOUND:
        raise FHEError(f"{name}={value} exceeds plaintext bound 2**63")
    return value


def _derive(label: bytes, *parts: bytes) -> bytes:
    """Domain-separated deterministic derivation."""
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(label)
    for part in parts:
        h.update(len(part).to_bytes(8, "big"))
        h.update(part)
    return h.digest()


def _int_bytes(value: int) -> bytes:
    """Sign-aware fixed-width encoding (immune to the JCS >2**53 caveat)."""
    sign = b"\x01" if value < 0 else b"\x00"
    return sign + abs(value).to_bytes(16, "big")


@dataclass(frozen=True)
class KeyPair:
    """A derived FHE key pair (pins only, never raw key material)."""

    key_id: str
    public_pin: str
    secret_pin: str

    def as_dict(self) -> dict:
        return {
            "schema": FHE_INTERFACE_SCHEMA,
            "key_id": self.key_id,
            "public_pin": self.public_pin,
            "secret_pin": self.secret_pin,
        }


@dataclass(frozen=True)
class Ciphertext:
    """A simulated FHE ciphertext: pinned value + noise ledger."""

    key_id: str
    value: int
    noise: int
    nonce: str
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": FHE_INTERFACE_SCHEMA,
            "version": FHE_INTERFACE_VERSION,
            "key_id": self.key_id,
            "value": self.value,
            "noise": self.noise,
            "nonce": self.nonce,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class EvalOp:
    """One pinned homomorphic op: ``kind`` in {"add", "mul"} over refs.

    Operands are indices into the working list: the program inputs first,
    then each produced intermediate in order. ``EvalOp("add", 0, 1)``
    adds the first two inputs.
    """

    kind: str
    left: int
    right: int

    def __post_init__(self) -> None:
        if self.kind not in ("add", "mul"):
            raise FHEError(f"unknown op kind {self.kind!r}")
        if isinstance(self.left, bool) or not isinstance(self.left, int) or self.left < 0:
            raise FHEError("op left index must be a non-negative int")
        if isinstance(self.right, bool) or not isinstance(self.right, int) or self.right < 0:
            raise FHEError("op right index must be a non-negative int")


@dataclass(frozen=True)
class EvalReport:
    """Frozen outcome of a pinned evaluation program."""

    ops: int
    input_count: int
    final_noise: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": FHE_INTERFACE_SCHEMA,
            "version": FHE_INTERFACE_VERSION,
            "ops": self.ops,
            "input_count": self.input_count,
            "final_noise": self.final_noise,
            "digest": self.digest,
        }


def keygen(seed: bytes) -> KeyPair:
    """Derive a deterministic key pair from a caller-supplied seed."""
    seed = _check_seed(seed)
    public = _derive(b"public", seed).hex()
    secret = _derive(b"secret", seed).hex()
    key_id = "fhe:" + _derive(b"key-id", seed).hex()[:16]
    return KeyPair(key_id=key_id, public_pin="sha256:" + public, secret_pin="sha256:" + secret)


class FHE:
    """Scheme-level FHE session bound to one key pair.

    All methods are deterministic; ``seq`` values are caller-supplied
    (no wall-clock). Ciphertexts are frozen records that may only be
    combined with ciphertexts from the same ``key_id``.
    """

    def __init__(self, seed: bytes):
        self._keypair = keygen(seed)
        self._mac = _derive(b"mac", seed)
        self._nonce_counter = 0

    @property
    def keypair(self) -> KeyPair:
        return self._keypair

    def _mac_for(self, value: int, noise: int, nonce: str) -> str:
        body = b"|".join(
            [
                _DOMAIN,
                self._keypair.key_id.encode(),
                _int_bytes(value),
                noise.to_bytes(8, "big"),
                nonce.encode(),
            ]
        )
        return "sha256:" + hmac.new(self._mac, body, hashlib.sha256).hexdigest()

    def _mint(self, value: int, noise: int, seq: int) -> Ciphertext:
        _check_bound("value", value)
        _check_seq(seq)
        self._nonce_counter += 1
        nonce = f"{self._nonce_counter:08d}:{seq}"
        digest = self._mac_for(value, noise, nonce)
        return Ciphertext(
            key_id=self._keypair.key_id,
            value=value,
            noise=noise,
            nonce=nonce,
            digest=digest,
        )

    def _verify(self, ct: Ciphertext, name: str) -> None:
        if not isinstance(ct, Ciphertext):
            raise TypeError(f"{name} must be a Ciphertext")
        if ct.key_id != self._keypair.key_id:
            raise KeyMismatchError(f"{name} was not encrypted under this key")
        expected = self._mac_for(ct.value, ct.noise, ct.nonce)
        if not hmac.compare_digest(expected, ct.digest):
            raise IntegrityError(f"{name} digest does not verify")

    def encrypt(self, value: int, seq: int) -> Ciphertext:
        """Encrypt an integer; fresh ciphertexts carry noise 0."""
        value = _check_int("value", value)
        _check_bound("value", value)
        return self._mint(value, 0, seq)

    def decrypt(self, ct: Ciphertext) -> int:
        """Decrypt; fail-closed if the digest is bad or noise is over budget."""
        self._verify(ct, "ciphertext")
        if ct.noise > MAX_NOISE:
            raise NoiseExceededError(
                f"ciphertext noise {ct.noise} exceeds MAX_NOISE={MAX_NOISE}"
            )
        return ct.value

    def add(self, c1: Ciphertext, c2: Ciphertext, seq: int) -> Ciphertext:
        """Homomorphic addition; noise compounds additively."""
        self._verify(c1, "c1")
        self._verify(c2, "c2")
        noise = c1.noise + c2.noise + ADD_NOISE
        return self._mint(c1.value + c2.value, noise, seq)

    def multiply(self, c1: Ciphertext, c2: Ciphertext, seq: int) -> Ciphertext:
        """Homomorphic multiplication; noise compounds multiplicatively."""
        self._verify(c1, "c1")
        self._verify(c2, "c2")
        noise = (c1.noise + 1) * (c2.noise + 1) - 1 + MUL_NOISE
        return self._mint(c1.value * c2.value, noise, seq)

    def evaluate(
        self, program: Sequence[EvalOp], inputs: Sequence[Ciphertext], seq: int
    ) -> Tuple[Ciphertext, EvalReport]:
        """Run a pinned op program over input ciphertexts.

        Each op appends its result to the working list; the final
        produced ciphertext is returned with a frozen ``EvalReport``.
        """
        _check_seq(seq)
        if not isinstance(inputs, (list, tuple)) or len(inputs) == 0:
            raise TypeError("inputs must be a non-empty list/tuple of Ciphertext")
        if not isinstance(program, (list, tuple)):
            raise TypeError("program must be a list/tuple of EvalOp")
        working = list(inputs)
        for i, ct in enumerate(working):
            self._verify(ct, f"inputs[{i}]")
        produced = 0
        for i, op in enumerate(program):
            if not isinstance(op, EvalOp):
                raise TypeError(f"program[{i}] must be an EvalOp")
            if op.left >= len(working) or op.right >= len(working):
                raise FHEError(f"program[{i}] references missing intermediate")
            a, b = working[op.left], working[op.right]
            if op.kind == "add":
                working.append(self.add(a, b, seq))
            else:
                working.append(self.multiply(a, b, seq))
            produced += 1
        final = working[-1]
        body = b"|".join(
            [
                _DOMAIN,
                b"eval",
                str(produced).encode(),
                str(len(inputs)).encode(),
                str(final.noise).encode(),
                final.digest.encode(),
            ]
        )
        report = EvalReport(
            ops=produced,
            input_count=len(inputs),
            final_noise=final.noise,
            digest="sha256:" + hashlib.sha256(body).hexdigest(),
        )
        return final, report


def fhe_audit_event(kind: str, seq: int, *, detail: str = "") -> dict:
    """Shape an FHE lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("keygen", "encrypt", "decrypt", "eval", "integrity-failed", "noise-exceeded")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, str):
        raise TypeError("detail must be str")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"fhe-interface.{kind}",
        "module": FHE_INTERFACE_SCHEMA,
        "version": FHE_INTERFACE_VERSION,
        "seq": seq,
        "detail": detail,
    }


def main() -> None:
    fhe = FHE(b"self-check-seed-0123456789abcdef")
    c1 = fhe.encrypt(7, 0)
    c2 = fhe.encrypt(6, 1)
    assert fhe.decrypt(fhe.add(c1, c2, 2)) == 13
    assert fhe.decrypt(fhe.multiply(c1, c2, 3)) == 42
    prog = [EvalOp("add", 0, 1), EvalOp("mul", 2, 0)]  # (7+6)*7 = 91
    final, report = fhe.evaluate(prog, [c1, c2], 4)
    assert fhe.decrypt(final) == 91
    assert report.ops == 2 and report.input_count == 2
    deep = fhe.encrypt(1, 4)
    for _ in range(3):
        deep = fhe.multiply(deep, deep, 5)
    try:
        fhe.decrypt(deep)
    except NoiseExceededError:
        pass
    else:
        raise AssertionError("expected NoiseExceededError")
    tampered = Ciphertext(c1.key_id, c1.value + 1, c1.noise, c1.nonce, c1.digest)
    try:
        fhe.decrypt(tampered)
    except IntegrityError:
        pass
    else:
        raise AssertionError("expected IntegrityError")
    print("fhe-interface OK: keygen, encrypt, add, multiply, eval, noise budget, integrity")


if __name__ == "__main__":
    main()
