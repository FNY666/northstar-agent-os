"""Homomorphic training interface (simulated).

Research datum: training *on encrypted data* - the data owner encrypts
the training set, an untrusted host runs the optimizer over ciphertexts,
and only the key holder decrypts the trained parameters. The building
blocks are the same encrypted add/multiply the ``fhe_interface`` module
pins; what this module adds is the *learning* shape: a model as an
encrypted parameter vector, a forward pass and a backward pass expressed
as homomorphic op DAGs, and SGD update steps carried out entirely under
encryption.

This module trains an encrypted linear regressor
``y ~= w . x + b`` with squared-error loss
``L = 1/2 (w.x + b - y)^2``. Gradients are
``grad_w = (pred - y) * x`` and ``grad_b = (pred - y)``, each a product
of (at most) two ciphertexts, so the whole training step is an
encrypted add/multiply pipeline the host can replay.

The load-bearing design choices:

- **Fixed-point arithmetic**: homomorphic ciphertexts hold integers, so
  every value is implicitly scaled by the trainer's ``scale`` S
  (``real = scaled / S``). Multiplying two S-scaled values yields an
  S²-scaled product, so every fixed-point multiply is followed by a
  truncation ``trunc(a*b / S)`` (toward zero) - exactly the truncation
  step real fixed-point ML pipelines (MPC/FHE) perform after each
  multiply. The simulation truncates the carried plaintext; real
  deployments implement this via their truncation protocol.
- **Learning rate**: ``train_step`` takes the *real* learning rate as a
  rational ``lr_num / lr_den`` (no divisibility constraint). The update
  is ``s_new = s - trunc(lr_num * g / lr_den)`` with the same
  truncation-toward-zero semantics.
- **Noise budget**: every encrypted add/multiply accrues noise exactly
  like ``fhe_interface`` (adds accumulate, multiplies compound;
  truncation itself is noise-free in the model). A ``train_step`` that
  would push any parameter past ``MAX_NOISE`` fail-closes with
  ``NoiseExceededError`` - the multiplicative-depth limit is the same
  one real leveled FHE hits.
- **Bootstrapping**: ``bootstrap(ct, seq)`` homomorphically refreshes a
  noisy ciphertext back to a low-noise equivalent (``BOOTSTRAP_NOISE``),
  mirroring real schemes where bootstrapping evaluates the decryption
  circuit under a bootstrapping key. Simulated here as a noise refresh;
  it is the honest, documented way to train past the noise budget.
- **Digest pins**: parameter vectors are pinned by ``sha256:`` digests
  over their canonical form, so a training run's inputs/outputs ride the
  audit path without carrying values.

Honest scope (read before relying on this):

- Simulated cryptography: plaintexts are carried in the records under an
  integrity digest so the learning algorithm and the noise model can be
  exercised. The process sees the plaintexts; this provides zero
  confidentiality and is NOT a security boundary.
- Linear regression only. Non-linear activations (sigmoid, ReLU,
  softmax) need polynomial approximations or encrypted comparison -
  neither is implemented here.
- Noise growth is the deliberate toy model from ``fhe_interface``;
  real schemes' growth is subtler.
- Deterministic: same seed, data, and op sequence always produce the
  same encrypted artifacts (caller seed; two deployments cannot
  silently share a key).
- Plaintext bound ``|v| < 2**63`` enforced fail-closed at eval time.

No wall-clock anywhere (caller-supplied int seqs). stdlib only
(``hashlib``, ``hmac``, ``dataclasses``, ``typing``).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Sequence, Tuple

#: Version pin for the interface described here.
HOMOMORPHIC_TRAINING_VERSION = "homomorphic-training.v1"

#: Schema pin stamped on encrypted records and audit events.
HOMOMORPHIC_TRAINING_SCHEMA = "northstar.homomorphic-training.v1"

#: Maximum accumulated noise a ciphertext may carry and still decrypt.
MAX_NOISE = 100

#: Noise added by one homomorphic addition, on top of operand noise.
ADD_NOISE = 1

#: Noise contributed by one homomorphic multiplication.
MUL_NOISE = 8

#: Noise left on a ciphertext after bootstrapping (a fresh refresh).
BOOTSTRAP_NOISE = 4

#: Plaintext bound: |value| must be < 2**63. Overflows fail closed.
PLAINTEXT_BOUND = 2**63

#: Fixed domain string mixed into every key and digest derivation.
_DOMAIN = b"northstar.homomorphic-training.v1"


class HomomorphicTrainingError(ValueError):
    """Raised for malformed homomorphic-training inputs (fail-closed)."""


class IntegrityError(HomomorphicTrainingError):
    """Raised when a ciphertext digest does not verify."""


class NoiseExceededError(HomomorphicTrainingError):
    """Raised when a ciphertext is too noisy to decrypt."""


class KeyMismatchError(HomomorphicTrainingError):
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
        raise HomomorphicTrainingError(f"{name}={value} exceeds plaintext bound 2**63")
    return value


def _derive(label: bytes, *parts: bytes) -> bytes:
    """Domain-separated deterministic derivation."""
    h = hashlib.sha256()
    h.update(_DOMAIN)
    h.update(b"|")
    h.update(label)
    for p in parts:
        h.update(b"|")
        h.update(p)
    return h.digest()


def _int_to_bytes(value: int) -> bytes:
    """Sign-aware fixed-width encoding (immune to the JCS >2**53 caveat)."""
    sign = b"\x01" if value < 0 else b"\x00"
    return sign + abs(value).to_bytes(8, "big")


def _trunc_div(a: int, b: int) -> int:
    """Integer division truncated toward zero (fixed-point truncation).

    This is the simulated truncation real fixed-point pipelines apply
    after every multiply; real deployments implement it via their
    truncation protocol rather than in the clear.
    """
    if b == 0:
        raise HomomorphicTrainingError("division by zero in truncation")
    q, r = divmod(abs(a), abs(b))
    return -q if (a < 0) != (b < 0) else q


def _digest_ct(key_id: bytes, value: int, noise: int, nonce: int) -> bytes:
    return _derive(
        b"ct", key_id, _int_to_bytes(value),
        _int_to_bytes(noise), _int_to_bytes(nonce),
    )


@dataclass(frozen=True)
class KeyPair:
    """Deterministic key pair derived from the caller seed."""

    key_id: str
    public_pin: str
    secret_pin: str
    schema: str = HOMOMORPHIC_TRAINING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != HOMOMORPHIC_TRAINING_SCHEMA:
            raise HomomorphicTrainingError("schema pin mismatch")
        if not self.key_id.startswith("key-"):
            raise HomomorphicTrainingError("bad key_id")


@dataclass(frozen=True)
class EncryptedValue:
    """One integer ciphertext with its noise level and integrity pin."""

    key_id: str
    value: int
    noise: int
    nonce: int
    digest: str
    schema: str = HOMOMORPHIC_TRAINING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != HOMOMORPHIC_TRAINING_SCHEMA:
            raise HomomorphicTrainingError("schema pin mismatch")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise HomomorphicTrainingError("bad digest pin")
        if self.noise < 0 or self.noise > MAX_NOISE:
            raise HomomorphicTrainingError("noise out of range")


@dataclass(frozen=True)
class EncryptedVector:
    """An encrypted parameter/feature vector: values under one key."""

    key_id: str
    values: Tuple[EncryptedValue, ...]
    digest: str
    schema: str = HOMOMORPHIC_TRAINING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != HOMOMORPHIC_TRAINING_SCHEMA:
            raise HomomorphicTrainingError("schema pin mismatch")
        if len(self.values) == 0:
            raise HomomorphicTrainingError("vector must be non-empty")
        if any(v.key_id != self.key_id for v in self.values):
            raise HomomorphicTrainingError("vector mixes keys")
        if not self.digest.startswith("sha256:"):
            raise HomomorphicTrainingError("bad digest pin")


@dataclass(frozen=True)
class TrainingStep:
    """Record of one encrypted SGD update."""

    step: int
    lr_num: int
    lr_den: int
    param_digest_before: str
    param_digest_after: str
    max_noise: int
    schema: str = HOMOMORPHIC_TRAINING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != HOMOMORPHIC_TRAINING_SCHEMA:
            raise HomomorphicTrainingError("schema pin mismatch")
        if self.step < 0:
            raise HomomorphicTrainingError("step must be non-negative")
        if not self.param_digest_after.startswith("sha256:"):
            raise HomomorphicTrainingError("bad digest pin")


def keygen(seed: bytes) -> KeyPair:
    """Derive a deterministic key pair from the caller seed."""
    _check_seed(seed)
    key_id = "key-" + _derive(b"keygen", seed)[:8].hex()
    public_pin = "sha256:" + _derive(b"pub", seed).hex()
    secret_pin = "sha256:" + _derive(b"sec", seed).hex()
    return KeyPair(key_id=key_id, public_pin=public_pin, secret_pin=secret_pin)


class HomomorphicTraining:
    """Encrypted linear-regression training session holder.

    ``seed`` owns the key material (deterministic, caller-supplied).
    ``n_features`` fixes the model shape. ``scale`` S is the fixed-point
    scale: real values equal scaled values divided by S.
    """

    def __init__(self, seed: bytes, n_features: int, scale: int = 1000) -> None:
        _check_seed(seed)
        if isinstance(n_features, bool) or not isinstance(n_features, int):
            raise TypeError("n_features must be an int")
        if n_features < 1 or n_features > 1024:
            raise HomomorphicTrainingError("n_features out of range")
        if isinstance(scale, bool) or not isinstance(scale, int):
            raise TypeError("scale must be an int")
        if scale < 1:
            raise HomomorphicTrainingError("scale must be positive")
        self._seed = seed
        self._n_features = n_features
        self._scale = scale
        self._keypair = keygen(seed)
        self._nonce = 0

    @property
    def key_id(self) -> str:
        return self._keypair.key_id

    @property
    def n_features(self) -> int:
        return self._n_features

    @property
    def scale(self) -> int:
        return self._scale

    # -- encryption primitives -------------------------------------------

    def _mint(self, value: int, noise: int, key_id: str | None = None) -> EncryptedValue:
        key_id = key_id or self._keypair.key_id
        _check_bound("value", value)
        if noise > MAX_NOISE:
            raise NoiseExceededError("noise exceeds budget")
        self._nonce += 1
        digest = "sha256:" + _digest_ct(
            key_id.encode(), value, noise, self._nonce
        ).hex()
        return EncryptedValue(
            key_id=key_id, value=value, noise=noise,
            nonce=self._nonce, digest=digest,
        )

    def _verify(self, ct: EncryptedValue) -> None:
        if not isinstance(ct, EncryptedValue):
            raise TypeError("expected EncryptedValue")
        if ct.key_id != self._keypair.key_id:
            raise KeyMismatchError("ciphertext is from another key")
        want = "sha256:" + _digest_ct(
            ct.key_id.encode(), ct.value, ct.noise, ct.nonce
        ).hex()
        if not hmac.compare_digest(want, ct.digest):
            raise IntegrityError("ciphertext digest mismatch")

    def _add(self, a: EncryptedValue, b: EncryptedValue) -> EncryptedValue:
        self._verify(a)
        self._verify(b)
        return self._mint(a.value + b.value, a.noise + b.noise + ADD_NOISE)

    def _sub(self, a: EncryptedValue, b: EncryptedValue) -> EncryptedValue:
        self._verify(a)
        self._verify(b)
        return self._mint(a.value - b.value, a.noise + b.noise + ADD_NOISE)

    def _mul(self, a: EncryptedValue, b: EncryptedValue) -> EncryptedValue:
        self._verify(a)
        self._verify(b)
        noise = (a.noise + 1) * (b.noise + 1) - 1 + MUL_NOISE
        return self._mint(a.value * b.value, noise)

    def _fpmul(self, a: EncryptedValue, b: EncryptedValue) -> EncryptedValue:
        """Fixed-point multiply of two S-scaled ciphertexts.

        Truncates the S^2-scaled product back to S-scaled
        (truncation toward zero). Charged one multiplication's noise;
        the truncation itself is noise-free in the model.
        """
        self._verify(a)
        self._verify(b)
        noise = (a.noise + 1) * (b.noise + 1) - 1 + MUL_NOISE
        return self._mint(_trunc_div(a.value * b.value, self._scale), noise)

    # -- public API ------------------------------------------------------

    def encrypt(self, value: int, seq: int) -> EncryptedValue:
        """Encrypt one integer (fresh ciphertext, noise 0)."""
        _check_seq(seq)
        return self._mint(_check_bound("value", _check_int("value", value)), 0)

    def encrypt_vector(self, values: Sequence[int], seq: int) -> EncryptedVector:
        """Encrypt a parameter/feature vector under this session's key."""
        _check_seq(seq)
        vals = tuple(values)
        if len(vals) == 0:
            raise HomomorphicTrainingError("vector must be non-empty")
        enc = tuple(self.encrypt(v, seq) for v in vals)
        digest = "sha256:" + _derive(
            b"vector", *[e.digest.encode() for e in enc]
        ).hex()
        return EncryptedVector(
            key_id=self._keypair.key_id, values=enc, digest=digest
        )

    def decrypt(self, ct: EncryptedValue) -> int:
        """Decrypt one ciphertext (fail-closed past the noise budget)."""
        self._verify(ct)
        if ct.noise > MAX_NOISE:
            raise NoiseExceededError("ciphertext too noisy to decrypt")
        return ct.value

    def decrypt_vector(self, vect: EncryptedVector) -> Tuple[int, ...]:
        """Decrypt a whole vector."""
        if not isinstance(vect, EncryptedVector):
            raise TypeError("expected EncryptedVector")
        if vect.key_id != self._keypair.key_id:
            raise KeyMismatchError("vector is from another key")
        return tuple(self.decrypt(v) for v in vect.values)

    def bootstrap(self, ct: EncryptedValue, seq: int) -> EncryptedValue:
        """Homomorphically refresh a noisy ciphertext (simulated).

        Returns an equivalent ciphertext at ``BOOTSTRAP_NOISE``.
        Honest scope: real bootstrapping evaluates the decryption
        circuit under a bootstrapping key and is the most expensive
        FHE op; here it is a noise refresh so multi-step training can
        proceed past the multiplicative-depth limit, like leveled FHE
        plus bootstrapping in real deployments.
        """
        _check_seq(seq)
        self._verify(ct)
        return self._mint(ct.value, BOOTSTRAP_NOISE)

    def bootstrap_vector(self, vect: EncryptedVector,
                         seq: int) -> EncryptedVector:
        """Refresh a whole encrypted vector."""
        if not isinstance(vect, EncryptedVector):
            raise TypeError("expected EncryptedVector")
        if vect.key_id != self._keypair.key_id:
            raise KeyMismatchError("vector is from another key")
        fresh = tuple(self.bootstrap(v, seq) for v in vect.values)
        digest = "sha256:" + _derive(
            b"vector", *[v.digest.encode() for v in fresh]
        ).hex()
        return EncryptedVector(
            key_id=self._keypair.key_id, values=fresh, digest=digest)

    def _check_vector(self, vect: EncryptedVector, expected_len: int,
                      name: str) -> None:
        if not isinstance(vect, EncryptedVector):
            raise TypeError(f"{name} must be an EncryptedVector")
        if vect.key_id != self._keypair.key_id:
            raise KeyMismatchError(f"{name} is from another key")
        if len(vect.values) != expected_len:
            raise HomomorphicTrainingError(
                f"{name} has {len(vect.values)} values, expected {expected_len}")

    def encrypted_forward(self, weights: EncryptedVector,
                          features: EncryptedVector, bias: EncryptedValue,
                          seq: int) -> EncryptedValue:
        """Homomorphic forward pass: ``pred = w . x + b``.

        The model weights, feature vector, and bias are all encrypted;
        the returned prediction is a ciphertext.
        """
        _check_seq(seq)
        self._check_vector(weights, self._n_features, "weights")
        self._check_vector(features, self._n_features, "features")
        self._verify(bias)
        acc = self._fpmul(weights.values[0], features.values[0])
        for w, x in zip(weights.values[1:], features.values[1:]):
            acc = self._add(acc, self._fpmul(w, x))
        return self._add(acc, bias)

    def encrypted_backward(self, pred: EncryptedValue, label: EncryptedValue,
                           features: EncryptedVector, seq: int
                           ) -> Tuple[EncryptedVector, EncryptedValue]:
        """Homomorphic backward pass for squared-error loss.

        ``grad_w = (pred - y) * x``, ``grad_b = (pred - y)``.
        Returns the encrypted gradient vector and the encrypted
        bias gradient.
        """
        _check_seq(seq)
        self._verify(pred)
        self._verify(label)
        self._check_vector(features, self._n_features, "features")
        err = self._sub(pred, label)
        grads = tuple(self._fpmul(err, x) for x in features.values)
        digest = "sha256:" + _derive(
            b"vector", *[g.digest.encode() for g in grads]
        ).hex()
        grad_vec = EncryptedVector(
            key_id=self._keypair.key_id, values=grads, digest=digest)
        return grad_vec, err

    def train_step(self, weights: EncryptedVector, bias: EncryptedValue,
                   grad_w: EncryptedVector, grad_b: EncryptedValue,
                   lr_num: int, lr_den: int, seq: int
                   ) -> Tuple[EncryptedVector, EncryptedValue, TrainingStep]:
        """One encrypted SGD step, entirely under encryption.

        ``params_new = params - lr * grad`` where ``lr`` is the *real*
        learning rate ``lr_num / lr_den`` (any positive denominator).
        The update is ``s_new = s - trunc(lr_num * g / lr_den)`` with
        truncation toward zero - the standard fixed-point truncation;
        real deployments implement it via their truncation protocol.
        """
        _check_seq(seq)
        self._check_vector(weights, self._n_features, "weights")
        self._check_vector(grad_w, self._n_features, "grad_w")
        self._verify(bias)
        self._verify(grad_b)
        lr_num = _check_int("lr_num", lr_num)
        lr_den = _check_int("lr_den", lr_den)
        if lr_num < 0:
            raise HomomorphicTrainingError("lr_num must be non-negative")
        if lr_den < 1:
            raise HomomorphicTrainingError("lr_den must be positive")

        before = "sha256:" + _derive(
            b"vector", *[v.digest.encode() for v in weights.values]
        ).hex()
        lr_ct = self._mint(lr_num, 0)

        def _scaled_step(param: EncryptedValue,
                         grad: EncryptedValue) -> EncryptedValue:
            prod = self._mul(lr_ct, grad)
            delta = self._mint(_trunc_div(prod.value, lr_den), prod.noise)
            return self._sub(param, delta)

        new_w = [_scaled_step(w, g)
                 for w, g in zip(weights.values, grad_w.values)]
        new_b = _scaled_step(bias, grad_b)

        digest_after = "sha256:" + _derive(
            b"vector", *[v.digest.encode() for v in new_w]
        ).hex()
        max_noise = max(
            [v.noise for v in new_w] + [new_b.noise])
        step_rec = TrainingStep(
            step=seq,
            lr_num=lr_num,
            lr_den=lr_den,
            param_digest_before=before,
            param_digest_after=digest_after,
            max_noise=max_noise,
        )
        new_vec = EncryptedVector(
            key_id=self._keypair.key_id,
            values=tuple(new_w),
            digest=digest_after,
        )
        return new_vec, new_b, step_rec


def homomorphic_training_audit_event(kind: str, seq: int, *,
                                     detail: str = "") -> dict:
    """Shape a homomorphic-training lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("keygen", "encrypt", "forward", "backward", "train-step",
             "bootstrap", "decrypt", "integrity-failed", "noise-exceeded")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, str):
        raise TypeError("detail must be str")
    return {
        "schema": "audit.ndjson/1",
        "kind": f"homomorphic-training.{kind}",
        "module": HOMOMORPHIC_TRAINING_SCHEMA,
        "version": HOMOMORPHIC_TRAINING_VERSION,
        "seq": seq,
        "detail": detail,
    }


def main() -> None:
    """Self-check: train a tiny encrypted linear model end to end."""
    t = HomomorphicTraining(b"self-check-seed", 2, scale=100)
    w = t.encrypt_vector([0, 0], 0)
    b = t.encrypt(0, 0)
    # y = 3*x1 + 5*x2 + 2, scaled by 100 (labels are scaled too)
    data = [([100, 200], 3 * 100 + 5 * 200 + 200),
            ([300, 100], 3 * 300 + 5 * 100 + 200)]
    for i, (xs, y) in enumerate(data):
        x_ct = t.encrypt_vector(xs, i)
        y_ct = t.encrypt(y, i)
        pred = t.encrypted_forward(w, x_ct, b, i)
        grad_w, grad_b = t.encrypted_backward(pred, y_ct, x_ct, i)
        w, b, step = t.train_step(w, b, grad_w, grad_b, 1, 100, i)
        w = t.bootstrap_vector(w, i)
        b = t.bootstrap(b, i)
    wv = t.decrypt_vector(w)
    bv = t.decrypt(b)
    assert len(wv) == 2
    assert isinstance(step, TrainingStep)
    print("homomorphic-training OK: 2 features, 2 steps, "
          f"weights={wv} bias={bv} max_noise={step.max_noise}")


if __name__ == "__main__":
    main()
