"""Private inference interface (API + bookkeeping, NOT real crypto).

Private inference lets a client obtain a model's prediction on *its* data
without exposing the raw input to the network and without the server
exposing the model weights to the client. This module pins that API shape
as a deterministic, network-free state machine:

* the server registers a model once; ``model_commitment()`` returns a
  digest-pinned, auditable handle (model id + architecture + parameter
  digest) so clients can verify *which* model they are querying;
* the client SDK seals its feature vector into a ``SealedInput`` bound to
  the model's commitment digest;
* ``predict()`` verifies the seal, checks the embedded commitment still
  matches the *currently registered* model (a swapped model fails closed
  instead of silently answering), runs the pinned architecture, and
  returns a frozen ``Prediction``.

Supported architectures (exact, deterministic):

* ``logistic-regression.v1`` — binary classifier: ``sigmoid(w.x + b)``.
* ``tiny-mlp.v1`` — one hidden layer with ReLU and a softmax head.

Honest scope, stated plainly:

* This is a **simulation of the interface**, the same way
  ``consensus_interface`` simulates the Raft/Paxos message half without a
  network. The "seal" is a deterministic SHA-256 counter-mode stream
  cipher with an HMAC integrity tag — a stand-in for real encrypted
  inference (homomorphic encryption, 2PC, TEE). There is no IND-CCA2
  here, and determinism (same inputs, same bytes) is deliberate for
  audit replay, not a confidentiality claim.
* Inference runs on the *unsealed* features inside the server process:
  the module is the server half, so the host process necessarily sees the
  plaintext. Do **not** treat this as a confidentiality boundary.
* Weights are IEEE-754 doubles encoded with ``struct`` big-endian packing,
  never JSON, so the >2^53 ``canonical_json`` float-loss caveat (see
  ``secure_aggregation``) does not apply here.
* ``predict()`` proves "this pinned model produced this prediction on
  this sealed input", never "the model is correct or fair".

Everything here is offline and deterministic. No network, no clock reads,
no randomness. ``hashlib``, ``hmac``, ``math``, ``struct``,
``dataclasses`` only.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import struct
from dataclasses import dataclass
from typing import Mapping, Sequence

#: Module version.
SECURE_INFERENCE_VERSION = "secure-inference.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.secure-inference.v1"

#: Digest prefix for pins.
_DIGEST_PREFIX = "sha256:"

#: Domain separator for seal key/tag derivation.
_DOMAIN = b"northstar-secure-inference.v1"

#: Integrity tag length in bytes.
_TAG_LEN = 16

#: Seal nonce length in bytes.
_NONCE_LEN = 8

#: Wire format magic.
_MAGIC = b"NSI1"

#: Supported model architectures.
ARCHITECTURES = (
    "logistic-regression.v1",
    "tiny-mlp.v1",
)

_AUDIT_KINDS = (
    "model-registered",
    "input-sealed",
    "predicted",
    "predict-refused",
)


class SecureInferenceError(Exception):
    """Malformed input or broken invariant (programming error)."""


class SealedInputError(SecureInferenceError):
    """A sealed input failed integrity or binding checks."""


class StaleModelError(SecureInferenceError):
    """The sealed input binds a model commitment that is no longer current."""


class UnknownModelError(SecureInferenceError):
    """The named model is not registered."""


class ModelRegistrationError(SecureInferenceError):
    """The model registration itself was rejected."""


def _check_seq(seq: object, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SecureInferenceError(f"{what} must be a non-negative int")
    return seq


def _check_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise SecureInferenceError(f"{what} must be a non-empty str")
    return value


def _check_arch(architecture: object) -> str:
    if not isinstance(architecture, str) or architecture not in ARCHITECTURES:
        raise SecureInferenceError(f"architecture must be one of {ARCHITECTURES}")
    return architecture


def _check_finite(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SecureInferenceError(f"{what} must be a finite number")
    f = float(value)
    if not math.isfinite(f):
        raise SecureInferenceError(f"{what} must be finite (no NaN/inf)")
    return f


def _check_digest(value: object, what: str = "digest") -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
    ):
        raise SecureInferenceError(f"{what} must be a '{_DIGEST_PREFIX}<64 hex>' pin")
    return value


def _digest_bytes(body: bytes) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(body).hexdigest()


def _pack_floats(values: Sequence[float]) -> bytes:
    """Deterministic big-endian IEEE-754 encoding of a float vector."""
    return struct.pack("!" + "d" * len(values), *[float(v) for v in values])


def _unpack_floats(blob: bytes) -> tuple:
    if len(blob) % 8 != 0:
        raise SealedInputError("feature payload length is not a multiple of 8")
    n = len(blob) // 8
    return struct.unpack("!" + "d" * n, blob)


@dataclass(frozen=True)
class ModelCommitment:
    """Public, digest-pinned handle for a registered model.

    Carries no raw weights — clients verify identity by digest only.
    """

    model_id: str
    architecture: str
    params_digest: str
    input_dim: int
    n_classes: int
    registered_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_id(self.model_id, "model_id")
        _check_arch(self.architecture)
        _check_digest(self.params_digest, "params_digest")
        if isinstance(self.input_dim, bool) or not isinstance(self.input_dim, int) or self.input_dim < 1:
            raise SecureInferenceError("input_dim must be a positive int")
        if isinstance(self.n_classes, bool) or not isinstance(self.n_classes, int) or self.n_classes < 2:
            raise SecureInferenceError("n_classes must be an int >= 2")
        _check_seq(self.registered_seq, "registered_seq")
        if self.schema != SCHEMA_PIN:
            raise SecureInferenceError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "architecture": self.architecture,
            "params_digest": self.params_digest,
            "input_dim": self.input_dim,
            "n_classes": self.n_classes,
            "registered_seq": self.registered_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class SealedInput:
    """Client-sealed feature vector, bound to a model commitment digest."""

    model_id: str
    model_digest: str
    features_ciphertext: bytes
    nonce: bytes
    tag: bytes
    sealed_seq: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_id(self.model_id, "model_id")
        _check_digest(self.model_digest, "model_digest")
        if not isinstance(self.features_ciphertext, bytes) or not self.features_ciphertext:
            raise SecureInferenceError("features_ciphertext must be non-empty bytes")
        if not isinstance(self.nonce, bytes) or len(self.nonce) != _NONCE_LEN:
            raise SecureInferenceError(f"nonce must be {_NONCE_LEN} bytes")
        if not isinstance(self.tag, bytes) or len(self.tag) != _TAG_LEN:
            raise SecureInferenceError(f"tag must be {_TAG_LEN} bytes")
        _check_seq(self.sealed_seq, "sealed_seq")
        if self.schema != SCHEMA_PIN:
            raise SecureInferenceError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "features_ciphertext": self.features_ciphertext.hex(),
            "nonce": self.nonce.hex(),
            "tag": self.tag.hex(),
            "sealed_seq": self.sealed_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Prediction:
    """Frozen prediction record for one sealed input."""

    model_id: str
    model_digest: str
    predicted_class: int
    scores: tuple
    inference_seq: int
    input_sealed_seq: int
    result_digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_id(self.model_id, "model_id")
        _check_digest(self.model_digest, "model_digest")
        if isinstance(self.predicted_class, bool) or not isinstance(self.predicted_class, int) or self.predicted_class < 0:
            raise SecureInferenceError("predicted_class must be a non-negative int")
        if not isinstance(self.scores, tuple) or len(self.scores) < 2:
            raise SecureInferenceError("scores must be a tuple with >= 2 entries")
        for s in self.scores:
            if isinstance(s, bool) or not isinstance(s, float) or not math.isfinite(s):
                raise SecureInferenceError("scores must be finite floats")
        _check_seq(self.inference_seq, "inference_seq")
        _check_seq(self.input_sealed_seq, "input_sealed_seq")
        _check_digest(self.result_digest, "result_digest")
        if self.schema != SCHEMA_PIN:
            raise SecureInferenceError("schema pin mismatch")
        if not 0 <= self.predicted_class < len(self.scores):
            raise SecureInferenceError("predicted_class out of range for scores")

    def as_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "predicted_class": self.predicted_class,
            "scores": list(self.scores),
            "inference_seq": self.inference_seq,
            "input_sealed_seq": self.input_sealed_seq,
            "result_digest": self.result_digest,
            "schema": self.schema,
        }


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


def _softmax(logits: Sequence[float]) -> tuple:
    m = max(logits)
    exps = [math.exp(v - m) for v in logits]
    total = sum(exps)
    return tuple(e / total for e in exps)


class SecureInference:
    """Server half of private inference.

    Registers models (weights stay server-side), seals/unseals client
    inputs with a deterministic session secret, and refuses to predict on
    tampered or stale sealed inputs instead of guessing.
    """

    def __init__(self, session_secret: bytes) -> None:
        if not isinstance(session_secret, bytes) or len(session_secret) < 16:
            raise SecureInferenceError("session_secret must be bytes of length >= 16")
        self._secret = session_secret
        self._models: dict = {}
        self._seal_counter = 0

    # -- model registration -------------------------------------------------

    def register_model(
        self,
        model_id: str,
        architecture: object,
        weights: Sequence,
        seq: int,
    ) -> ModelCommitment:
        """Register a model; returns its digest-pinned commitment."""
        model_id = _check_id(model_id, "model_id")
        architecture = _check_arch(architecture)
        seq = _check_seq(seq, "seq")
        if model_id in self._models:
            raise ModelRegistrationError(f"model_id already registered: {model_id}")
        flat = self._validate_weights(architecture, weights)
        digest = _digest_bytes(_pack_floats(flat))
        spec = self._model_spec(architecture, flat)
        commitment = ModelCommitment(
            model_id=model_id,
            architecture=architecture,
            params_digest=digest,
            input_dim=spec["input_dim"],
            n_classes=spec["n_classes"],
            registered_seq=seq,
        )
        self._models[model_id] = {
            "commitment": commitment,
            "weights": flat,
            "arch": architecture,
        }
        return commitment

    def _validate_weights(self, architecture: str, weights: object) -> tuple:
        if not isinstance(weights, (list, tuple)) or not weights:
            raise ModelRegistrationError("weights must be a non-empty list/tuple")
        flat: list = []
        for i, w in enumerate(weights):
            flat.append(_check_finite(w, f"weights[{i}]"))
        flat_t = tuple(flat)
        if architecture == "logistic-regression.v1":
            if len(flat_t) < 2:
                raise ModelRegistrationError(
                    "logistic-regression.v1 needs >= 2 weights (n features + bias)"
                )
        else:  # tiny-mlp.v1: (W1, b1, W2, b2, dims...)
            if len(flat_t) < 4:
                raise ModelRegistrationError(
                    "tiny-mlp.v1 needs (W1..., b1..., W2..., b2...) plus dims"
                )
        return flat_t

    def _model_spec(self, architecture: str, weights: tuple) -> dict:
        if architecture == "logistic-regression.v1":
            return {"input_dim": len(weights) - 1, "n_classes": 2}
        # tiny-mlp.v1 layout: first two floats are (hidden, classes) dims,
        # then W1 (hidden*input_dim), b1 (hidden), W2 (classes*hidden), b2.
        hidden = int(weights[0])
        classes = int(weights[1])
        if hidden < 1 or classes < 2:
            raise ModelRegistrationError("tiny-mlp.v1 needs hidden >= 1, classes >= 2")
        if not float(weights[0]).is_integer() or not float(weights[1]).is_integer():
            raise ModelRegistrationError("tiny-mlp.v1 dim entries must be integral")
        rest = len(weights) - 2
        # Solve input_dim from: hidden*input_dim + hidden + classes*hidden + classes == rest
        fixed = hidden + classes * hidden + classes
        remaining = rest - fixed
        if remaining <= 0 or remaining % hidden != 0:
            raise ModelRegistrationError(
                "tiny-mlp.v1 weight count does not match (hidden, classes) dims"
            )
        input_dim = remaining // hidden
        return {"input_dim": input_dim, "n_classes": classes, "hidden": hidden}

    def model_commitment(self, model_id: str) -> ModelCommitment:
        model_id = _check_id(model_id, "model_id")
        entry = self._models.get(model_id)
        if entry is None:
            raise UnknownModelError(f"unknown model_id: {model_id}")
        return entry["commitment"]

    def registered_models(self) -> tuple:
        return tuple(sorted(self._models))

    # -- sealing ------------------------------------------------------------

    def _seal_key(self, model_id: str, nonce: bytes) -> bytes:
        return hashlib.sha256(
            _DOMAIN + b"|seal|" + model_id.encode("utf-8") + b"|" + nonce
        ).digest()

    def _stream_xor(self, key: bytes, data: bytes) -> bytes:
        out = bytearray(len(data))
        counter = 0
        pos = 0
        while pos < len(data):
            block = hashlib.sha256(key + struct.pack("!Q", counter)).digest()
            chunk = block[: min(32, len(data) - pos)]
            out[pos : pos + len(chunk)] = bytes(
                b ^ c for b, c in zip(data[pos : pos + len(chunk)], chunk)
            )
            pos += len(chunk)
            counter += 1
        return bytes(out)

    def _tag(self, model_id: str, nonce: bytes, ciphertext: bytes) -> bytes:
        mac_key = hashlib.sha256(_DOMAIN + b"|tag|" + self._secret).digest()
        return hmac.new(
            mac_key, model_id.encode("utf-8") + b"|" + nonce + b"|" + ciphertext,
            hashlib.sha256,
        ).digest()[:_TAG_LEN]

    def seal_input(self, model_id: str, features: Sequence, seq: int) -> SealedInput:
        """Seal a client feature vector to a registered model."""
        entry = self._entry(model_id)
        seq = _check_seq(seq, "seq")
        if not isinstance(features, (list, tuple)) or not features:
            raise SecureInferenceError("features must be a non-empty list/tuple")
        vals = tuple(_check_finite(v, f"features[{i}]") for i, v in enumerate(features))
        if len(vals) != entry["commitment"].input_dim:
            raise SecureInferenceError(
                f"feature dim {len(vals)} != model input_dim "
                f"{entry['commitment'].input_dim}"
            )
        plaintext = _pack_floats(vals)
        nonce = hashlib.sha256(
            _DOMAIN + b"|nonce|" + model_id.encode("utf-8")
            + struct.pack("!Q", self._seal_counter) + struct.pack("!Q", seq)
        ).digest()[:_NONCE_LEN]
        self._seal_counter += 1
        ciphertext = self._stream_xor(self._seal_key(model_id, nonce), plaintext)
        tag = self._tag(model_id, nonce, ciphertext)
        return SealedInput(
            model_id=model_id,
            model_digest=entry["commitment"].params_digest,
            features_ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            sealed_seq=seq,
        )

    def _entry(self, model_id: str) -> dict:
        model_id = _check_id(model_id, "model_id")
        entry = self._models.get(model_id)
        if entry is None:
            raise UnknownModelError(f"unknown model_id: {model_id}")
        return entry

    def _open_input(self, sealed: SealedInput) -> tuple:
        if not isinstance(sealed, SealedInput):
            raise SealedInputError("sealed must be a SealedInput")
        entry = self._entry(sealed.model_id)
        expected_tag = self._tag(sealed.model_id, sealed.nonce, sealed.features_ciphertext)
        if not hmac.compare_digest(expected_tag, sealed.tag):
            raise SealedInputError("sealed input integrity tag mismatch")
        if sealed.model_digest != entry["commitment"].params_digest:
            raise StaleModelError(
                "sealed input binds a stale model commitment; refusing to predict"
            )
        plaintext = self._stream_xor(
            self._seal_key(sealed.model_id, sealed.nonce), sealed.features_ciphertext
        )
        return entry, _unpack_floats(plaintext)

    # -- prediction ---------------------------------------------------------

    def predict(self, sealed: SealedInput, seq: int) -> Prediction:
        """Run the pinned model on a sealed input; fail-closed on any check."""
        seq = _check_seq(seq, "seq")
        entry, features = self._open_input(sealed)
        arch = entry["arch"]
        weights = entry["weights"]
        if arch == "logistic-regression.v1":
            scores, predicted = self._predict_logistic(weights, features)
        else:
            scores, predicted = self._predict_mlp(weights, features)
        result_digest = _digest_bytes(
            (sealed.model_id + "|" + sealed.model_digest + "|"
             + ",".join(repr(s) for s in scores)).encode("utf-8")
        )
        return Prediction(
            model_id=sealed.model_id,
            model_digest=sealed.model_digest,
            predicted_class=predicted,
            scores=tuple(float(s) for s in scores),
            inference_seq=seq,
            input_sealed_seq=sealed.sealed_seq,
            result_digest=result_digest,
        )

    @staticmethod
    def _predict_logistic(weights: tuple, features: tuple) -> tuple:
        w, b = weights[:-1], weights[-1]
        z = sum(wi * xi for wi, xi in zip(w, features)) + b
        p1 = _sigmoid(z)
        scores = (1.0 - p1, p1)
        return scores, (0 if p1 < 0.5 else 1)

    def _predict_mlp(self, weights: tuple, features: tuple) -> tuple:
        spec = self._model_spec("tiny-mlp.v1", weights)
        hidden = spec["hidden"]
        classes = spec["n_classes"]
        input_dim = spec["input_dim"]
        body = weights[2:]
        w1 = body[: hidden * input_dim]
        b1 = body[hidden * input_dim : hidden * input_dim + hidden]
        rest = body[hidden * input_dim + hidden :]
        w2 = rest[: classes * hidden]
        b2 = rest[classes * hidden : classes * hidden + classes]
        # Hidden layer with ReLU.
        h = []
        for j in range(hidden):
            z = sum(w1[j * input_dim + i] * features[i] for i in range(input_dim)) + b1[j]
            h.append(z if z > 0.0 else 0.0)
        logits = [
            sum(w2[c * hidden + j] * h[j] for j in range(hidden)) + b2[c]
            for c in range(classes)
        ]
        scores = _softmax(logits)
        predicted = max(range(classes), key=lambda c: scores[c])
        return scores, predicted


def secure_inference_audit_event(kind: str, record: Mapping, seq: int) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a secure-inference event."""
    if kind not in _AUDIT_KINDS:
        raise SecureInferenceError(f"kind must be one of {_AUDIT_KINDS}")
    if not isinstance(record, Mapping):
        raise SecureInferenceError("record must be a mapping")
    seq = _check_seq(seq, "audit seq")
    return {
        "schema": SCHEMA_PIN,
        "kind": f"secure-inference.{kind}",
        "record": dict(record),
        "audit_seq": seq,
    }


def main() -> None:
    si = SecureInference(b"northstar-test-session-secret-16")

    # Logistic regression: 2 features + bias; weights (0.5, -0.25, 0.1).
    log_commit = si.register_model("logreg-1", "logistic-regression.v1", (0.5, -0.25, 0.1), 0)
    assert log_commit.input_dim == 2 and log_commit.n_classes == 2
    assert log_commit.params_digest.startswith("sha256:")

    sealed = si.seal_input("logreg-1", (1.0, 2.0), 1)
    pred = si.predict(sealed, 2)
    expected_z = 0.5 * 1.0 + -0.25 * 2.0 + 0.1
    expected_p1 = _sigmoid(expected_z)
    assert abs(pred.scores[1] - expected_p1) < 1e-12, pred.scores
    assert pred.predicted_class == (0 if expected_p1 < 0.5 else 1)
    assert pred.model_digest == log_commit.params_digest

    # Tampered sealed input fails closed.
    tampered = SealedInput(
        model_id=sealed.model_id,
        model_digest=sealed.model_digest,
        features_ciphertext=bytes([sealed.features_ciphertext[0] ^ 0xFF])
        + sealed.features_ciphertext[1:],
        nonce=sealed.nonce,
        tag=sealed.tag,
        sealed_seq=sealed.sealed_seq,
    )
    try:
        si.predict(tampered, 3)
    except SealedInputError:
        pass
    else:
        raise AssertionError("tampered seal must be refused")

    # Stale model binding fails closed.
    stale = SealedInput(
        model_id=sealed.model_id,
        model_digest="sha256:" + "00" * 32,
        features_ciphertext=sealed.features_ciphertext,
        nonce=sealed.nonce,
        tag=si._tag(sealed.model_id, sealed.nonce, sealed.features_ciphertext),
        sealed_seq=sealed.sealed_seq,
    )
    try:
        si.predict(stale, 4)
    except StaleModelError:
        pass
    else:
        raise AssertionError("stale model binding must be refused")

    # Tiny MLP: dims (hidden=2, classes=2), weights sized to input_dim=1.
    # Layout: (2.0, 2.0) dims, W1(2), b1(2), W2(4), b2(2).
    mlp_weights = (2.0, 2.0, 1.0, -1.0, 0.5, -0.5, 1.0, 0.0, 0.0, 1.0, 0.1, -0.1)
    mlp_commit = si.register_model("mlp-1", "tiny-mlp.v1", mlp_weights, 5)
    assert mlp_commit.input_dim == 1 and mlp_commit.n_classes == 2
    sealed_mlp = si.seal_input("mlp-1", (0.75,), 6)
    pred_mlp = si.predict(sealed_mlp, 7)
    assert abs(sum(pred_mlp.scores) - 1.0) < 1e-12
    assert pred_mlp.predicted_class in (0, 1)
    assert pred_mlp.result_digest.startswith("sha256:")

    # Seal is deterministic for same (model, counter, seq) — replay-safe.
    si2 = SecureInference(b"northstar-test-session-secret-16")
    si2.register_model("logreg-1", "logistic-regression.v1", (0.5, -0.25, 0.1), 0)
    sealed2 = si2.seal_input("logreg-1", (1.0, 2.0), 1)
    assert sealed2.features_ciphertext == sealed.features_ciphertext
    assert sealed2.tag == sealed.tag

    print("secure-inference OK: register, seal, predict, tamper/stale refusal")


if __name__ == "__main__":
    main()
