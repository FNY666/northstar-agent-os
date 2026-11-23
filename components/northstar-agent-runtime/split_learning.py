"""Split learning interface (SplitNN, Gupta & Raskar 2018), simulated.

Research motivation: *split learning* trains a neural network split
across parties at a "cut layer". The client holds the first ``k``
layers and computes forward up to the cut, sending the intermediate
"**smashed data**" (activations) to the server; the server finishes the
forward pass, computes the loss, and back-propagates only as far as the
cut, returning the gradient at the cut to the client. Neither side ever
sees the other's raw data (the client never shares inputs, the server
never shares labels or its weights).

This module models the split-learning *protocol and state machine*
with fully simulated math (a deterministic toy MLP):

- ``SplitLearning`` owns the full stack of layers and a cut index.
  ``forward`` runs client layers, pins the smashed data, runs server
  layers, and returns a frozen ``ForwardPass``.
- ``backward`` takes the loss gradient at the output, runs server-side
  backprop down to the cut, and returns the gradient w.r.t. the smashed
  data; ``apply_client_gradients`` finishes the client-side pass.
- ``cut_layer`` exposes the current split point; ``move_cut`` re-splits
  the network at a different layer.

Honest scope:

- **Simulated math.** The "network" is a tiny deterministic MLP with
  ReLU activations and toy scalar math -- not a real gradient library.
  Gradients are structurally sound (chain rule through the recorded
  layers) but this is not a training framework.
- **No privacy.** The server sees the smashed data, which can leak
  information about client inputs (model-inversion attacks are real).
  No differential privacy, no homomorphic encryption: this module pins
  the *protocol shape* (who sends what, when), not a privacy guarantee.
  Pair with ``fhe_interface`` or ``dp_accountant`` for real protections.
- **No network.** This is single-host protocol bookkeeping: the host
  owns the transport, ordering, and both sides' honesty.
- ``backward`` returns the gradient *at the cut*, not the client's raw
  data -- but smashed-data leakage means this is protocol plumbing, not
  a confidentiality claim.

Public API:

- ``SplitLearning(n_layers, dims, cut, seed=b"")`` -- network + split.
- ``forward(inputs, seq)`` -- client pass to cut, server pass to
  output; returns frozen ``ForwardPass``.
- ``backward(loss_grad, seq)`` -- server-side backprop down to the cut;
  returns frozen ``BackwardPass`` with the cut gradient.
- ``apply_client_gradients(cut_grad, seq)`` -- finishes client-side
  backprop using the cached forward pass.
- ``move_cut(new_cut, seq)`` -- re-splits the network.
- ``split_learning_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records; kinds ``"split-created"`` / ``"forwarded"`` /
  ``"backwarded"`` / ``"client-updated"`` / ``"cut-moved"`` /
  ``"rejected"``.
- ``SplitLearningError``.

Version pin: ``split-learning.v1`` / schema pin
``northstar.split-learning.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

#: Module version.
SPLIT_LEARNING_VERSION = "split-learning.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.split-learning.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {
        "split-created",
        "forwarded",
        "backwarded",
        "client-updated",
        "cut-moved",
        "rejected",
    }
)

#: Domain separator for every hash in this module.
_DOMAIN = b"northstar.split-learning.v1\x00"

#: Bound on vector/matrix sizes (fail-closed guardrail).
_MAX_DIM = 1024


class SplitLearningError(Exception):
    """Base error for split-learning failures."""


def _reject_bool(value: object, name: str) -> None:
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be bool")


def _check_dim(value: object, name: str) -> int:
    _reject_bool(value, name)
    if not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value <= 0 or value > _MAX_DIM:
        raise ValueError(f"{name} must be in [1, {_MAX_DIM}]")
    return value


def _check_seq(seq: object) -> int:
    _reject_bool(seq, "seq")
    if not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_vector(vec: object, dim: int, name: str) -> List[float]:
    if not isinstance(vec, (list, tuple)):
        raise TypeError(f"{name} must be a list/tuple of numbers")
    if len(vec) != dim:
        raise ValueError(f"{name} must have length {dim}, got {len(vec)}")
    out: List[float] = []
    for v in vec:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError(f"{name} entries must be numbers")
        if not math.isfinite(v):
            raise ValueError(f"{name} entries must be finite")
        out.append(float(v))
    return out


def _pin_vector(vec: Sequence[float]) -> str:
    body = ",".join(repr(v) for v in vec).encode("utf-8")
    return "sha256:" + hashlib.sha256(_DOMAIN + b"vec\x00" + body).hexdigest()


def _kdf(label: bytes, length: int) -> List[float]:
    """Deterministic pseudo-random weights in [-1, 1]."""
    out: List[float] = []
    counter = 0
    while len(out) < length:
        digest = hashlib.sha256(
            _DOMAIN + b"weight\x00" + label + counter.to_bytes(4, "big")
        ).digest()
        for b in digest:
            out.append((b / 255.0) * 2.0 - 1.0)
        counter += 1
    return out[:length]


def _matvec(matrix: List[List[float]], vec: List[float]) -> List[float]:
    return [sum(row[j] * vec[j] for j in range(len(vec))) for row in matrix]


def _relu(vec: List[float]) -> List[float]:
    return [v if v > 0.0 else 0.0 for v in vec]


@dataclass(frozen=True)
class SmashedData:
    """Frozen activation at the cut layer (client -> server message)."""

    version: str
    schema: str
    cut: int
    activation: Tuple[float, ...]
    activation_pin: str
    seq: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "schema": self.schema,
            "cut": self.cut,
            "activation": list(self.activation),
            "activation_pin": self.activation_pin,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ForwardPass:
    """Frozen forward-pass record."""

    version: str
    schema: str
    cut: int
    input_pin: str
    smashed_pin: str
    output: Tuple[float, ...]
    output_pin: str
    seq: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "schema": self.schema,
            "cut": self.cut,
            "input_pin": self.input_pin,
            "smashed_pin": self.smashed_pin,
            "output": list(self.output),
            "output_pin": self.output_pin,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class BackwardPass:
    """Frozen server-side backward-pass record (cut gradient message)."""

    version: str
    schema: str
    cut: int
    cut_gradient: Tuple[float, ...]
    cut_gradient_pin: str
    loss_gradient_pin: str
    seq: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "schema": self.schema,
            "cut": self.cut,
            "cut_gradient": list(self.cut_gradient),
            "cut_gradient_pin": self.cut_gradient_pin,
            "loss_gradient_pin": self.loss_gradient_pin,
            "seq": self.seq,
        }


def split_learning_audit_event(
    kind: str,
    seq: int,
    smashed_pin: Optional[str] = None,
    params_digest: Optional[str] = None,
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for this module."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    record: Dict[str, object] = {
        "format": AUDIT_FORMAT,
        "module": SPLIT_LEARNING_VERSION,
        "schema": SCHEMA_PIN,
        "kind": f"split-learning-{kind}",
        "seq": seq,
    }
    if smashed_pin is not None:
        record["smashed_pin"] = smashed_pin
    if params_digest is not None:
        record["params_digest"] = params_digest
    return record


class SplitLearning:
    """Split neural network with a configurable cut layer (simulated)."""

    def __init__(
        self,
        n_layers: int,
        dims: Sequence[int],
        cut: int,
        seed: bytes = b"",
    ) -> None:
        _reject_bool(n_layers, "n_layers")
        if not isinstance(n_layers, int) or n_layers < 2:
            raise SplitLearningError("n_layers must be an int >= 2")
        if not isinstance(dims, (list, tuple)) or len(dims) != n_layers + 1:
            raise SplitLearningError(
                "dims must be a list of n_layers + 1 dimensions"
            )
        dims = [_check_dim(d, f"dims[{i}]") for i, d in enumerate(dims)]
        _reject_bool(cut, "cut")
        if not isinstance(cut, int) or cut < 1 or cut >= n_layers:
            raise SplitLearningError(
                f"cut must be in [1, {n_layers - 1}] (never before the "
                "first or after the last layer)"
            )
        if not isinstance(seed, bytes):
            raise TypeError("seed must be bytes")
        self._n_layers = n_layers
        self._dims = list(dims)
        self._cut = cut
        self._seed = bytes(seed)
        self._weights: List[List[List[float]]] = []
        self._biases: List[List[float]] = []
        self._rebuild_weights()
        self._last_forward: Optional[ForwardPass] = None
        self._last_activations: Optional[List[List[float]]] = None

    def _rebuild_weights(self) -> None:
        self._weights = []
        self._biases = []
        for i in range(self._n_layers):
            rows, cols = self._dims[i + 1], self._dims[i]
            label = self._seed + i.to_bytes(4, "big")
            flat = _kdf(label, rows * cols)
            matrix = [flat[r * cols : (r + 1) * cols] for r in range(rows)]
            self._weights.append(matrix)
            self._biases.append(
                _kdf(self._seed + b"bias" + i.to_bytes(4, "big"), rows)
            )

    # ------------------------------------------------------------------
    # Introspection.
    # ------------------------------------------------------------------

    @property
    def cut_layer(self) -> int:
        """Index of the layer after which the network is cut."""
        return self._cut

    @property
    def n_layers(self) -> int:
        return self._n_layers

    def client_layer_count(self) -> int:
        """Number of layers held by the client (0..cut)."""
        return self._cut

    def server_layer_count(self) -> int:
        """Number of layers held by the server (cut..n)."""
        return self._n_layers - self._cut

    def weights_digest(self) -> str:
        """Pin the full weight stack (for audit, never raw weights)."""
        body = b""
        for matrix in self._weights:
            for row in matrix:
                body += ",".join(repr(v) for v in row).encode("utf-8") + b";"
        return "sha256:" + hashlib.sha256(
            _DOMAIN + b"weights\x00" + body
        ).hexdigest()

    # ------------------------------------------------------------------
    # Protocol.
    # ------------------------------------------------------------------

    def forward(self, inputs: Sequence[float], seq: int) -> ForwardPass:
        """Run client layers to the cut, then server layers to output."""
        _check_seq(seq)
        vec = _check_vector(inputs, self._dims[0], "inputs")
        activations: List[List[float]] = [vec]
        for i in range(self._n_layers):
            pre = _matvec(self._weights[i], activations[-1])
            pre = [pre[j] + self._biases[i][j] for j in range(len(pre))]
            activations.append(_relu(pre) if i < self._n_layers - 1 else pre)
        smashed = activations[self._cut]
        output = activations[-1]
        record = ForwardPass(
            version=SPLIT_LEARNING_VERSION,
            schema=SCHEMA_PIN,
            cut=self._cut,
            input_pin=_pin_vector(vec),
            smashed_pin=_pin_vector(smashed),
            output=tuple(output),
            output_pin=_pin_vector(output),
            seq=seq,
        )
        self._last_forward = record
        self._last_activations = activations
        return record

    def smashed_data(self, seq: int) -> SmashedData:
        """Expose the last cut activation as a frozen client->server msg."""
        _check_seq(seq)
        if self._last_forward is None or self._last_activations is None:
            raise SplitLearningError(
                "no forward pass yet; call forward() first"
            )
        smashed = self._last_activations[self._cut]
        return SmashedData(
            version=SPLIT_LEARNING_VERSION,
            schema=SCHEMA_PIN,
            cut=self._cut,
            activation=tuple(smashed),
            activation_pin=self._last_forward.smashed_pin,
            seq=seq,
        )

    def backward(self, loss_grad: Sequence[float], seq: int) -> BackwardPass:
        """Server-side backprop: output gradient down to the cut."""
        _check_seq(seq)
        if self._last_forward is None or self._last_activations is None:
            raise SplitLearningError(
                "no forward pass yet; call forward() first"
            )
        grad = _check_vector(loss_grad, self._dims[-1], "loss_grad")
        activations = self._last_activations
        # Backprop through server layers (cut .. n-1).
        for i in range(self._n_layers - 1, self._cut - 1, -1):
            grad = _matvec(
                [list(col) for col in zip(*self._weights[i])], grad
            )
            if i > self._cut:
                # ReLU derivative at the recorded pre-activation sign.
                grad = [
                    g if a > 0.0 else 0.0
                    for g, a in zip(grad, activations[i])
                ]
        record = BackwardPass(
            version=SPLIT_LEARNING_VERSION,
            schema=SCHEMA_PIN,
            cut=self._cut,
            cut_gradient=tuple(grad),
            cut_gradient_pin=_pin_vector(grad),
            loss_gradient_pin=_pin_vector(loss_grad),
            seq=seq,
        )
        return record

    def apply_client_gradients(self, cut_grad: BackwardPass, seq: int) -> str:
        """Finish client-side backprop; returns the input-gradient pin."""
        _check_seq(seq)
        if not isinstance(cut_grad, BackwardPass):
            raise TypeError("cut_grad must be a BackwardPass")
        if self._last_forward is None or self._last_activations is None:
            raise SplitLearningError(
                "no forward pass yet; call forward() first"
            )
        if cut_grad.cut != self._cut:
            raise SplitLearningError(
                f"cut gradient is for cut {cut_grad.cut}, "
                f"network cut is {self._cut}"
            )
        if cut_grad.seq < self._last_forward.seq:
            raise SplitLearningError(
                "cut gradient predates the cached forward pass"
            )
        grad = list(cut_grad.cut_gradient)
        activations = self._last_activations
        for i in range(self._cut - 1, -1, -1):
            grad = _matvec(
                [list(col) for col in zip(*self._weights[i])], grad
            )
            if i > 0:
                grad = [
                    g if a > 0.0 else 0.0
                    for g, a in zip(grad, activations[i])
                ]
        return _pin_vector(grad)

    def move_cut(self, new_cut: int, seq: int) -> None:
        """Re-split the network at a different layer."""
        _check_seq(seq)
        _reject_bool(new_cut, "new_cut")
        if not isinstance(new_cut, int):
            raise TypeError("new_cut must be int")
        if new_cut < 1 or new_cut >= self._n_layers:
            raise SplitLearningError(
                f"new_cut must be in [1, {self._n_layers - 1}]"
            )
        self._cut = new_cut
        self._last_forward = None
        self._last_activations = None


def main() -> None:
    sl = SplitLearning(n_layers=4, dims=[4, 8, 8, 4, 2], cut=2)
    fwd = sl.forward([0.5, -0.5, 0.25, 1.0], seq=1)
    smash = sl.smashed_data(seq=2)
    assert smash.activation_pin == fwd.smashed_pin
    bwd = sl.backward([1.0, -1.0], seq=3)
    assert bwd.cut == 2
    pin = sl.apply_client_gradients(bwd, seq=4)
    assert pin.startswith("sha256:")
    ev = split_learning_audit_event("forwarded", 5, fwd.smashed_pin)
    assert ev["format"] == "audit.ndjson/1"
    sl.move_cut(3, seq=6)
    assert sl.cut_layer == 3 and sl.client_layer_count() == 3
    print("split-learning OK: forward, smashed, backward, cut-move")


if __name__ == "__main__":
    main()
