"""Sparse autoencoder (SAE) interface contract for interpretability plumbing.

Sparse autoencoders are the current working method for extracting
human-interpretable features from model activations (Anthropic's "Towards
Monosemanticity" line, Cunningham et al. on k-sparse autoencoders,
Templeton et al. on scaling monosemanticity): an overcomplete dictionary
of feature directions, of which only a few (top-k) are active for any
given input. Two operations matter for any host wiring SAEs into a
governance loop:

* ``encode`` — map an activation vector to a sparse feature code;
* ``decode`` — reconstruct the activation from the sparse code.

The interpretability question is never "did encode run"; it is which
features fired, how often, and whether the reconstruction is faithful.
This module therefore pins three things:

1. :class:`SparseAutoencoder` — a deterministic top-k encoder/decoder with
   a seeded, unit-norm dictionary. Pure functions of (seed, input); no
   wall-clock, no network, no training.
2. :class:`FeatureUsageTracker` — accumulates which features fired across
   encodes so the host can spot *dead features* (dictionary directions that
   never activate — a standard SAE failure mode) and *overused* features
   (directions that fire on everything, i.e. polysemantic or degenerate).
3. Frozen records (``SparseCode``, ``FeatureActivation``,
   ``DeadFeatureReport``) with ``as_dict()`` carrying the schema pin, plus
   an audit-shaped event helper for the host's ``audit.ndjson/1`` stream.

Honest scope: this is an *interface contract*, not a trained SAE. The
decoder dictionary is seeded random, not learned from data, so individual
feature ids carry no semantic meaning — "feature 7 fired" says nothing
about what feature 7 *means*. What is honest: the plumbing (top-k
selection, reconstruction, usage accounting, dead-feature detection) is
exactly the plumbing a real SAE drops into, and production code written
against this API keeps working when the host swaps in trained weights.
A clean dead-feature report says "every direction fired at least once on
this corpus", never "the features are monosemantic".

Determinism contract: same seed + same input -> same code, bit for bit.
Top-k ties break by ascending feature id. All randomness comes from
``random.Random(seed)`` — stdlib, seeded, no global-RNG coupling.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

#: Module version pin. Bump on any semantic change.
SAE_INTERFACE_VERSION = "sae-interface.v1"

#: Schema pin for audit records and as_dict() payloads.
SAE_INTERFACE_SCHEMA = "northstar.sae-interface.v1"


class SAEError(Exception):
    """Base error for malformed SAE inputs (programming errors, fail closed)."""


def _check_positive_int(value: Any, name: str) -> int:
    """Validate a dimension/count; fail closed on bad input."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def _check_activation(values: Any, expected_dim: int) -> Tuple[float, ...]:
    """Validate an activation vector; fail closed on malformed input."""
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError(
            f"activation must be a sequence of numbers, got {type(values).__name__}"
        )
    items = tuple(values)
    if len(items) != expected_dim:
        raise ValueError(
            f"activation dim mismatch: expected {expected_dim}, got {len(items)}"
        )
    out: List[float] = []
    for i, v in enumerate(items):
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError(f"activation[{i}] must be a number, got {type(v).__name__}")
        if not math.isfinite(v):
            raise ValueError(f"activation[{i}] must be finite, got {v!r}")
        out.append(float(v))
    return tuple(out)


def _check_seq(seq: Any) -> int:
    """Validate a caller-supplied sequence number (no wall-clock anywhere)."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError(f"seq must be non-negative, got {seq}")
    return seq


@dataclass(frozen=True)
class FeatureActivation:
    """One active dictionary feature in a sparse code.

    Attributes:
        feature_id: dictionary index in ``[0, n_features)``.
        value: non-negative activation strength (ReLU of the raw score).
    """

    feature_id: int
    value: float

    def __post_init__(self) -> None:
        if isinstance(self.feature_id, bool) or not isinstance(self.feature_id, int):
            raise TypeError("feature_id must be an int")
        if self.feature_id < 0:
            raise ValueError("feature_id must be non-negative")
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise TypeError("value must be a number")
        if not math.isfinite(self.value):
            raise ValueError("value must be finite")
        if self.value < 0:
            raise ValueError("value must be non-negative")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SAE_INTERFACE_SCHEMA,
            "feature_id": self.feature_id,
            "value": float(self.value),
        }


@dataclass(frozen=True)
class SparseCode:
    """The sparse code produced by :meth:`SparseAutoencoder.encode`.

    Exactly ``min(sparsity_k, n_features)`` entries, in the order they were
    selected (descending score, ascending feature id on ties).
    """

    actives: Tuple[FeatureActivation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.actives, tuple):
            raise TypeError("actives must be a tuple")
        for a in self.actives:
            if not isinstance(a, FeatureActivation):
                raise TypeError("actives must contain FeatureActivation only")

    def feature_ids(self) -> Tuple[int, ...]:
        """Feature ids in selection order."""
        return tuple(a.feature_id for a in self.actives)

    def density(self) -> float:
        """Alias-friendly view: number of active features (always an int)."""
        return float(len(self.actives))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SAE_INTERFACE_SCHEMA,
            "actives": [a.as_dict() for a in self.actives],
        }


@dataclass(frozen=True)
class DeadFeatureReport:
    """Result of :meth:`FeatureUsageTracker.dead_feature_report`.

    ``dead_ids`` are dictionary indices that never fired across the
    recorded encodes. ``total_encodes`` is the denominator — a report over
    zero encodes marks everything dead (no evidence of life).
    """

    dead_ids: Tuple[int, ...]
    total_encodes: int

    def __post_init__(self) -> None:
        if not isinstance(self.dead_ids, tuple):
            raise TypeError("dead_ids must be a tuple")
        if isinstance(self.total_encodes, bool) or not isinstance(
            self.total_encodes, int
        ):
            raise TypeError("total_encodes must be an int")
        if self.total_encodes < 0:
            raise ValueError("total_encodes must be non-negative")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SAE_INTERFACE_SCHEMA,
            "dead_ids": list(self.dead_ids),
            "total_encodes": self.total_encodes,
        }


class SparseAutoencoder:
    """Deterministic top-k sparse autoencoder interface.

    Args:
        input_dim: activation vector length (> 0).
        n_features: dictionary size, overcomplete means ``n_features > input_dim``
            but that is not enforced — the contract works for any size.
        sparsity_k: number of active features per encode; must satisfy
            ``1 <= sparsity_k <= n_features``.
        seed: dictionary seed. Same seed -> same dictionary, bit for bit.

    The dictionary is generated once at construction: each feature is a
    random unit-norm direction drawn with ``random.Random(seed)``.
    """

    def __init__(
        self, input_dim: int, n_features: int, sparsity_k: int, seed: int = 0
    ) -> None:
        self.input_dim = _check_positive_int(input_dim, "input_dim")
        self.n_features = _check_positive_int(n_features, "n_features")
        self.sparsity_k = _check_positive_int(sparsity_k, "sparsity_k")
        if self.sparsity_k > self.n_features:
            raise ValueError(
                f"sparsity_k ({self.sparsity_k}) must not exceed "
                f"n_features ({self.n_features})"
            )
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise TypeError(f"seed must be an int, got {type(seed).__name__}")
        self.seed = seed
        self._decoder: Tuple[Tuple[float, ...], ...] = self._build_dictionary(seed)

    def _build_dictionary(self, seed: int) -> Tuple[Tuple[float, ...], ...]:
        rng = random.Random(seed)
        cols: List[Tuple[float, ...]] = []
        for _ in range(self.n_features):
            vec = [rng.gauss(0.0, 1.0) for _ in range(self.input_dim)]
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            cols.append(tuple(v / norm for v in vec))
        return tuple(cols)

    @property
    def dictionary(self) -> Tuple[Tuple[float, ...], ...]:
        """Read-only view of the dictionary (n_features unit-norm columns)."""
        return self._decoder

    def decoder_vector(self, feature_id: int) -> Tuple[float, ...]:
        """The dictionary direction for one feature (unit norm)."""
        if isinstance(feature_id, bool) or not isinstance(feature_id, int):
            raise TypeError("feature_id must be an int")
        if not 0 <= feature_id < self.n_features:
            raise ValueError(f"feature_id out of range: {feature_id}")
        return self._decoder[feature_id]

    def encode(self, activation: Sequence[float]) -> SparseCode:
        """Map an activation vector to a sparse feature code.

        Scores each feature by dot product with the activation, takes the
        top ``sparsity_k`` (ties break by ascending feature id), and applies
        ReLU. Always returns exactly ``min(sparsity_k, n_features)`` actives —
        ``sparsity_k <= n_features`` is enforced at construction, so exactly
        ``sparsity_k``.
        """
        x = _check_activation(activation, self.input_dim)
        scored = [
            (sum(x[i] * col[i] for i in range(self.input_dim)), j)
            for j, col in enumerate(self._decoder)
        ]
        # Descending score, ascending id on ties -> deterministic.
        scored.sort(key=lambda t: (-t[0], t[1]))
        actives = tuple(
            FeatureActivation(feature_id=j, value=max(0.0, s))
            for s, j in scored[: self.sparsity_k]
        )
        return SparseCode(actives=actives)

    def decode(self, code: SparseCode) -> Tuple[float, ...]:
        """Reconstruct an activation vector from a sparse code."""
        if not isinstance(code, SparseCode):
            raise TypeError(f"code must be a SparseCode, got {type(code).__name__}")
        recon = [0.0] * self.input_dim
        for active in code.actives:
            if not 0 <= active.feature_id < self.n_features:
                raise ValueError(
                    f"feature_id out of range for this SAE: {active.feature_id}"
                )
            col = self._decoder[active.feature_id]
            for i in range(self.input_dim):
                recon[i] += active.value * col[i]
        return tuple(recon)

    def reconstruction_error(self, activation: Sequence[float]) -> float:
        """Mean squared error of ``decode(encode(activation))``."""
        x = _check_activation(activation, self.input_dim)
        recon = self.decode(self.encode(x))
        return sum((a - r) ** 2 for a, r in zip(x, recon)) / self.input_dim

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SAE_INTERFACE_SCHEMA,
            "version": SAE_INTERFACE_VERSION,
            "input_dim": self.input_dim,
            "n_features": self.n_features,
            "sparsity_k": self.sparsity_k,
            "seed": self.seed,
        }


class FeatureUsageTracker:
    """Accumulates which dictionary features fired across encodes.

    The interpretability loop cares about usage statistics, not single
    encodes: dead features (never fired) waste dictionary capacity, and
    features that fire on *every* input are suspicious (degenerate or
    polysemantic directions). This tracker is the bookkeeping half; the
    encoder is the measurement half.
    """

    def __init__(self, n_features: int) -> None:
        self.n_features = _check_positive_int(n_features, "n_features")
        self._counts: List[int] = [0] * self.n_features
        self._total_encodes = 0

    @property
    def total_encodes(self) -> int:
        return self._total_encodes

    def record(self, code: SparseCode) -> None:
        """Record one encode's sparse code (counts features with value > 0)."""
        if not isinstance(code, SparseCode):
            raise TypeError(f"code must be a SparseCode, got {type(code).__name__}")
        for active in code.actives:
            if not 0 <= active.feature_id < self.n_features:
                raise ValueError(
                    f"feature_id out of range for this tracker: {active.feature_id}"
                )
            if active.value > 0.0:
                self._counts[active.feature_id] += 1
        self._total_encodes += 1

    def usage_counts(self) -> Tuple[int, ...]:
        """Per-feature fire counts, in feature-id order."""
        return tuple(self._counts)

    def dead_feature_report(self) -> DeadFeatureReport:
        """Features that never fired across all recorded encodes."""
        dead = tuple(i for i, c in enumerate(self._counts) if c == 0)
        return DeadFeatureReport(dead_ids=dead, total_encodes=self._total_encodes)

    def overused_features(self, threshold: float = 1.0) -> Tuple[int, ...]:
        """Features firing on at least ``threshold`` fraction of encodes.

        Args:
            threshold: fraction in (0, 1]; 1.0 (default) means "fired on
                every recorded encode". Zero encodes -> empty tuple (no
                evidence), never "everything is overused".
        """
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise TypeError("threshold must be a number")
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be in (0, 1]")
        if self._total_encodes == 0:
            return ()
        return tuple(
            i
            for i, c in enumerate(self._counts)
            if c / self._total_encodes >= threshold
        )

    def reset(self) -> None:
        """Clear all counts (start a fresh corpus)."""
        self._counts = [0] * self.n_features
        self._total_encodes = 0


def sae_audit_event(
    event_type: str,
    *,
    seq: int,
    detail: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for SAE operations.

    ``event_type`` is a short verb like ``"encode"`` or
    ``"dead-feature-report"``. ``seq`` is caller-supplied (no wall-clock).
    """
    _check_seq(seq)
    if not isinstance(event_type, str) or not event_type:
        raise ValueError("event_type must be a non-empty string")
    record: Dict[str, Any] = {
        "schema": "audit.ndjson/1",
        "module": SAE_INTERFACE_SCHEMA,
        "event_type": event_type,
        "seq": seq,
    }
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping")
        record["detail"] = dict(detail)
    return record


def main() -> None:
    """Self-check: encode/decode roundtrip, sparsity, dead-feature tracking."""
    sae = SparseAutoencoder(input_dim=8, n_features=32, sparsity_k=4, seed=7)
    code = sae.encode(tuple(float(i) for i in range(8)))
    assert len(code.actives) == 4, "exactly k actives"
    recon = sae.decode(code)
    assert len(recon) == 8, "reconstruction matches input dim"
    err = sae.reconstruction_error(tuple(float(i) for i in range(8)))
    assert err >= 0.0, "MSE is non-negative"

    tracker = FeatureUsageTracker(n_features=32)
    for _ in range(10):
        tracker.record(sae.encode(tuple(float(i) for i in range(8))))
    report = tracker.dead_feature_report()
    assert report.total_encodes == 10
    assert len(report.dead_ids) < 32, "the same input should reuse few features"

    empty = FeatureUsageTracker(n_features=5)
    assert empty.dead_feature_report().dead_ids == (0, 1, 2, 3, 4)

    ev = sae_audit_event("encode", seq=1, detail={"k": 4})
    assert ev["schema"] == "audit.ndjson/1"

    print(
        "sae-interface OK: top-k encode/decode roundtrip, usage tracking, "
        "dead-feature report"
    )


if __name__ == "__main__":
    main()
