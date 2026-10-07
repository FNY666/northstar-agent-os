"""Federated-learning Byzantine attack detector: majority statistics, not trust.

Research datum: federated aggregation is a Byzantine consensus problem.
A single malicious client can poison the global model or plant a backdoor
without any single update "looking wrong" in isolation:

* **Model replacement** (Bagdasaryan et al., 2020): the attacker scales a
  backdoored update by the inverse of the aggregation weight so the
  *average* becomes the attacker's model. The update looks like a
  legitimate-but-large gradient step.
* **Sign flipping / inner-product manipulation** (Baruch et al., 2019):
  the attacker flips the sign of its update so it points against the
  honest direction. Aggregation then moves the model the wrong way.
* **Random/divergent updates**: a client submitting noise or a wildly
  divergent vector to degrade convergence or stall the round.

This module detects those three shapes with coordinate-wise median
statistics over the *other* clients' updates (the robust-aggregation
literature's standard honest reference: median, trimmed mean, Krum).
One client is never compared against itself, and the reference is a
median -- so up to half the cohort can be Byzantine before the
reference itself is compromised.

Hard doctrine: aggregation trusts nothing. Every update is scored
against the majority; scores are evidence, not verdicts.

Honest scope (documented here, not elided): shape detector on
host-reported update vectors. It cannot see the client's true local
data, cannot distinguish an honest-but-heterogeneous client (non-IID
data legitimately produces divergent updates) from an attacker, and
cannot observe updates the host never reports. A clean verdict is
"no known Byzantine shape", never "all clients honest". Colluding
clients above 50% poison the median and pass silently -- this is the
known limit of all median-based defenses.

Design rules (repo conventions):

- Frozen dataclasses, ``sha256:`` digest pins on canonical JSON with
  constant-time compare where applicable, fail-closed validation,
  caller-supplied everything (no wall-clock reads, no network).
- ``round_seq`` is a caller-supplied integer sequence number; bools and
  negatives are rejected. Vectors are tuples of floats; bools are
  rejected as vector elements (``True`` is not ``1.0``).
- ``detect_byzantine`` is a boolean tripwire; ``scan_byzantine``
  returns frozen per-client reports. No composite safety score -- each
  report is one layer's evidence.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from enum import Enum
from hmac import compare_digest
from typing import Any, Dict, Iterable, List, Mapping, Tuple


FEDERATED_ATTACK_DETECTOR_VERSION = "federated-attack-detector.v1"

#: The schema every record this module emits must carry.
SCHEMA_PIN = "northstar.federated-attack-detector.v1"

#: Digest prefix for pinned records.
_DIGEST_PREFIX = "sha256:"


def _canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding (stdlib-only JCS approximation)."""
    import json as _json

    return _json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256_hex(obj: Any) -> str:
    return hashlib.sha256(_canonical_json(obj)).hexdigest()


class ByzantineSignal(Enum):
    """The attack shape a report is filed under."""

    DIVERGENCE = "divergence"  # update far from the coordinate-wise median
    SIGN_FLIP = "sign-flip"  # update points against the median direction
    SCALE = "scale"  # inflated norm or inflated aggregation weight


#: A median-normalized distance above this flags divergence.
#: Honest non-IID clients can diverge, so this is a flag, not a verdict.
DIVERGENCE_THRESHOLD = 3.0

#: Cosine similarity at or below this flags a sign flip (pointing against
#: the honest direction). Near-zero cosine is ambiguous drift, not a flip.
SIGN_FLIP_THRESHOLD = -0.1

#: Norm ratio above this flags an inflated update (model-replacement shape).
SCALE_THRESHOLD = 5.0

#: Weight ratio above this flags an inflated aggregation weight claim.
WEIGHT_THRESHOLD = 5.0

#: Minimum cohort size for a median reference to mean anything.
MIN_COHORT = 3

#: Cosine above this means the update points roughly along the honest
#: direction. Below it, an inflated-norm update is not an "inflated
#: version of the honest update" at all -- it is a different-direction
#: vector, and divergence is the better diagnosis. (Triangle inequality:
#: a norm ratio R forces median-normalized distance >= R - 1, so a
#: norm-scale fire with off-direction always coincides with a
#: divergence fire; the ordering below is still total.)
HONEST_DIRECTION_COSINE = 0.5


def _reject_bool(value: Any, name: str) -> None:
    if isinstance(value, bool):
        raise TypeError(f"{name} must not be a bool")


@dataclass(frozen=True)
class ClientUpdate:
    """One client's submitted update for one federated round.

    ``vector`` is the client's gradient/model-delta as a tuple of floats.
    ``weight`` is the client's *claimed* aggregation weight (e.g. local
    dataset size in FedAvg); inflated claims are themselves a signal.
    """

    client_id: str
    round_seq: int
    vector: Tuple[float, ...]
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not isinstance(self.client_id, str) or not self.client_id:
            raise TypeError("client_id must be a non-empty string")
        _reject_bool(self.round_seq, "round_seq")
        if not isinstance(self.round_seq, int) or self.round_seq < 0:
            raise TypeError("round_seq must be a non-negative int")
        if (
            not isinstance(self.vector, tuple)
            or not self.vector
            or any(not isinstance(v, (int, float)) or isinstance(v, bool) for v in self.vector)
        ):
            raise TypeError("vector must be a non-empty tuple of numbers (no bools)")
        _reject_bool(self.weight, "weight")
        if not isinstance(self.weight, (int, float)) or not math.isfinite(self.weight):
            raise TypeError("weight must be a finite number")
        if self.weight <= 0:
            raise ValueError("weight must be positive")

    def digest(self) -> str:
        """Pin this update for the audit trail."""
        return _DIGEST_PREFIX + _sha256_hex(
            {
                "schema": SCHEMA_PIN,
                "client_id": self.client_id,
                "round_seq": self.round_seq,
                "vector": list(self.vector),
                "weight": self.weight,
            }
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "client_id": self.client_id,
            "round_seq": self.round_seq,
            "vector": list(self.vector),
            "weight": self.weight,
        }


def _coerce_update(item: Any) -> ClientUpdate:
    """Accept a ClientUpdate or an equivalent mapping; fail closed."""
    if isinstance(item, ClientUpdate):
        return item
    if isinstance(item, Mapping):
        vector = item.get("vector")
        if isinstance(vector, list):
            vector = tuple(vector)
        return ClientUpdate(
            client_id=item.get("client_id", ""),
            round_seq=item.get("round_seq", 0),
            vector=vector,
            weight=item.get("weight", 1.0),
        )
    raise TypeError("updates must be ClientUpdate records or mappings")


@dataclass(frozen=True)
class ByzantineReport:
    """One flagged client: frozen evidence, not a verdict."""

    client_id: str
    signal: ByzantineSignal
    anomaly_score: float
    detail: str
    round_seq: int
    schema: str = field(default=SCHEMA_PIN)

    def __post_init__(self) -> None:
        if not isinstance(self.signal, ByzantineSignal):
            raise TypeError("signal must be a ByzantineSignal")
        if not isinstance(self.anomaly_score, (int, float)) or isinstance(
            self.anomaly_score, bool
        ):
            raise TypeError("anomaly_score must be a number")
        if not 0.0 <= self.anomaly_score <= 1.0:
            raise ValueError("anomaly_score must be in [0, 1]")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "client_id": self.client_id,
            "signal": self.signal.value,
            "anomaly_score": self.anomaly_score,
            "detail": self.detail,
            "round_seq": self.round_seq,
        }


def _median(values: List[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _coordinate_median(vectors: List[Tuple[float, ...]]) -> Tuple[float, ...]:
    """Coordinate-wise median: Byzantine-robust honest reference."""
    dim = len(vectors[0])
    return tuple(
        _median([v[i] for v in vectors]) for i in range(dim)
    )


def _norm(vector: Tuple[float, ...]) -> float:
    return math.sqrt(sum(v * v for v in vector))


def _dot(a: Tuple[float, ...], b: Tuple[float, ...]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _score_update(
    update: ClientUpdate, others: List[ClientUpdate]
) -> Tuple[ByzantineSignal | None, float, str]:
    """Score one update against the median of the others.

    Returns (signal, anomaly_score, detail); signal is None when the
    update is within all envelopes. When several envelopes fire, a
    decision tree picks the most *actionable* diagnosis, not merely
    the largest number:

    1. SIGN_FLIP -- exact anti-direction is the sharpest adversarial
       claim and always wins.
    2. SCALE (weight) -- an inflated aggregation-weight claim is
       direction-independent gaming of FedAvg itself.
    3. SCALE (norm) -- only when the update points roughly along the
       honest direction: the model-replacement shape is an *inflated
       copy of the honest update*.
    4. DIVERGENCE -- a big-norm update in a wrong direction is not an
       inflation of the honest update; the distribution mismatch is
       the real story. (Also the plain divergent case.)

    The score is the fired envelope's own normalized severity.
    """
    ref = _coordinate_median([u.vector for u in others])
    ref_norm = _norm(ref)
    upd_norm = _norm(update.vector)

    cosine: float | None = None
    flip_score = 0.0
    if ref_norm > 0.0 and upd_norm > 0.0:
        cosine = _dot(update.vector, ref) / (upd_norm * ref_norm)
        if cosine <= SIGN_FLIP_THRESHOLD:
            # Full reversal (cosine -1) scores 1.0; at the threshold it
            # scores -threshold (0.1); linear in between.
            flip_score = max(0.0, min(1.0, -cosine))

    div_score = 0.0
    div_detail = ""
    if ref_norm > 0.0:
        distance = math.sqrt(
            sum((a - b) ** 2 for a, b in zip(update.vector, ref))
        )
        divergence = distance / ref_norm
        if divergence >= DIVERGENCE_THRESHOLD:
            div_score = min(1.0, divergence / (2.0 * DIVERGENCE_THRESHOLD))
            div_detail = (
                f"median-normalized distance {divergence:.2f} "
                f">= threshold {DIVERGENCE_THRESHOLD}"
            )

    norm_score = 0.0
    norm_detail = ""
    other_norms = [_norm(u.vector) for u in others]
    median_norm = _median(other_norms)
    if median_norm > 0.0:
        norm_ratio = upd_norm / median_norm
        if norm_ratio >= SCALE_THRESHOLD:
            norm_score = min(1.0, norm_ratio / (2.0 * SCALE_THRESHOLD))
            norm_detail = (
                f"norm ratio {norm_ratio:.2f} >= threshold {SCALE_THRESHOLD} "
                "(inflated update; model-replacement shape)"
            )

    weight_score = 0.0
    weight_detail = ""
    other_weights = [u.weight for u in others]
    median_weight = _median(other_weights)
    if median_weight > 0.0:
        weight_ratio = update.weight / median_weight
        if weight_ratio >= WEIGHT_THRESHOLD:
            weight_score = min(1.0, weight_ratio / (2.0 * WEIGHT_THRESHOLD))
            weight_detail = (
                f"weight ratio {weight_ratio:.2f} >= threshold {WEIGHT_THRESHOLD} "
                "(inflated aggregation weight claim)"
            )

    if flip_score > 0.0:
        detail = (
            f"cosine {cosine:.3f} <= threshold {SIGN_FLIP_THRESHOLD} "
            "(points against the honest direction)"
        )
        return ByzantineSignal.SIGN_FLIP, flip_score, detail
    if weight_score > 0.0:
        return ByzantineSignal.SCALE, weight_score, weight_detail
    if norm_score > 0.0 and cosine is not None and cosine > HONEST_DIRECTION_COSINE:
        return ByzantineSignal.SCALE, norm_score, norm_detail
    if div_score > 0.0:
        return ByzantineSignal.DIVERGENCE, div_score, div_detail
    if norm_score > 0.0:
        # Degenerate fallback: inflated norm that somehow did not trip
        # divergence (triangle inequality makes this near-impossible).
        return ByzantineSignal.SCALE, norm_score, norm_detail
    return None, 0.0, ""


def scan_byzantine(updates: Iterable[Any]) -> Tuple[ByzantineReport, ...]:
    """Score every client against the median of the others.

    Returns frozen reports in client-id order (deterministic). Fewer
    than ``MIN_COHORT`` updates yields no reports: with no honest
    majority to reference, there is no evidence either way, and the
    module refuses to certify or to accuse.
    """
    if updates is None:
        raise TypeError("updates must be an iterable of ClientUpdate records")
    coerced = [_coerce_update(u) for u in updates]
    if len(coerced) < MIN_COHORT:
        return ()

    dim = len(coerced[0].vector)
    for u in coerced[1:]:
        if len(u.vector) != dim:
            raise TypeError("all update vectors must share one dimension")

    reports: List[ByzantineReport] = []
    for i, update in enumerate(coerced):
        others = coerced[:i] + coerced[i + 1 :]
        signal, score, detail = _score_update(update, others)
        if signal is not None:
            reports.append(
                ByzantineReport(
                    client_id=update.client_id,
                    signal=signal,
                    anomaly_score=score,
                    detail=detail,
                    round_seq=update.round_seq,
                )
            )
    reports.sort(key=lambda r: r.client_id)
    return tuple(reports)


def detect_byzantine(updates: Iterable[Any]) -> bool:
    """Tripwire: True when at least one client shows a Byzantine shape."""
    return len(scan_byzantine(updates)) > 0


def byzantine_audit_event(
    report: ByzantineReport, seq: int
) -> Dict[str, Any]:
    """Shape a report for the host's audit trail (``audit.ndjson/1``-style)."""
    _reject_bool(seq, "seq")
    if not isinstance(seq, int) or seq < 0:
        raise TypeError("seq must be a non-negative int")
    payload = report.as_dict()
    return {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "kind": "federated-byzantine-flag",
        "digest": _DIGEST_PREFIX + _sha256_hex(payload),
        "payload": payload,
    }


def main() -> None:
    """Self-check: canonical scenario with one sign-flip and one scaler."""
    honest_a = ClientUpdate("honest-a", 1, (1.0, 2.0, 3.0))
    honest_b = ClientUpdate("honest-b", 1, (1.1, 1.9, 3.2))
    honest_c = ClientUpdate("honest-c", 1, (0.9, 2.1, 2.8))
    flipper = ClientUpdate("flipper", 1, (-1.0, -2.0, -3.0))
    scaler = ClientUpdate("scaler", 1, (10.0, 20.0, 30.0))
    cohort = [honest_a, honest_b, honest_c, flipper, scaler]

    reports = scan_byzantine(cohort)
    by_client = {r.client_id: r for r in reports}
    assert "flipper" in by_client, "sign flip must be caught"
    assert by_client["flipper"].signal is ByzantineSignal.SIGN_FLIP
    assert "scaler" in by_client, "inflated update must be caught"
    assert by_client["scaler"].signal is ByzantineSignal.SCALE
    assert "honest-a" not in by_client
    assert "honest-b" not in by_client
    assert "honest-c" not in by_client
    assert detect_byzantine(cohort) is True
    assert detect_byzantine([honest_a, honest_b, honest_c]) is False
    assert scan_byzantine([honest_a, honest_b]) == ()  # below MIN_COHORT

    # Divergence shape: one client far from the median.
    drifter = ClientUpdate("drifter", 1, (50.0, -40.0, 60.0))
    reports = scan_byzantine([honest_a, honest_b, honest_c, drifter])
    assert len(reports) == 1 and reports[0].client_id == "drifter"
    assert reports[0].signal is ByzantineSignal.DIVERGENCE

    # Inflated weight claim.
    heavyweight = ClientUpdate("heavy", 1, (1.0, 2.0, 3.0), weight=100.0)
    reports = scan_byzantine([honest_a, honest_b, honest_c, heavyweight])
    assert len(reports) == 1 and reports[0].signal is ByzantineSignal.SCALE

    print(
        "federated-attack-detector OK: sign-flip, scale, divergence, "
        "and inflated-weight shapes all flagged; honest cohort clean"
    )


if __name__ == "__main__":
    main()
