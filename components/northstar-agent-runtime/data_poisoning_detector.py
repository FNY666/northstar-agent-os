"""Training data poisoning detector: catch backdoors before they train.

Training data poisoning is the attack shape where the adversary does not
touch the model, the prompt, or the tools — they touch the *data*. A
handful of poisoned samples (a wrong label here, an implanted trigger
pattern there) get averaged into the gradient update and the backdoor
survives training while the eval suite stays green. The standard CI
pipeline — "loss went down, accuracy held" — is blind to it.

The three classical shapes this module surfaces:

1. **Label flips** — the same (or near-identical) input carrying two
   different labels. Clean data is consistent: identical feature vectors
   do not disagree about their label. When they do, at least one side
   was written by someone other than the labeling process.
2. **Outlier clusters** — poisoned samples often sit far from the
   natural data mass, in a corner of feature space where the clean data
   never goes. A single outlier is noise; a *cluster* of far outliers
   is a manufacturing process.
3. **Trigger patterns** — the backdoor shape: a feature value that is
   rare in the corpus but appears repeatedly and correlates with one
   target label. The canonical example is a single pixel/feature set to
   an unusual constant on samples that all read "class 0" — the trigger
   that fires at inference time.

Design:

* ``DataSample`` is the frozen per-sample record: ``features`` (a tuple
  of floats), ``label`` (str), ``source`` (where it came from — a
  contributor id, a crawl batch, anything), and a caller-supplied integer
  ``seq``. No wall-clock anywhere; ordering is the caller's.
* ``analyze_dataset(samples)`` folds the whole dataset into a frozen
  ``PoisoningReport``: per-signal scores in [0, 1], the aggregate
  ``anomaly_score``, and the ``affected_samples`` (seqs) that tripped a
  signal.
* ``detect_poisoning(samples)`` is the boolean checkpoint: ``True``
  when ``anomaly_score`` reaches ``POISONING_THRESHOLD``.
* The three signals are independent and each interpretable on its own;
  the aggregate is the max (fail toward surfacing, never toward hiding):
  - **flip**: fraction of quantized-feature groups whose members
    disagree about the label. Quantization is exact-equality on the
    rounded features — conservative, no fuzzy matching.
  - **outlier**: fraction of samples whose z-distance from the dataset
    centroid exceeds 3. A tight far-away cluster counts per member, so
    a manufactured pocket scores higher than one stray point.
  - **trigger**: for each feature index, a value occurring in <5% of
    samples but >=3 samples, where >=80% of those samples share one
    label. Score is the strongest such correlation found.
* ``poisoning_audit_event()`` shapes the report for ``audit.ndjson/1``.

Fail-closed throughout: a non-list input is a programming error
(``TypeError``); an empty dataset has no verdict (``False``); feature
vectors of mixed length are a ``ValueError``; non-numeric or bool
features are ``TypeError``. Malformed data is *suspicious*, not clean —
but this module refuses to score what it cannot parse, and says so
loudly rather than returning a quiet ``False``.

Honest scope: this is a *statistical shape* detector over a
host-supplied dataset. It catches the three classical manufacturing
signatures — crude flips, far clusters, correlated rare values. An
adaptive adversary (clean-label poisoning, feature-space camouflage,
poisoning below the 5%/3-sample floor) passes through untouched. A
clean verdict means "no known poisoning shape", never "the data is
trustworthy". Pair with provenance tracking (who contributed what,
when) and held-out canary evaluation for the full picture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import sqrt
from typing import Any, Iterable, Mapping, Optional, Sequence

DATA_POISONING_VERSION = "data-poisoning-detector.v1"
SCHEMA_PIN = "northstar.data-poisoning.v1"

#: Aggregate anomaly score at or above this trips ``detect_poisoning``.
POISONING_THRESHOLD = 0.5

#: Trigger search: value rarer than this fraction of the corpus ...
TRIGGER_RARITY = 0.05
#: ... but appearing at least this many times ...
TRIGGER_MIN_COUNT = 3
#: ... with at least this fraction sharing one label.
TRIGGER_LABEL_COHERENCE = 0.8

#: Decimals used to quantize features for the label-flip check.
FLIP_QUANTIZE_DECIMALS = 3


@dataclass(frozen=True)
class DataSample:
    """One frozen training sample.

    ``features`` is the numeric feature vector, ``label`` the class
    string, ``source`` an opaque contributor/batch tag, and ``seq`` the
    caller-supplied ordering key. All numeric validation happens at
    construction: bool features, non-numeric features, NaN, and empty
    vectors are rejected loudly.
    """

    features: tuple
    label: str
    source: str
    seq: int

    def __post_init__(self) -> None:
        if not isinstance(self.features, tuple) or len(self.features) == 0:
            raise TypeError("features must be a non-empty tuple")
        for f in self.features:
            if isinstance(f, bool) or not isinstance(f, (int, float)):
                raise TypeError("features must be numeric (bool rejected)")
            if f != f or f in (float("inf"), float("-inf")):
                raise ValueError("features must be finite (no NaN/inf)")
        if not isinstance(self.label, str) or not self.label:
            raise TypeError("label must be a non-empty str")
        if not isinstance(self.source, str) or not self.source:
            raise TypeError("source must be a non-empty str")
        if isinstance(self.seq, bool) or not isinstance(self.seq, int):
            raise TypeError("seq must be an int (bool rejected)")


def make_sample(features: Sequence, label: str, source: str, seq: int) -> DataSample:
    """Convenience constructor accepting lists for ``features``."""
    return DataSample(tuple(features), label, source, seq)


def _validate_dataset(samples: Sequence) -> list:
    if not isinstance(samples, (list, tuple)):
        raise TypeError("samples must be a list or tuple")
    for s in samples:
        if not isinstance(s, DataSample):
            raise TypeError("every sample must be a DataSample")
    dims = {len(s.features) for s in samples}
    if len(dims) > 1:
        raise ValueError("all feature vectors must have the same length")
    return list(samples)


def _flip_score(samples: list) -> tuple[float, list[int]]:
    """Label-flip signal: quantized groups whose labels disagree."""
    if not samples:
        return 0.0, []
    groups: dict[tuple, list[int]] = {}
    for i, s in enumerate(samples):
        key = tuple(round(float(f), FLIP_QUANTIZE_DECIMALS) for f in s.features)
        groups.setdefault(key, []).append(i)
    affected: list[int] = []
    for idxs in groups.values():
        labels = {samples[i].label for i in idxs}
        if len(labels) > 1:
            affected.extend(samples[i].seq for i in idxs)
    score = min(1.0, len(affected) / len(samples))
    return score, sorted(set(affected))


def _centroid(samples: list) -> list[float]:
    dim = len(samples[0].features)
    n = len(samples)
    return [sum(float(s.features[d]) for s in samples) / n for d in range(dim)]


def _outlier_score(samples: list) -> tuple[float, list[int]]:
    """Outlier signal: a pocket of far-away samples.

    Flags samples whose distance from the centroid exceeds 3x the median
    distance. A z-score is deliberately avoided: with two tight symmetric
    clusters the distance std collapses to ~0 and harmless jitter scores
    infinite z. The score is pocket-calibrated — 5 far points is a full-
    strength signal (a manufactured pocket, not noise); a single stray
    point scores 0.2 and stays below the trip threshold.
    """
    if not samples:
        return 0.0, []
    c = _centroid(samples)
    dists = []
    for s in samples:
        d = sqrt(sum((float(f) - c[i]) ** 2 for i, f in enumerate(s.features)))
        dists.append(d)
    ordered = sorted(dists)
    n = len(ordered)
    median = ordered[n // 2] if n % 2 else (ordered[n // 2 - 1] + ordered[n // 2]) / 2
    cutoff = 3 * median if median > 0 else 0.0
    affected = [s.seq for s, d in zip(samples, dists) if cutoff > 0 and d > cutoff]
    score = min(1.0, len(affected) / 5)
    return score, sorted(set(affected))


def _trigger_score(samples: list) -> tuple[float, list[int]]:
    """Trigger signal: rare feature value with high label coherence.

    For each feature index, bucket the values coarsely (rounded to 1
    decimal — a backdoor trigger is a *constant*, not a distribution).
    A bucket is a trigger candidate when it is rare (< TRIGGER_RARITY
    of the corpus) but repeated (>= TRIGGER_MIN_COUNT) and its members
    mostly share one label (>= TRIGGER_LABEL_COHERENCE). The score is
    the strongest coherence found.
    """
    if not samples:
        return 0.0, []
    n = len(samples)
    dim = len(samples[0].features)
    best = 0.0
    best_seqs: list[int] = []
    for d in range(dim):
        buckets: dict[float, list[int]] = {}
        for i, s in enumerate(samples):
            key = round(float(s.features[d]), 1)
            buckets.setdefault(key, []).append(i)
        for idxs in buckets.values():
            frac = len(idxs) / n
            if frac >= TRIGGER_RARITY or len(idxs) < TRIGGER_MIN_COUNT:
                continue
            label_counts: dict[str, int] = {}
            for i in idxs:
                label_counts[samples[i].label] = label_counts.get(samples[i].label, 0) + 1
            coherence = max(label_counts.values()) / len(idxs)
            if coherence >= TRIGGER_LABEL_COHERENCE and coherence > best:
                best = coherence
                best_seqs = [samples[i].seq for i in idxs]
    return min(1.0, best), sorted(set(best_seqs))


@dataclass(frozen=True)
class PoisoningReport:
    """Frozen analysis of one dataset."""

    version: str = DATA_POISONING_VERSION
    schema: str = SCHEMA_PIN
    sample_count: int = 0
    flip_score: float = 0.0
    outlier_score: float = 0.0
    trigger_score: float = 0.0
    anomaly_score: float = 0.0
    affected_samples: tuple = field(default_factory=tuple)
    tripped: bool = False

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "schema": self.schema,
            "sample_count": self.sample_count,
            "flip_score": self.flip_score,
            "outlier_score": self.outlier_score,
            "trigger_score": self.trigger_score,
            "anomaly_score": self.anomaly_score,
            "affected_samples": list(self.affected_samples),
            "tripped": self.tripped,
        }


def analyze_dataset(samples: Sequence) -> PoisoningReport:
    """Fold a dataset into a frozen :class:`PoisoningReport`."""
    clean = _validate_dataset(samples)
    if not clean:
        return PoisoningReport()
    flip, flip_seqs = _flip_score(clean)
    outlier, outlier_seqs = _outlier_score(clean)
    trigger, trigger_seqs = _trigger_score(clean)
    anomaly = max(flip, outlier, trigger)
    affected = tuple(sorted(set(flip_seqs) | set(outlier_seqs) | set(trigger_seqs)))
    return PoisoningReport(
        sample_count=len(clean),
        flip_score=flip,
        outlier_score=outlier,
        trigger_score=trigger,
        anomaly_score=anomaly,
        affected_samples=affected,
        tripped=anomaly >= POISONING_THRESHOLD,
    )


def detect_poisoning(samples: Sequence) -> bool:
    """Boolean checkpoint: ``True`` when the dataset looks poisoned."""
    return analyze_dataset(samples).tripped


def poisoning_audit_event(report: PoisoningReport, dataset_id: str, seq: int) -> dict:
    """Shape a report for ``audit.ndjson/1``."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int (bool rejected)")
    if not isinstance(dataset_id, str) or not dataset_id:
        raise TypeError("dataset_id must be a non-empty str")
    return {
        "schema": "audit.ndjson/1",
        "event": "data-poisoning-scan",
        "dataset_id": dataset_id,
        "seq": seq,
        "tripped": report.tripped,
        "anomaly_score": report.anomaly_score,
        "signals": {
            "flip": report.flip_score,
            "outlier": report.outlier_score,
            "trigger": report.trigger_score,
        },
        "affected_samples": list(report.affected_samples),
        "detector_version": DATA_POISONING_VERSION,
    }


def main() -> None:
    # Clean dataset: two well-separated clusters, consistent labels.
    clean = [
        make_sample([1.0 + 0.1 * i, 2.0], "a", "batch-1", i) for i in range(20)
    ] + [
        make_sample([9.0, 8.0 + 0.1 * i], "b", "batch-1", 20 + i) for i in range(20)
    ]
    assert not detect_poisoning(clean), "clean dataset must not trip"

    # Label flips: identical features, conflicting labels.
    flips = [make_sample([1.0, 2.0], "a", "batch-2", i) for i in range(15)]
    flips += [make_sample([1.0, 2.0], "b", "batch-2", 15 + i) for i in range(15)]
    assert detect_poisoning(flips), "label flips must trip"

    # Trigger: rare constant value on one feature, all label "b".
    # 5 trigger samples in 105 total = 4.8% < 5% rarity bar.
    trig = [make_sample([1.0, 2.0 + 0.01 * i], "a", "batch-3", i) for i in range(100)]
    trig += [make_sample([777.7, 2.0], "b", "batch-3", 100 + i) for i in range(5)]
    r = analyze_dataset(trig)
    assert r.tripped and r.trigger_score >= TRIGGER_LABEL_COHERENCE, r.as_dict()

    # Outlier pocket: 6 far samples trip the pocket-calibrated signal;
    # one stray does not.
    pocket = [make_sample([0.1 * i, 0.1 * i], "a", "batch-4", i) for i in range(40)]
    pocket += [make_sample([100.0, 100.0], "b", "batch-4", 40 + i) for i in range(6)]
    rp = analyze_dataset(pocket)
    assert rp.outlier_score == 1.0 and rp.tripped, rp.as_dict()
    stray = [make_sample([0.1 * i, 0.1 * i], "a", "batch-5", i) for i in range(40)]
    stray += [make_sample([100.0, 100.0], "b", "batch-5", 40)]
    rs = analyze_dataset(stray)
    assert rs.outlier_score < POISONING_THRESHOLD, rs.as_dict()

    print("data-poisoning-detector OK: flips and trigger flagged, clean passed")


if __name__ == "__main__":
    main()
