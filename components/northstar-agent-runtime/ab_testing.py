"""A/B testing (experiment allocation) interface, simulated.

Research motivation: randomized experiments are the gold standard for
causal claims about product changes -- Optimizely, LaunchDarkly, and
in-house experimentation platforms all reduce to the same core
mechanics: declare variants with allocation weights, assign subjects
deterministically and stickily, then compare outcomes per variant.
Getting the bookkeeping wrong (non-sticky reassignment, allocation
drift, silent re-randomization) invalidates the experiment before any
statistics run.

This module is the *allocation bookkeeping* half of that shape, pinned
so the runtime's experimentation plumbing speaks one dialect:

- ``ABTesting.create(name, variants, seq)`` -- declare an experiment.
  ``variants`` maps variant ids to allocation weights; at least two
  variants are required (a one-variant "experiment" is refused
  fail-closed). Returns a frozen ``ExperimentRecord`` with a
  ``sha256:`` digest pin.
- ``ABTesting.assign(experiment_id, subject_id, seq)`` -- assign one
  subject to a variant. Bucketing is deterministic: the assignment is
  a pure function of (experiment digest, subject id), so the same
  subject always lands in the same variant and assignments replay
  exactly across instances. Re-assigning an already-assigned subject
  is idempotent -- the original ``AssignmentRecord`` is returned, never
  re-randomized (sticky assignment is what keeps an experiment valid).
- ``ABTesting.results(experiment_id, seq)`` -- frozen ``ResultsReport``
  with per-variant assigned counts plus expected-vs-observed shares
  (allocation balance as data, not as a significance claim).
- ``ABTesting.variant(experiment_id, variant_id)`` -- frozen
  ``VariantView``: one variant's declared weight, expected share, and
  live assignment count. Pure read view (no seq, no audit row).
- ``ABTesting.analyze(experiment_id, seq)`` -- frozen
  ``AnalysisReport``: per-variant deviations, a chi-square
  goodness-of-fit statistic against the declared weights, and a
  verdict as data (``"no-data"`` / ``"balanced"`` / ``"imbalanced"``).
  Allocation balance is ledger health, not statistical significance.
- ``ab_testing_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``experiment-created`` / ``subject-assigned`` / ``results-reported`` /
  ``analysis-reported``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``name`` must be a non-empty str; ``experiment_id`` (when given) must
  be a non-empty str and is never recycled.
- ``variants`` must name at least two distinct non-empty str ids;
  weights must be finite real numbers (bool refused -- ``True`` must
  not alias ``1``), >= 0, and sum to > 0. An all-zero allocation is
  refused: it would assign nobody.
- ``assign`` on an unknown experiment raises ``UnknownExperimentError``;
  empty/non-str ``subject_id`` is refused.
- Seqs are ints (not bool), >= 0.

Honest scope:

- This module books *allocation decisions*. It does not observe
  outcomes, compute p-values, or claim statistical significance --
  per-variant outcome comparison pairs with ``experiment_tracker``
  (and real inference belongs in a stats layer, not here).
- Bucketing uses sha256 as a deterministic uniform source, not a
  cryptographic randomness claim; it is replayable, which is the
  property the ledger needs.
- ``results()`` reports allocation balance (observed vs expected
  shares). A balanced ledger is a necessary, not sufficient, condition
  for a valid experiment -- it cannot detect peeking, SRM from
  upstream filtering, or subjects gaming the assignment.
- No persistence: the registry is in-memory. Pair with the durable
  audit writer if experiments must survive a restart.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AB_TESTING_VERSION = "ab-testing.v1"

#: Schema pin carried by records and audit events.
AB_TESTING_SCHEMA = "northstar.ab-testing.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_EXPERIMENT_CREATED = "experiment-created"
KIND_SUBJECT_ASSIGNED = "subject-assigned"
KIND_RESULTS_REPORTED = "results-reported"
KIND_ANALYSIS_REPORTED = "analysis-reported"
_KINDS = (KIND_EXPERIMENT_CREATED, KIND_SUBJECT_ASSIGNED,
          KIND_RESULTS_REPORTED, KIND_ANALYSIS_REPORTED)


class ABTestingError(Exception):
    """Base error for A/B testing (programming errors)."""


class DuplicateExperimentError(ABTestingError):
    """Raised when an experiment_id is created twice."""


class UnknownExperimentError(ABTestingError):
    """Raised when an experiment_id names no declared experiment."""


class UnknownVariantError(ABTestingError):
    """Raised when a variant_id names no variant of the experiment."""


class BadExperimentError(ABTestingError):
    """Raised when the experiment declaration itself is malformed."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")
    return value


def _check_name(value: object) -> str:
    """Validate an experiment name: non-empty str."""
    if not isinstance(value, str):
        raise TypeError(f"name must be str, got {type(value).__name__}")
    if not value:
        raise ValueError("name must be non-empty")
    return value


def _check_experiment_id(value: object) -> str:
    """Validate an experiment identifier: non-empty str."""
    if not isinstance(value, str):
        raise TypeError(f"experiment_id must be str, got {type(value).__name__}")
    if not value:
        raise ValueError("experiment_id must be non-empty")
    return value


def _check_subject_id(value: object) -> str:
    """Validate a subject identifier: non-empty str."""
    if not isinstance(value, str):
        raise TypeError(f"subject_id must be str, got {type(value).__name__}")
    if not value:
        raise ValueError("subject_id must be non-empty")
    return value


def _check_weight(variant_id: str, value: object) -> float:
    """Validate one allocation weight: finite real number, never bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"weight for variant {variant_id!r} must be a number, "
            f"got {type(value).__name__}"
        )
    if not math.isfinite(value):
        raise ValueError(f"weight for variant {variant_id!r} must be finite")
    if value < 0:
        raise ValueError(f"weight for variant {variant_id!r} must be >= 0")
    return float(value)


def _check_variants(variants: object) -> Tuple[Tuple[str, float], ...]:
    """Validate the variant declaration; return canonical (id, weight) pairs.

    Accepts a mapping of variant_id -> weight or an iterable of
    (variant_id, weight) pairs. The canonical form is sorted by
    variant_id so equivalent declarations pin to the same digest.
    """
    pairs: Iterable[Any]
    if isinstance(variants, Mapping):
        pairs = list(variants.items())
    elif isinstance(variants, Iterable) and not isinstance(variants, (str, bytes)):
        pairs = list(variants)
    else:
        raise TypeError(
            "variants must be a mapping or an iterable of (id, weight) pairs, "
            f"got {type(variants).__name__}"
        )
    checked: list[Tuple[str, float]] = []
    seen: set[str] = set()
    for entry in pairs:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise BadExperimentError(
                "each variant must be an (id, weight) pair, "
                f"got {entry!r}"
            )
        variant_id, weight = entry
        if not isinstance(variant_id, str):
            raise TypeError(
                f"variant id must be str, got {type(variant_id).__name__}"
            )
        if not variant_id:
            raise ValueError("variant id must be non-empty")
        if variant_id in seen:
            raise BadExperimentError(
                f"duplicate variant id {variant_id!r}"
            )
        seen.add(variant_id)
        checked.append((variant_id, _check_weight(variant_id, weight)))
    if len(checked) < 2:
        raise BadExperimentError(
            f"an experiment needs at least 2 variants, got {len(checked)}"
        )
    total = sum(w for _, w in checked)
    if total <= 0:
        raise BadExperimentError(
            "variant weights must sum to > 0 (an all-zero allocation assigns nobody)"
        )
    return tuple(sorted(checked, key=lambda kv: kv[0]))


def _pin_experiment(experiment_id: str, name: str,
                    variants: Tuple[Tuple[str, float], ...], seq: int) -> str:
    """Digest-pin the canonical experiment body."""
    return "sha256:" + jcs_sha256_hex({
        "experiment_id": experiment_id,
        "name": name,
        "variants": [[vid, w] for vid, w in variants],
        "seq": seq,
    })


def _pin_assignment(experiment_id: str, subject_id: str, variant_id: str,
                    bucket: int, seq: int) -> str:
    """Digest-pin the canonical assignment body."""
    return "sha256:" + jcs_sha256_hex({
        "experiment_id": experiment_id,
        "subject_id": subject_id,
        "variant_id": variant_id,
        "bucket": bucket,
        "seq": seq,
    })


def _pin_results(experiment_id: str,
                 counts: Tuple[Tuple[str, int], ...], seq: int) -> str:
    """Digest-pin the canonical results body."""
    return "sha256:" + jcs_sha256_hex({
        "experiment_id": experiment_id,
        "counts": [[vid, n] for vid, n in counts],
        "seq": seq,
    })


def _pin_analysis(experiment_id: str,
                  counts: Tuple[Tuple[str, int], ...],
                  verdict: str, seq: int) -> str:
    """Digest-pin the canonical analysis body."""
    return "sha256:" + jcs_sha256_hex({
        "experiment_id": experiment_id,
        "counts": [[vid, n] for vid, n in counts],
        "verdict": verdict,
        "seq": seq,
    })


#: Imbalance verdict tolerance: a variant whose observed share deviates
#: from its expected share by more than this (absolute) marks the
#: allocation "imbalanced". This is a ledger health signal, not a
#: statistical significance claim.
IMBALANCE_TOLERANCE = 0.05


def _bucket(experiment_digest: str, subject_id: str) -> int:
    """Deterministic 256-bit bucket for (experiment, subject)."""
    return int.from_bytes(
        hashlib.sha256(f"{experiment_digest}|{subject_id}".encode("utf-8")).digest(),
        "big",
    )


def _pick_variant(variants: Tuple[Tuple[str, float], ...], bucket: int) -> str:
    """Map a bucket to a variant id by walking cumulative weight shares."""
    total = sum(w for _, w in variants)
    # r in [0, 1): uniform under the sha256 source, deterministic.
    r = bucket / float(1 << 256)
    cumulative = 0.0
    for variant_id, weight in variants:
        cumulative += weight / total
        if r < cumulative:
            return variant_id
    # Float rounding can in principle skip every boundary; the last
    # variant owns the tail rather than raising.
    return variants[-1][0]


@dataclass(frozen=True)
class ExperimentRecord:
    """One declared experiment (frozen)."""
    experiment_id: str
    name: str
    variants: Tuple[Tuple[str, float], ...]
    seq: int
    digest: str
    version: str = AB_TESTING_VERSION
    schema: str = AB_TESTING_SCHEMA

    def variant_ids(self) -> Tuple[str, ...]:
        return tuple(vid for vid, _ in self.variants)

    def total_weight(self) -> float:
        return sum(w for _, w in self.variants)

    def expected_share(self, variant_id: str) -> float:
        for vid, weight in self.variants:
            if vid == variant_id:
                return weight / self.total_weight()
        raise KeyError(f"unknown variant {variant_id!r}")

    def as_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "name": self.name,
            "variants": [{"variant_id": vid, "weight": w}
                         for vid, w in self.variants],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class AssignmentRecord:
    """One subject's variant assignment (frozen, sticky)."""
    experiment_id: str
    subject_id: str
    variant_id: str
    bucket: int
    seq: int
    digest: str
    version: str = AB_TESTING_VERSION
    schema: str = AB_TESTING_SCHEMA

    def as_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "subject_id": self.subject_id,
            "variant_id": self.variant_id,
            "bucket": self.bucket,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VariantResult:
    """Per-variant allocation outcome inside a results report (frozen)."""
    variant_id: str
    assigned: int
    expected_share: float
    observed_share: float

    def as_dict(self) -> dict:
        return {
            "variant_id": self.variant_id,
            "assigned": self.assigned,
            "expected_share": self.expected_share,
            "observed_share": self.observed_share,
        }


@dataclass(frozen=True)
class ResultsReport:
    """Allocation results for one experiment (frozen)."""
    experiment_id: str
    total_subjects: int
    variant_results: Tuple[VariantResult, ...]
    seq: int
    digest: str
    version: str = AB_TESTING_VERSION
    schema: str = AB_TESTING_SCHEMA

    def count_for(self, variant_id: str) -> int:
        for vr in self.variant_results:
            if vr.variant_id == variant_id:
                return vr.assigned
        raise KeyError(f"unknown variant {variant_id!r}")

    def as_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "total_subjects": self.total_subjects,
            "variant_results": [vr.as_dict() for vr in self.variant_results],
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VariantView:
    """One variant's declared config plus live assignment count (frozen).

    Pure read view: booking nothing, auditing nothing.
    """
    experiment_id: str
    variant_id: str
    weight: float
    expected_share: float
    assigned: int
    version: str = AB_TESTING_VERSION
    schema: str = AB_TESTING_SCHEMA

    def as_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "variant_id": self.variant_id,
            "weight": self.weight,
            "expected_share": self.expected_share,
            "assigned": self.assigned,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class VariantAnalysis:
    """Per-variant allocation-balance analysis inside a report (frozen)."""
    variant_id: str
    assigned: int
    expected_share: float
    observed_share: float
    deviation: float  # observed_share - expected_share

    def as_dict(self) -> dict:
        return {
            "variant_id": self.variant_id,
            "assigned": self.assigned,
            "expected_share": self.expected_share,
            "observed_share": self.observed_share,
            "deviation": self.deviation,
        }


#: Allocation-balance verdicts (data, never raised).
VERDICT_NO_DATA = "no-data"
VERDICT_BALANCED = "balanced"
VERDICT_IMBALANCED = "imbalanced"
_ANALYSIS_VERDICTS = (VERDICT_NO_DATA, VERDICT_BALANCED, VERDICT_IMBALANCED)


@dataclass(frozen=True)
class AnalysisReport:
    """Allocation-balance analysis for one experiment (frozen).

    ``chi_square`` is the goodness-of-fit statistic against the declared
    allocation weights; ``verdict`` is ledger health as data -- a
    necessary, not sufficient, condition for a valid experiment.
    """
    experiment_id: str
    total_subjects: int
    variant_analyses: Tuple[VariantAnalysis, ...]
    chi_square: float
    verdict: str
    seq: int
    digest: str
    version: str = AB_TESTING_VERSION
    schema: str = AB_TESTING_SCHEMA

    def verify(self) -> bool:
        """Recompute the digest pin; False on any tampering."""
        counts = tuple((va.variant_id, va.assigned)
                       for va in self.variant_analyses)
        return self.digest == _pin_analysis(
            self.experiment_id, counts, self.verdict, self.seq)

    def as_dict(self) -> dict:
        return {
            "experiment_id": self.experiment_id,
            "total_subjects": self.total_subjects,
            "variant_analyses": [va.as_dict()
                                 for va in self.variant_analyses],
            "chi_square": self.chi_square,
            "verdict": self.verdict,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class ABTesting:
    """In-memory registry of A/B experiments (thread-safe)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._experiments: Dict[str, ExperimentRecord] = {}
        self._assignments: Dict[Tuple[str, str], AssignmentRecord] = {}
        self._audit: list[dict] = []
        self._counter = 0

    def _audit_event(self, kind: str, seq: int,
                     experiment_id: Optional[str] = None) -> None:
        self._audit.append(
            ab_testing_audit_event(kind, seq, experiment_id=experiment_id)
        )

    def create(self, name: object, variants: object, seq: object,
               experiment_id: object = None) -> ExperimentRecord:
        """Declare an experiment; returns the frozen record.

        ``variants`` maps variant ids to allocation weights (or is an
        iterable of ``(id, weight)`` pairs). When ``experiment_id`` is
        omitted a deterministic ``exp-<n>`` id is minted from the
        per-tracker counter.
        """
        seq = _check_seq(seq)
        name = _check_name(name)
        checked_variants = _check_variants(variants)
        if experiment_id is None:
            with self._lock:
                self._counter += 1
                experiment_id = f"exp-{self._counter}"
        else:
            experiment_id = _check_experiment_id(experiment_id)
        digest = _pin_experiment(experiment_id, name, checked_variants, seq)
        record = ExperimentRecord(
            experiment_id=experiment_id,
            name=name,
            variants=checked_variants,
            seq=seq,
            digest=digest,
        )
        with self._lock:
            if experiment_id in self._experiments:
                raise DuplicateExperimentError(
                    f"experiment_id {experiment_id!r} already declared"
                )
            self._experiments[experiment_id] = record
            self._audit_event(KIND_EXPERIMENT_CREATED, seq,
                              experiment_id=experiment_id)
        return record

    def assign(self, experiment_id: object, subject_id: object,
               seq: object) -> AssignmentRecord:
        """Assign a subject to a variant (deterministic, sticky).

        Re-assigning an already-assigned subject is idempotent: the
        original ``AssignmentRecord`` is returned unchanged.
        """
        seq = _check_seq(seq)
        experiment_id = _check_experiment_id(experiment_id)
        subject_id = _check_subject_id(subject_id)
        with self._lock:
            experiment = self._experiments.get(experiment_id)
            if experiment is None:
                raise UnknownExperimentError(
                    f"unknown experiment_id {experiment_id!r}"
                )
            key = (experiment_id, subject_id)
            existing = self._assignments.get(key)
            if existing is not None:
                return existing
            bucket = _bucket(experiment.digest, subject_id)
            variant_id = _pick_variant(experiment.variants, bucket)
            record = AssignmentRecord(
                experiment_id=experiment_id,
                subject_id=subject_id,
                variant_id=variant_id,
                bucket=bucket,
                seq=seq,
                digest=_pin_assignment(experiment_id, subject_id,
                                       variant_id, bucket, seq),
            )
            self._assignments[key] = record
            self._audit_event(KIND_SUBJECT_ASSIGNED, seq,
                              experiment_id=experiment_id)
            return record

    def results(self, experiment_id: object, seq: object) -> ResultsReport:
        """Report per-variant assignment counts for an experiment.

        Pure view: it mutates nothing and pins the digest over the
        observed counts, so the report is reproducible.
        """
        seq = _check_seq(seq)
        experiment_id = _check_experiment_id(experiment_id)
        with self._lock:
            experiment = self._experiments.get(experiment_id)
            if experiment is None:
                raise UnknownExperimentError(
                    f"unknown experiment_id {experiment_id!r}"
                )
            counts: Dict[str, int] = {vid: 0 for vid in experiment.variant_ids()}
            for (eid, _subject), assignment in self._assignments.items():
                if eid == experiment_id:
                    counts[assignment.variant_id] += 1
            total = sum(counts.values())
            variant_results = tuple(
                VariantResult(
                    variant_id=vid,
                    assigned=counts[vid],
                    expected_share=experiment.expected_share(vid),
                    observed_share=(counts[vid] / total) if total else 0.0,
                )
                for vid in experiment.variant_ids()
            )
            report = ResultsReport(
                experiment_id=experiment_id,
                total_subjects=total,
                variant_results=variant_results,
                seq=seq,
                digest=_pin_results(
                    experiment_id,
                    tuple((vid, counts[vid]) for vid in experiment.variant_ids()),
                    seq,
                ),
            )
            self._audit_event(KIND_RESULTS_REPORTED, seq,
                              experiment_id=experiment_id)
            return report

    def analyze(self, experiment_id: object, seq: object) -> AnalysisReport:
        """Analyze allocation balance for an experiment (frozen report).

        Books per-variant observed-vs-expected deviations, a chi-square
        goodness-of-fit statistic against the declared weights, and a
        verdict as data (``"no-data"`` / ``"balanced"`` /
        ``"imbalanced"``). Allocation balance is a ledger health signal
        -- it is not a significance claim about outcomes.
        """
        seq = _check_seq(seq)
        experiment_id = _check_experiment_id(experiment_id)
        with self._lock:
            experiment = self._experiments.get(experiment_id)
            if experiment is None:
                raise UnknownExperimentError(
                    f"unknown experiment_id {experiment_id!r}"
                )
            counts: Dict[str, int] = {vid: 0 for vid in experiment.variant_ids()}
            for (eid, _subject), assignment in self._assignments.items():
                if eid == experiment_id:
                    counts[assignment.variant_id] += 1
            total = sum(counts.values())
            analyses = []
            chi_square = 0.0
            max_abs_dev = 0.0
            for vid in experiment.variant_ids():
                expected_share = experiment.expected_share(vid)
                observed_share = (counts[vid] / total) if total else 0.0
                deviation = observed_share - expected_share
                max_abs_dev = max(max_abs_dev, abs(deviation))
                expected_count = total * expected_share
                if expected_count > 0:
                    chi_square += ((counts[vid] - expected_count) ** 2
                                   / expected_count)
                analyses.append(VariantAnalysis(
                    variant_id=vid,
                    assigned=counts[vid],
                    expected_share=expected_share,
                    observed_share=observed_share,
                    deviation=deviation,
                ))
            if total == 0:
                verdict = VERDICT_NO_DATA
            elif max_abs_dev > IMBALANCE_TOLERANCE:
                verdict = VERDICT_IMBALANCED
            else:
                verdict = VERDICT_BALANCED
            report = AnalysisReport(
                experiment_id=experiment_id,
                total_subjects=total,
                variant_analyses=tuple(analyses),
                chi_square=chi_square,
                verdict=verdict,
                seq=seq,
                digest=_pin_analysis(
                    experiment_id,
                    tuple((vid, counts[vid])
                          for vid in experiment.variant_ids()),
                    verdict,
                    seq,
                ),
            )
            self._audit_event(KIND_ANALYSIS_REPORTED, seq,
                              experiment_id=experiment_id)
            return report

    def experiment(self, experiment_id: object) -> ExperimentRecord:
        """Read back one declared experiment."""
        experiment_id = _check_experiment_id(experiment_id)
        with self._lock:
            record = self._experiments.get(experiment_id)
        if record is None:
            raise UnknownExperimentError(
                f"unknown experiment_id {experiment_id!r}"
            )
        return record

    def assignment(self, experiment_id: object,
                   subject_id: object) -> Optional[AssignmentRecord]:
        """Read back one subject's assignment, or None if unassigned."""
        experiment_id = _check_experiment_id(experiment_id)
        subject_id = _check_subject_id(subject_id)
        with self._lock:
            return self._assignments.get((experiment_id, subject_id))

    def variant(self, experiment_id: object,
                variant_id: object) -> VariantView:
        """Read back one variant's config plus its live assignment count.

        Pure view: it mutates nothing, consumes no seq, writes no audit
        row.
        """
        experiment_id = _check_experiment_id(experiment_id)
        if not isinstance(variant_id, str) or not variant_id:
            raise UnknownVariantError(
                f"variant_id must be a non-empty str, "
                f"got {variant_id!r}"
            )
        with self._lock:
            experiment = self._experiments.get(experiment_id)
            if experiment is None:
                raise UnknownExperimentError(
                    f"unknown experiment_id {experiment_id!r}"
                )
            weight: Optional[float] = None
            for vid, w in experiment.variants:
                if vid == variant_id:
                    weight = w
                    break
            if weight is None:
                raise UnknownVariantError(
                    f"unknown variant_id {variant_id!r} "
                    f"in experiment {experiment_id!r}"
                )
            assigned = sum(
                1 for (eid, _subject), a in self._assignments.items()
                if eid == experiment_id and a.variant_id == variant_id
            )
            return VariantView(
                experiment_id=experiment_id,
                variant_id=variant_id,
                weight=weight,
                expected_share=experiment.expected_share(variant_id),
                assigned=assigned,
            )

    def experiment_ids(self) -> Tuple[str, ...]:
        """Sorted ids of declared experiments."""
        with self._lock:
            return tuple(sorted(self._experiments))

    def audit_log(self) -> Tuple[dict, ...]:
        """Append-only audit trail."""
        with self._lock:
            return tuple(self._audit)

    def as_dict(self) -> dict:
        """Snapshot of the whole registry."""
        with self._lock:
            return {
                "experiments": [e.as_dict() for e in self._experiments.values()],
                "assignments": [a.as_dict() for a in self._assignments.values()],
                "version": AB_TESTING_VERSION,
                "schema": AB_TESTING_SCHEMA,
            }


def ab_testing_audit_event(kind: str, seq: object,
                           experiment_id: Optional[str] = None) -> dict:
    """Audit-shaped record for an A/B-testing observation."""
    if kind not in _KINDS:
        raise ValueError("unknown kind")
    _check_seq(seq)
    if experiment_id is not None:
        _check_experiment_id(experiment_id)
    body: dict[str, Any] = {
        "event": "ab-testing",
        "kind": kind,
        "audit_seq": seq,
        "schema": AUDIT_SCHEMA,
    }
    if experiment_id is not None:
        body["experiment_id"] = experiment_id
    return body


def main() -> None:
    ab = ABTesting()
    exp = ab.create("checkout-cta", {"control": 1, "treatment": 1}, seq=1)
    a1 = ab.assign(exp.experiment_id, "user-1", seq=2)
    a2 = ab.assign(exp.experiment_id, "user-2", seq=3)
    # Sticky + deterministic: same subject, same variant, same record.
    assert ab.assign(exp.experiment_id, "user-1", seq=4) == a1
    report = ab.results(exp.experiment_id, seq=5)
    assert report.total_subjects == 2, report
    assert {a1.variant_id, a2.variant_id} <= set(exp.variant_ids())
    # Spec API: variant view + allocation-balance analysis.
    view = ab.variant(exp.experiment_id, a1.variant_id)
    assert view.assigned >= 1, view
    analysis = ab.analyze(exp.experiment_id, seq=6)
    assert analysis.verify(), analysis
    assert analysis.verdict in ("balanced", "imbalanced", "no-data"), analysis
    print("ab-testing OK: create, assign, sticky, results, variant, analyze")


if __name__ == "__main__":
    main()
