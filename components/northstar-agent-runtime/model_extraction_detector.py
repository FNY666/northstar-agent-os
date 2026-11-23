"""Model-extraction detector: query logs as a tripwire for substitute-model theft.

Research datum: a model behind a black-box API can be copied without ever
seeing its weights. The adversary issues crafted query batches -- systematic
probing of the input space, paraphrase/gradient perturbations around base
inputs (Jacobian-style), or broad output-class coverage -- and trains a
substitute model on the (input, output) pairs. No single query is malicious;
the theft is the *shape of the batch*.

This module is a shape detector over host-reported query records. It watches
four independent signals, each in [0, 1], and takes the max (fail toward
surfacing):

1. **Volume** -- ``query_count / volume_threshold`` (capped at 1). A burst
   far above baseline is the cheapest extraction tell.
2. **Diversity** -- fraction of distinct input digests. Near 1.0 means the
   caller is exploring the input space, not reusing inputs for a goal.
   Legitimate traffic reuses prompts; extraction campaigns do not.
3. **Perturbation clusters** -- distinct input digests that share one
   input-length bucket (width 8 tokens). Paraphrase variants of a base input
   land at similar lengths with different digests; a bucket holding
   ``>= cluster_threshold`` distinct digests smells like local-surface
   mapping (gradient/confidence probing).
4. **Output-class coverage** -- distinct reported output classes (when the
   host reports them), normalized by 10. Substitute-training data collection
   spreads across classes; goal-directed use concentrates.

``detect_extraction`` returns True when the aggregate suspicion reaches
``suspicion_threshold`` (default 0.7). ``analyze_queries`` returns the full
frozen ``ExtractionPattern`` for audit.

Hard doctrine: the detector sees digests, never raw inputs -- the monitor
pins what it observed without becoming a second exfiltration channel.

Honest scope (documented here, not elided): shape detector on host-reported
records. It cannot see intent (a load test looks like volume), cannot
distinguish user-requested bulk evaluation from theft, and cannot observe
queries the host never logged. A clean verdict is "no known extraction
shape", never "no extraction". It measures; it does not block.

Design rules (repo conventions):

- Frozen dataclasses, ``sha256:`` digest pins with constant-time compare,
  fail-closed validation, caller-supplied everything (no wall-clock reads,
  no network). ``seq`` is a caller-supplied integer sequence number; bools
  and negatives are rejected.
- No composite safety score: suspicion is one metric for one layer, never
  collapsed with other layers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from hmac import compare_digest
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


EXTRACTION_DETECTOR_VERSION = "model-extraction-detector.v1"

#: The schema every record this module emits must carry.
SCHEMA_PIN = "northstar.model-extraction-detector.v1"

#: Digest prefix for pinned digests in this module.
_DIGEST_PREFIX = "sha256:"

#: Default decision threshold on aggregate suspicion.
SUSPICION_THRESHOLD = 0.7

#: Default volume tripwire: queries in one window.
VOLUME_THRESHOLD = 100

#: Default diversity bar: distinct-digest fraction that reads as exploration.
DIVERSITY_THRESHOLD = 0.9

#: Default perturbation tripwire: distinct digests in one length bucket.
CLUSTER_THRESHOLD = 5

#: Width of an input-length bucket (tokens) for perturbation clustering.
_LENGTH_BUCKET_WIDTH = 8


class ExtractionDetectorError(ValueError):
    """Malformed input to the extraction detector (fail closed)."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ExtractionDetectorError("seq must be an integer (bools rejected)")
    if seq < 0:
        raise ExtractionDetectorError("seq must be non-negative")
    return seq


def _check_digest(digest: Any) -> str:
    if not isinstance(digest, str):
        raise ExtractionDetectorError("input_digest must be a string")
    if len(digest) != 64:
        raise ExtractionDetectorError("input_digest must be a 64-char hex sha256")
    try:
        int(digest, 16)
    except ValueError:
        raise ExtractionDetectorError("input_digest must be hex") from None
    return digest.lower()


def _check_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExtractionDetectorError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class QueryRecord:
    """One host-reported query against the model API.

    The monitor sees the digest of the input, never the input itself.
    """

    query_id: str
    client_id: str
    seq: int
    input_digest: str
    input_len: int
    output_class: Optional[str] = None
    confidence: Optional[float] = None

    def __post_init__(self) -> None:
        _check_text(self.query_id, "query_id")
        _check_text(self.client_id, "client_id")
        _check_seq(self.seq)
        object.__setattr__(self, "input_digest", _check_digest(self.input_digest))
        if isinstance(self.input_len, bool) or not isinstance(self.input_len, int):
            raise ExtractionDetectorError("input_len must be an integer (bools rejected)")
        if self.input_len < 0:
            raise ExtractionDetectorError("input_len must be non-negative")
        if self.output_class is not None:
            _check_text(self.output_class, "output_class")
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(
                self.confidence, (int, float)
            ):
                raise ExtractionDetectorError("confidence must be a number")
            if not 0.0 <= float(self.confidence) <= 1.0:
                raise ExtractionDetectorError("confidence must be in [0, 1]")


def _coerce_record(item: Any) -> QueryRecord:
    if isinstance(item, QueryRecord):
        return item
    if isinstance(item, Mapping):
        try:
            return QueryRecord(
                query_id=item["query_id"],
                client_id=item["client_id"],
                seq=item["seq"],
                input_digest=item["input_digest"],
                input_len=item["input_len"],
                output_class=item.get("output_class"),
                confidence=item.get("confidence"),
            )
        except KeyError as exc:
            raise ExtractionDetectorError(f"query mapping missing key: {exc}") from None
    raise TypeError(
        f"query must be a QueryRecord or mapping, got {type(item).__name__}"
    )


def _digest_of(record: QueryRecord) -> str:
    body = (
        f"{EXTRACTION_DETECTOR_VERSION}|{record.query_id}|{record.client_id}|"
        f"{record.seq}|{record.input_digest}|{record.input_len}"
    )
    return _DIGEST_PREFIX + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExtractionPattern:
    """Frozen analysis of one query batch."""

    query_count: int
    diversity_score: float
    volume_score: float
    perturbation_score: float
    coverage_score: float
    suspicion: float
    strongest_signal: str
    verdict: bool
    version: str = EXTRACTION_DETECTOR_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "schema": self.schema,
            "query_count": self.query_count,
            "diversity_score": self.diversity_score,
            "volume_score": self.volume_score,
            "perturbation_score": self.perturbation_score,
            "coverage_score": self.coverage_score,
            "suspicion": self.suspicion,
            "strongest_signal": self.strongest_signal,
            "verdict": self.verdict,
        }


def _length_bucket(input_len: int) -> int:
    return input_len // _LENGTH_BUCKET_WIDTH


def analyze_queries(
    queries: Iterable[Any],
    *,
    volume_threshold: int = VOLUME_THRESHOLD,
    diversity_threshold: float = DIVERSITY_THRESHOLD,
    cluster_threshold: int = CLUSTER_THRESHOLD,
    suspicion_threshold: float = SUSPICION_THRESHOLD,
) -> ExtractionPattern:
    """Analyze a batch of query records; return the frozen pattern.

    Never raises on policy: malformed input fails closed with
    ``ExtractionDetectorError``/``TypeError`` (programming errors), an
    empty batch yields a quiet pattern.
    """
    if isinstance(volume_threshold, bool) or not isinstance(volume_threshold, int):
        raise ExtractionDetectorError("volume_threshold must be an integer")
    if volume_threshold <= 0:
        raise ExtractionDetectorError("volume_threshold must be positive")
    if isinstance(cluster_threshold, bool) or not isinstance(cluster_threshold, int):
        raise ExtractionDetectorError("cluster_threshold must be an integer")
    if cluster_threshold <= 0:
        raise ExtractionDetectorError("cluster_threshold must be positive")
    for name, value in (
        ("diversity_threshold", diversity_threshold),
        ("suspicion_threshold", suspicion_threshold),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ExtractionDetectorError(f"{name} must be a number")
        if not 0.0 < float(value) <= 1.0:
            raise ExtractionDetectorError(f"{name} must be in (0, 1]")
    if isinstance(queries, (str, bytes)) or isinstance(queries, Mapping):
        raise TypeError("queries must be a sequence of records, not a single mapping")

    records = [_coerce_record(q) for q in queries]
    count = len(records)
    if count == 0:
        return ExtractionPattern(
            query_count=0,
            diversity_score=0.0,
            volume_score=0.0,
            perturbation_score=0.0,
            coverage_score=0.0,
            suspicion=0.0,
            strongest_signal="none",
            verdict=False,
        )

    distinct = len({r.input_digest for r in records})
    diversity = distinct / count
    volume = min(1.0, count / volume_threshold)

    buckets: Dict[int, set] = {}
    for r in records:
        buckets.setdefault(_length_bucket(r.input_len), set()).add(r.input_digest)
    largest_cluster = max(len(digests) for digests in buckets.values())
    perturbation = min(1.0, largest_cluster / cluster_threshold)

    classes = {r.output_class for r in records if r.output_class is not None}
    coverage = min(1.0, len(classes) / 10) if classes else 0.0

    signals = (
        ("volume", volume),
        ("diversity", diversity),
        ("perturbation", perturbation),
        ("coverage", coverage),
    )
    strongest, suspicion = max(signals, key=lambda kv: kv[1])
    return ExtractionPattern(
        query_count=count,
        diversity_score=diversity,
        volume_score=volume,
        perturbation_score=perturbation,
        coverage_score=coverage,
        suspicion=suspicion,
        strongest_signal=strongest if suspicion > 0.0 else "none",
        verdict=suspicion >= suspicion_threshold,
    )


def detect_extraction(
    queries: Iterable[Any],
    *,
    volume_threshold: int = VOLUME_THRESHOLD,
    diversity_threshold: float = DIVERSITY_THRESHOLD,
    cluster_threshold: int = CLUSTER_THRESHOLD,
    suspicion_threshold: float = SUSPICION_THRESHOLD,
) -> bool:
    """True when the query batch shows a known extraction shape."""
    return analyze_queries(
        queries,
        volume_threshold=volume_threshold,
        diversity_threshold=diversity_threshold,
        cluster_threshold=cluster_threshold,
        suspicion_threshold=suspicion_threshold,
    ).verdict


def extraction_audit_event(pattern: ExtractionPattern) -> Dict[str, Any]:
    """Shape an extraction analysis as an audit-log record."""
    event = {
        "type": "audit.ndjson/1",
        "event": "model-extraction-analysis",
        "schema": SCHEMA_PIN,
        "version": EXTRACTION_DETECTOR_VERSION,
        **pattern.as_dict(),
    }
    digest_body = "|".join(
        f"{k}={event[k]}" for k in sorted(event) if k != "schema"
    )
    event["digest"] = _DIGEST_PREFIX + hashlib.sha256(
        digest_body.encode("utf-8")
    ).hexdigest()
    return event


def main() -> None:
    """Self-check: benign reuse stays quiet, extraction shape gets flagged."""
    benign = [
        {
            "query_id": f"b{i}",
            "client_id": "user-1",
            "seq": i,
            "input_digest": hashlib.sha256(f"same-prompt-{i % 3}".encode()).hexdigest(),
            "input_len": 40 + (i % 3),
        }
        for i in range(20)
    ]
    assert detect_extraction(benign) is False

    hostile = []
    for i in range(120):
        hostile.append(
            {
                "query_id": f"x{i}",
                "client_id": "anon",
                "seq": i,
                # paraphrase cluster: distinct digests, same length bucket
                "input_digest": hashlib.sha256(f"probe-{i}".encode()).hexdigest(),
                "input_len": 64 + (i % 5),
                "output_class": f"class-{i % 8}",
            }
        )
    pattern = analyze_queries(hostile)
    assert pattern.verdict is True, pattern.as_dict()
    assert pattern.strongest_signal in ("volume", "diversity", "perturbation", "coverage")
    print(
        "model-extraction-detector OK: benign quiet, "
        f"extraction flagged (suspicion={pattern.suspicion:.2f}, "
        f"signal={pattern.strongest_signal})"
    )


if __name__ == "__main__":
    main()
