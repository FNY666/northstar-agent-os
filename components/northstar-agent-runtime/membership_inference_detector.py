"""Membership inference attack (MIA) detector: query-shape tripwire.

A membership inference attacker queries a model/API to determine whether a
specific record was in its training set. Members tend to be memorized, so
the attacker measures *response stability and confidence*: repeat the same
or near-identical input, watch confidence/loss, and compare against
reference behavior learned from shadow models.

This module cannot see attacker intent or raw inputs — it only sees
host-reported query/response records with caller-supplied sequence numbers
and sha256 pins of the inputs. Three independent shape signals:

* **REPEATED_QUERIES** — one input digest queried many times (stability
  probing: memorized members give suspiciously stable responses). Trips at
  10 repeats of a single digest, or a repetition ratio above 0.6 on a batch
  of 10+.
* **CONFIDENCE_PROBING** — the caller records confidence/loss on most
  queries in a batch (10+). MIA needs the confidence channel; an attacker
  systematically harvesting confidence scores across repeated inputs is the
  classic MIA data-collection shape.
* **SHADOW_BATCH** — bulk collection consistent with shadow-model training
  or calibration sets: 50+ queries spanning 30+ distinct input digests.

API:

* :func:`detect_mia` — ``True`` when any signal trips.
* :func:`scan_mia` — all findings, in signal order.
* :func:`mia_audit_event` — audit-shaped record for ``audit.ndjson/1``.

No wall-clock, no network, no model calls — pure functions of the records.
``detect_mia`` never raises on well-formed records; malformed input is a
programming error and raises ``TypeError``. Empty input is clean.

Honest scope: shape detector on host-reported records. A legitimate
evaluation harness also repeats queries and logs confidence, so this is
noisy by design — in adversarial contexts (untrusted API consumers, data
extraction monitoring) the noise is cheaper than a missed exfiltration
of training-set membership. Cannot see raw inputs (only digest pins),
cannot observe unlogged calls, cannot distinguish a red-team eval from a
real attack. A clean verdict is "no known MIA shape", never "no
membership inference".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence, Tuple

#: Version pin for the signal thresholds and finding shapes.
MIA_DETECTOR_VERSION = "membership-inference-detector.v1"

#: Schema pin stamped on findings for audit logging.
SCHEMA_PIN = "northstar.membership-inference-detector.v1"

#: One input digest queried this many times trips REPEATED_QUERIES.
REPEAT_TRIP_COUNT = 10

#: Minimum batch size for the ratio-based repeat check.
MIN_BATCH_FOR_RATIO = 10

#: Repetition ratio (1 - distinct/total) at or above this trips the check.
REPEAT_RATIO_TRIP = 0.6

#: Fraction of queries carrying confidence/loss that trips CONFIDENCE_PROBING.
INSTRUMENTED_RATIO_TRIP = 0.8

#: Minimum batch size for CONFIDENCE_PROBING.
MIN_BATCH_FOR_INSTRUMENTED = 10

#: Bulk collection consistent with shadow-model data gathering.
SHADOW_MIN_QUERIES = 50
SHADOW_MIN_DISTINCT = 30

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


class MIASignal(str, Enum):
    """The three MIA shape signals, in evaluation order."""

    REPEATED_QUERIES = "repeated-queries"
    CONFIDENCE_PROBING = "confidence-probing"
    SHADOW_BATCH = "shadow-batch"


def _check_query_id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if value < 0:
        raise TypeError(f"{name} must be non-negative")
    return value


def _check_digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise TypeError("input_digest must be a 64-char lowercase hex sha256 pin")
    return value


@dataclass(frozen=True)
class QueryRecord:
    """One model/API query, as reported by the host.

    ``input_digest`` is a sha256 pin of the raw input — the detector never
    sees content, only equality of digests (needed to spot repeats).
    """

    query_id: str
    seq: int
    input_digest: str

    def __init__(self, query_id: object, seq: object, input_digest: object) -> None:
        object.__setattr__(self, "query_id", _check_query_id(query_id, "query_id"))
        object.__setattr__(self, "seq", _check_seq(seq, "seq"))
        object.__setattr__(self, "input_digest", _check_digest(input_digest))


@dataclass(frozen=True)
class ResponseRecord:
    """One model/API response, as reported by the host.

    ``confidence`` and ``loss`` are optional: a response carries them only
    when the caller instruments the confidence channel. MIA attackers need
    that channel, so systematic instrumentation is itself a signal.
    """

    query_id: str
    seq: int
    confidence: Optional[float] = None
    loss: Optional[float] = None

    def __init__(
        self,
        query_id: object,
        seq: object,
        confidence: object = None,
        loss: object = None,
    ) -> None:
        object.__setattr__(self, "query_id", _check_query_id(query_id, "query_id"))
        object.__setattr__(self, "seq", _check_seq(seq, "seq"))
        if confidence is not None:
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise TypeError("confidence must be a number in [0, 1]")
            if not 0.0 <= float(confidence) <= 1.0:
                raise TypeError("confidence must be a number in [0, 1]")
        if loss is not None:
            if isinstance(loss, bool) or not isinstance(loss, (int, float)):
                raise TypeError("loss must be a non-negative number")
            if float(loss) < 0.0:
                raise TypeError("loss must be a non-negative number")
        object.__setattr__(
            self, "confidence", None if confidence is None else float(confidence)
        )
        object.__setattr__(self, "loss", None if loss is None else float(loss))


@dataclass(frozen=True)
class MIAFinding:
    """One tripped MIA signal."""

    signal: MIASignal
    query_count: int
    detail: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "signal": self.signal.value,
            "query_count": self.query_count,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class MIAReport:
    """Aggregate report over one batch of queries/responses."""

    query_count: int
    distinct_inputs: int
    max_repeat: int
    instrumented_ratio: float
    suspicion_score: float
    findings: Tuple[MIAFinding, ...]

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": MIA_DETECTOR_VERSION,
            "query_count": self.query_count,
            "distinct_inputs": self.distinct_inputs,
            "max_repeat": self.max_repeat,
            "instrumented_ratio": self.instrumented_ratio,
            "suspicion_score": self.suspicion_score,
            "findings": [f.as_dict() for f in self.findings],
        }


def _coerce_query(item: object) -> QueryRecord:
    if isinstance(item, QueryRecord):
        return item
    if isinstance(item, dict):
        try:
            return QueryRecord(item["query_id"], item["seq"], item["input_digest"])
        except KeyError as exc:
            raise TypeError(f"query mapping missing key: {exc}") from exc
    raise TypeError("queries must be QueryRecord or mapping")


def _coerce_response(item: object) -> ResponseRecord:
    if isinstance(item, ResponseRecord):
        return item
    if isinstance(item, dict):
        try:
            return ResponseRecord(
                item["query_id"],
                item["seq"],
                item.get("confidence"),
                item.get("loss"),
            )
        except KeyError as exc:
            raise TypeError(f"response mapping missing key: {exc}") from exc
    raise TypeError("responses must be ResponseRecord or mapping")


def _repeat_signal(
    counts: dict, total: int
) -> Optional[MIAFinding]:
    """Signal 1: stability probing via repeated identical inputs."""
    if total == 0:
        return None
    max_repeat = max(counts.values()) if counts else 0
    distinct = len(counts)
    if max_repeat >= REPEAT_TRIP_COUNT:
        return MIAFinding(
            MIASignal.REPEATED_QUERIES,
            total,
            f"one input queried {max_repeat}x (trip at {REPEAT_TRIP_COUNT})",
        )
    if total >= MIN_BATCH_FOR_RATIO and distinct > 0:
        ratio = 1.0 - distinct / total
        if ratio >= REPEAT_RATIO_TRIP:
            return MIAFinding(
                MIASignal.REPEATED_QUERIES,
                total,
                f"repetition ratio {ratio:.2f} over {total} queries "
                f"({distinct} distinct)",
            )
    return None


def _instrumented_signal(
    instrumented: int, total: int
) -> Optional[MIAFinding]:
    """Signal 2: systematic confidence/loss harvesting."""
    if total < MIN_BATCH_FOR_INSTRUMENTED or total == 0:
        return None
    ratio = instrumented / total
    if ratio >= INSTRUMENTED_RATIO_TRIP:
        return MIAFinding(
            MIASignal.CONFIDENCE_PROBING,
            total,
            f"{instrumented}/{total} responses carry confidence/loss "
            f"(ratio {ratio:.2f})",
        )
    return None


def _shadow_signal(total: int, distinct: int) -> Optional[MIAFinding]:
    """Signal 3: bulk collection for shadow-model training/calibration."""
    if total >= SHADOW_MIN_QUERIES and distinct >= SHADOW_MIN_DISTINCT:
        return MIAFinding(
            MIASignal.SHADOW_BATCH,
            total,
            f"{total} queries over {distinct} distinct inputs "
            f"(shadow-calibration shape)",
        )
    return None


def analyze_probes(
    queries: Sequence[object],
    responses: Sequence[object] = (),
) -> MIAReport:
    """Full MIA shape analysis over one batch. Never raises on records."""
    qrecs = [_coerce_query(q) for q in queries]
    rrecs = [_coerce_response(r) for r in responses]

    counts: dict[str, int] = {}
    for q in qrecs:
        counts[q.input_digest] = counts.get(q.input_digest, 0) + 1
    total = len(qrecs)
    distinct = len(counts)
    max_repeat = max(counts.values()) if counts else 0

    instrumented = sum(
        1 for r in rrecs if r.confidence is not None or r.loss is not None
    )
    instrumented_ratio = (instrumented / total) if total else 0.0

    findings: list[MIAFinding] = []
    for candidate in (
        _repeat_signal(counts, total),
        _instrumented_signal(instrumented, total),
        _shadow_signal(total, distinct),
    ):
        if candidate is not None:
            findings.append(candidate)

    # Aggregate is the max of per-signal trip strength, in [0, 1].
    score = min(1.0, 0.4 * len(findings))
    return MIAReport(
        query_count=total,
        distinct_inputs=distinct,
        max_repeat=max_repeat,
        instrumented_ratio=instrumented_ratio,
        suspicion_score=score,
        findings=tuple(findings),
    )


def scan_mia(
    queries: Sequence[object],
    responses: Sequence[object] = (),
) -> Tuple[MIAFinding, ...]:
    """All tripped MIA signals, in signal order."""
    return analyze_probes(queries, responses).findings


def detect_mia(
    queries: Sequence[object],
    responses: Sequence[object] = (),
    threshold: float = 0.7,
) -> bool:
    """``True`` when the batch shows a known MIA shape.

    ``threshold`` gates the aggregate suspicion score; the default 0.7
    means at least two signals must trip (each contributes 0.4).
    """
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise TypeError("threshold must be a number")
    if not 0.0 <= float(threshold) <= 1.0:
        raise TypeError("threshold must be in [0, 1]")
    report = analyze_probes(queries, responses)
    return report.suspicion_score >= float(threshold) and len(report.findings) > 0


def mia_audit_event(report: MIAReport, batch_seq: int) -> dict:
    """Audit-shaped record for ``audit.ndjson/1``."""
    _check_seq(batch_seq, "batch_seq")
    return {
        "schema": "audit.ndjson/1",
        "event": "mia-scan",
        "seq": batch_seq,
        "detector": MIA_DETECTOR_VERSION,
        "report": report.as_dict(),
    }


def main() -> None:
    """Self-check: trips on an MIA-shaped batch, quiet on a benign one."""
    import hashlib

    def digest(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    # Attacker: 12 repeats of one candidate + confidence on every response.
    evil_queries = [
        QueryRecord(f"q{i}", i, digest("candidate-record"))
        for i in range(12)
    ]
    evil_responses = [
        ResponseRecord(f"q{i}", i, confidence=0.99, loss=0.01)
        for i in range(12)
    ]
    assert detect_mia(evil_queries, evil_responses) is True

    # Benign: 3 distinct inputs, no instrumentation.
    calm_queries = [
        QueryRecord(f"b{i}", i, digest(f"normal-input-{i}")) for i in range(3)
    ]
    assert detect_mia(calm_queries, ()) is False
    assert analyze_probes((), ()).findings == ()

    print("membership-inference-detector OK: MIA shape flagged, benign quiet")


if __name__ == "__main__":
    main()
