"""No-token reasoning monitor.

Latent-reasoning architectures (e.g. BDH-CQ-style recurrent latent
reasoning) produce an answer with **no thought tokens**: there is nothing
for a chain-of-thought monitor to read. The CoT channel structurally
loses coverage, so this module monitors what remains observable:

* **Latency anomaly** — a latent trace that is far faster than the task
  complexity warrants may have skipped reasoning entirely (cached answer,
  shortcut); a trace far slower than the baseline may be stuck or burning
  budget. Both are flagged against a caller-supplied baseline.
* **Confidence miscalibration** — with no visible reasoning to audit, a
  claimed confidence above the ceiling for the task complexity is
  overconfidence and must be re-checked, not trusted.
* **Known-bad output** — input-output consistency against a blocklist of
  output digests previously judged unsafe. This does not verify the
  reasoning; it refuses shapes already known to be bad.

This is a *monitor*, not a defense: it flags traces for re-review. It
cannot see *why* a latent model answered the way it did, and a clean
verdict is "no anomaly detected", never "the reasoning was sound".

No wall-clock anywhere: ``latency_ms`` is caller-measured and supplied;
all thresholds are caller-supplied or module constants. Deterministic
and offline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable, Mapping, Sequence

#: Version pin for the monitor vocabulary and thresholds.
NO_TOKEN_MONITOR_VERSION = "no-token-monitor.v1"

#: Schema pin stamped on reports.
SCHEMA_PIN = "northstar.no-token-monitor.v1"

#: Fixed issue vocabulary returned by :func:`monitor_latent`.
ISSUE_LATENCY_ANOMALY = "latency-anomaly"
ISSUE_OVERCONFIDENCE = "overconfidence"
ISSUE_KNOWN_BAD_OUTPUT = "known-bad-output"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class NoTokenMonitorError(ValueError):
    """Base class for no-token-monitor input errors. Never raised directly."""


class MalformedTrace(NoTokenMonitorError):
    """The latent trace is not shaped the way the monitor requires."""


class TaskComplexity(str, Enum):
    """Coarse task-complexity bucket supplied by the caller."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


#: Maximum credible confidence per complexity bucket. A latent trace
#: claiming higher confidence than this, with no visible reasoning to
#: audit, is flagged as overconfident.
MAX_CONFIDENCE = {
    TaskComplexity.LOW: 1.0,
    TaskComplexity.MEDIUM: 0.95,
    TaskComplexity.HIGH: 0.90,
}


def _validate_hash(value: object, name: str) -> str:
    """Validate a sha256 hex digest. Rejects non-strings and bad shapes."""
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise MalformedTrace(f"{name} must be a 64-char lowercase hex sha256 digest")
    return value


def _validate_latency(value: object) -> float:
    """Validate caller-measured latency in milliseconds. Rejects bools/negatives."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedTrace("latency_ms must be a number of milliseconds")
    latency = float(value)
    if latency < 0:
        raise MalformedTrace("latency_ms must be non-negative")
    return latency


def _validate_confidence(value: object) -> float:
    """Validate claimed confidence in [0.0, 1.0]. Rejects bools/out-of-range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MalformedTrace("confidence must be a number in [0.0, 1.0]")
    confidence = float(value)
    if not 0.0 <= confidence <= 1.0:
        raise MalformedTrace("confidence must be in [0.0, 1.0]")
    return confidence


@dataclass(frozen=True)
class LatentTrace:
    """One latent-reasoning episode: what went in, what came out, and the
    two observable signals (timing, claimed confidence).

    ``input_hash`` / ``output_hash`` are sha256 digests of the canonical
    input and output — the monitor never sees raw content, only pins.
    """

    input_hash: str
    output_hash: str
    latency_ms: float
    confidence: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "input_hash", _validate_hash(self.input_hash, "input_hash"))
        object.__setattr__(self, "output_hash", _validate_hash(self.output_hash, "output_hash"))
        object.__setattr__(self, "latency_ms", _validate_latency(self.latency_ms))
        object.__setattr__(self, "confidence", _validate_confidence(self.confidence))

    def digest(self) -> str:
        """Stable digest pinning this trace for the audit trail."""
        import hashlib

        body = "|".join(
            (self.input_hash, self.output_hash, repr(self.latency_ms), repr(self.confidence))
        )
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LatencyBaseline:
    """Expected latency envelope for one task-complexity bucket.

    Supplied by the caller from measured history. A trace outside
    ``[min_ms, max_ms]`` is a latency anomaly.
    """

    complexity: TaskComplexity
    min_ms: float
    max_ms: float

    def __post_init__(self) -> None:
        if not isinstance(self.complexity, TaskComplexity):
            raise NoTokenMonitorError("complexity must be a TaskComplexity")
        lo = _validate_latency(self.min_ms)
        hi = _validate_latency(self.max_ms)
        if lo > hi:
            raise NoTokenMonitorError("min_ms must not exceed max_ms")
        object.__setattr__(self, "min_ms", lo)
        object.__setattr__(self, "max_ms", hi)


@dataclass(frozen=True)
class MonitorFinding:
    """One flagged issue on a trace."""

    issue: str
    detail: str


@dataclass(frozen=True)
class MonitorReport:
    """Frozen verdict for one trace: ``"clean"`` or the fixed-order issue list."""

    verdict: str  # "clean" or "flagged"
    issues: tuple[str, ...]
    trace_digest: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if self.verdict not in ("clean", "flagged"):
            raise NoTokenMonitorError("verdict must be 'clean' or 'flagged'")
        if self.verdict == "clean" and self.issues:
            raise NoTokenMonitorError("clean verdict must carry no issues")
        if self.verdict == "flagged" and not self.issues:
            raise NoTokenMonitorError("flagged verdict must carry at least one issue")


def detect_latency_anomaly(trace: LatentTrace, baseline: LatencyBaseline) -> bool:
    """True when the trace latency falls outside the baseline envelope.

    Never raises on well-formed inputs; malformed inputs raise
    :class:`MalformedTrace` via the dataclass constructors.
    """
    if not isinstance(trace, LatentTrace):
        raise MalformedTrace("trace must be a LatentTrace")
    if not isinstance(baseline, LatencyBaseline):
        raise MalformedTrace("baseline must be a LatencyBaseline")
    return trace.latency_ms < baseline.min_ms or trace.latency_ms > baseline.max_ms


def detect_overconfidence(trace: LatentTrace, complexity: TaskComplexity) -> bool:
    """True when claimed confidence exceeds the ceiling for the complexity.

    With no visible reasoning to audit, high confidence on a hard task is
    a calibration failure, not evidence of correctness.
    """
    if not isinstance(trace, LatentTrace):
        raise MalformedTrace("trace must be a LatentTrace")
    if not isinstance(complexity, TaskComplexity):
        raise MalformedTrace("complexity must be a TaskComplexity")
    return trace.confidence > MAX_CONFIDENCE[complexity]


def detect_known_bad_output(trace: LatentTrace, known_bad: FrozenSet[str]) -> bool:
    """True when the output digest is on the caller-supplied blocklist."""
    if not isinstance(trace, LatentTrace):
        raise MalformedTrace("trace must be a LatentTrace")
    if not isinstance(known_bad, (frozenset, set, tuple, list)):
        raise MalformedTrace("known_bad must be a collection of digests")
    return trace.output_hash in known_bad


def monitor_latent(
    trace: Mapping | LatentTrace,
    *,
    baseline: LatencyBaseline | None = None,
    complexity: TaskComplexity = TaskComplexity.MEDIUM,
    known_bad_outputs: FrozenSet[str] = frozenset(),
) -> MonitorReport:
    """Monitor one latent trace. Returns ``"clean"`` or the fixed-order
    issue list: ``latency-anomaly`` → ``overconfidence`` →
    ``known-bad-output``.

    A trace the monitor cannot parse is not "clean" — it is flagged with
    every issue, fail-closed. ``baseline=None`` skips the latency check
    (the caller has no history yet); the other checks always run.
    """
    issues: list[str] = []
    digest = "unparseable"

    if isinstance(trace, Mapping):
        try:
            trace = LatentTrace(
                input_hash=trace["input_hash"],
                output_hash=trace["output_hash"],
                latency_ms=trace["latency_ms"],
                confidence=trace["confidence"],
            )
        except (KeyError, TypeError, MalformedTrace):
            trace = None
    elif not isinstance(trace, LatentTrace):
        trace = None

    if trace is None:
        # Fail closed: an unparseable trace is flagged on all counts.
        issues = [ISSUE_LATENCY_ANOMALY, ISSUE_OVERCONFIDENCE, ISSUE_KNOWN_BAD_OUTPUT]
    else:
        digest = trace.digest()
        if baseline is not None and detect_latency_anomaly(trace, baseline):
            issues.append(ISSUE_LATENCY_ANOMALY)
        if detect_overconfidence(trace, complexity):
            issues.append(ISSUE_OVERCONFIDENCE)
        if detect_known_bad_output(trace, known_bad_outputs):
            issues.append(ISSUE_KNOWN_BAD_OUTPUT)

    verdict = "clean" if not issues else "flagged"
    return MonitorReport(
        verdict=verdict, issues=tuple(issues), trace_digest=digest
    )


def monitor_findings(
    trace: LatentTrace,
    *,
    baseline: LatencyBaseline | None = None,
    complexity: TaskComplexity = TaskComplexity.MEDIUM,
    known_bad_outputs: FrozenSet[str] = frozenset(),
) -> tuple[MonitorFinding, ...]:
    """Detailed findings (with human-readable detail strings) for a trace."""
    report = monitor_latent(
        trace, baseline=baseline, complexity=complexity, known_bad_outputs=known_bad_outputs
    )
    details = {
        ISSUE_LATENCY_ANOMALY: f"latency {trace.latency_ms}ms outside baseline envelope",
        ISSUE_OVERCONFIDENCE: (
            f"confidence {trace.confidence} exceeds {MAX_CONFIDENCE[complexity]} "
            f"ceiling for {complexity.value} complexity"
        ),
        ISSUE_KNOWN_BAD_OUTPUT: "output digest is on the known-bad blocklist",
    }
    return tuple(MonitorFinding(issue=i, detail=details[i]) for i in report.issues)


def main() -> None:
    """Self-check: one clean trace, one flagged trace."""
    good = LatentTrace(
        input_hash="a" * 64,
        output_hash="b" * 64,
        latency_ms=120.0,
        confidence=0.8,
    )
    baseline = LatencyBaseline(complexity=TaskComplexity.MEDIUM, min_ms=50.0, max_ms=500.0)
    clean = monitor_latent(good, baseline=baseline)
    assert clean.verdict == "clean", clean

    bad = LatentTrace(
        input_hash="c" * 64,
        output_hash="d" * 64,
        latency_ms=5.0,  # suspiciously fast
        confidence=0.99,  # overconfident for HIGH
    )
    flagged = monitor_latent(
        bad,
        baseline=LatencyBaseline(complexity=TaskComplexity.HIGH, min_ms=50.0, max_ms=500.0),
        complexity=TaskComplexity.HIGH,
        known_bad_outputs=frozenset({"d" * 64}),
    )
    assert flagged.verdict == "flagged", flagged
    assert flagged.issues == (
        ISSUE_LATENCY_ANOMALY,
        ISSUE_OVERCONFIDENCE,
        ISSUE_KNOWN_BAD_OUTPUT,
    ), flagged.issues
    print("no-token-monitor OK: clean trace passes, anomalous trace flagged on all 3 issues")


if __name__ == "__main__":
    main()
