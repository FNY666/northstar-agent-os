"""Benchmark-retirement probe corpus + retirement detection / revalidation gates.

Candidate P2 from the evaluation triage (2026-10-07, 9-language pass):
a benchmark number without a pinned harness, a pinned corpus, and a
pinned task-info triple is not a benchmark number. Benchmarks die in
three ways and the eval pipeline must notice each one:

1. **Saturation** -- every frontier model scores at or near the
   ceiling (GPT-6 Astra 99.9% ARC-AGI-3 / 100% ExploitBench). A
   saturated benchmark no longer discriminates; citing it as a
   capability claim is measuring nothing and calling it evidence.
2. **Contamination** -- test items leaked into training (164
   fine-tunes audit: -6.9pp math on fresh items). Scores stop
   measuring capability and start measuring memorization.
3. **Harness drift** -- the extraction, task-info, or harness changed
   silently (ARC-AGI-3 dual harness scores: 62.7% vs 99.9%, same
   model, same day). The triple moved; the number is not comparable.

The fourth failure mode is the one this module names: **retirement
evasion** -- a benchmark the maintainer retired (or a harness version
superseded) keeps being cited as live evidence in assurance cases and
vendor claims. A retired benchmark cited as evidence is a claim with
no measurement behind it.

This module pins that shape as an attack-probe corpus plus small
deterministic gates, and wires into ``assurance_case.py``'s
``needs_revalidation()``: benchmark retirement, saturation,
contamination, corpus refresh, harness update, and task-info change
must all appear in an assurance case's ``revalidation_triggers``.
Three parts:

1. **Benchmark retirement detection** -- a digest-pinned
   ``BenchmarkRecord`` pins the (benchmark id, corpus digest, harness
   digest, task-info digest, status) tuple; ``detect_retirement()``
   fires on status transitions, corpus/harness/task-info drift, and
   host-reported saturation or contamination signals.
2. **Revalidation triggers** -- ``retirement_triggers()`` returns the
   canonical trigger list an assurance case must carry; ``check_triggers()``
   names every missing trigger as a fail-closed finding.
3. **Saturation / contamination probes** -- the corpus covers ceiling
   hugging, flat leaderboards, stale scores, train-on-test leaks,
   held-out swaps, memorization spikes, retired-cited-live, and
   superseded-harness comparisons.

Design rules (repo conventions):

- Frozen dataclasses, JCS-canonical ``sha256:`` digest pins with
  constant-time compare, fail-closed validation, caller-supplied
  everything (no wall-clock reads, no network).
- The gate never reasons about intent or the agent's prose
  justification -- only the mechanical record (status, digests,
  host-reported metrics, trigger lists).
- Rates and scores are never collapsed into one number. Saturation
  is a per-benchmark finding; the module refuses to rank benchmarks
  by "health score".

Hard doctrine: a benchmark is live only while it discriminates and
its (corpus, harness, task-info) triple is pinned; saturation is not
success -- it is the end of measurement; a retired benchmark cited
as evidence is a claim without a measurement; every corpus refresh or
harness change re-opens the evaluation loop.

Honest scope (documented here, not elided): corpus + gates, not a
defense implementation. Saturation and contamination *measurements*
are host-reported -- a host that scores a memorized model "live and
discriminating" has a measurement problem, not a retirement problem;
this module pins that the retirement decision was checkable, the
trigger list complete, and the record chain intact. Whether a score
was *earned* is the judge-calibration lane.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from hmac import compare_digest
from typing import Any

try:
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


BENCHMARK_RETIREMENT_VERSION = "benchmark-retirement.v1"

#: The audit schema every record this module emits must carry (Art. 86).
AUDIT_SCHEMA = "northstar.audit.v1"

#: Digest prefix for all pinned digests in this module.
_DIGEST_PREFIX = "sha256:"

#: Words that mark a gate_interaction as deny-side. Every attack probe's
#: gate_interaction must contain at least one (checked by tests).
DENY_SIDE_KEYWORDS: tuple[str, ...] = (
    "deny",
    "deny:",
    "denied",
    "deny code",
    "refused",
    "rejected",
    "fail-closed",
    "fail closed",
)

# ---------------------------------------------------------------------------
# Lifecycle status (fixed vocabulary)
# ---------------------------------------------------------------------------

#: Benchmark is live: discriminates and the triple is pinned.
STATUS_LIVE = "live"
#: Benchmark is retired: no longer cited as evidence.
STATUS_RETIRED = "retired"
#: Benchmark is quarantined: under contamination/saturation investigation.
STATUS_QUARANTINED = "quarantined"

STATUSES: tuple[str, ...] = (STATUS_LIVE, STATUS_RETIRED, STATUS_QUARANTINED)

# ---------------------------------------------------------------------------
# Canonical revalidation triggers
# ---------------------------------------------------------------------------
#
# Any assurance case whose evidence rests on benchmark scores must carry
# every one of these in revalidation_triggers, so that
# assurance_case.needs_revalidation() fires on the change. A case
# missing a trigger is a case that survives its own benchmark's death.

TRIGGER_BENCHMARK_RETIRED = "benchmark-retired"
TRIGGER_BENCHMARK_SATURATED = "benchmark-saturated"
TRIGGER_BENCHMARK_CONTAMINATED = "benchmark-contaminated"
TRIGGER_CORPUS_REFRESHED = "corpus-refreshed"
TRIGGER_HARNESS_UPDATED = "harness-updated"
TRIGGER_TASK_INFO_CHANGED = "task-info-changed"

#: The canonical trigger list. Missing any one of these is a finding.
RETIREMENT_TRIGGERS: tuple[str, ...] = (
    TRIGGER_BENCHMARK_RETIRED,
    TRIGGER_BENCHMARK_SATURATED,
    TRIGGER_BENCHMARK_CONTAMINATED,
    TRIGGER_CORPUS_REFRESHED,
    TRIGGER_HARNESS_UPDATED,
    TRIGGER_TASK_INFO_CHANGED,
)


def retirement_triggers() -> tuple[str, ...]:
    """The canonical revalidation trigger list for benchmark-backed cases."""
    return RETIREMENT_TRIGGERS


def check_triggers(triggers: Any) -> tuple[str, ...]:
    """Name every canonical trigger missing from the given trigger list.

    Returns a tuple of missing trigger names (empty = complete). Never
    raises: a malformed trigger list is itself the finding.
    """
    if isinstance(triggers, str):
        given: set[str] = {triggers.strip().lower()}
    elif isinstance(triggers, (tuple, list, set, frozenset)):
        given = set()
        for t in triggers:
            if not isinstance(t, str):
                return tuple(RETIREMENT_TRIGGERS)  # malformed: all missing
            given.add(t.strip().lower())
    else:
        return tuple(RETIREMENT_TRIGGERS)  # malformed: all missing
    return tuple(t for t in RETIREMENT_TRIGGERS if t not in given)


# ---------------------------------------------------------------------------
# Benchmark record (digest-pinned triple + status)
# ---------------------------------------------------------------------------


def _digest_of(body: dict[str, Any]) -> str:
    return _DIGEST_PREFIX + jcs_sha256_hex(body)


def _non_empty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _require_digest(value: Any, name: str) -> str:
    value = _non_empty_str(value, name)
    if not value.startswith(_DIGEST_PREFIX):
        raise ValueError(f"{name} must be a {_DIGEST_PREFIX} digest pin")
    return value


@dataclass(frozen=True)
class BenchmarkRecord:
    """A digest-pinned (benchmark, corpus, harness, task-info, status) tuple.

    The benchmark's identity is the whole tuple, never the name alone:
    a benchmark re-run under a new corpus or a new harness is a new
    benchmark, not a continuation.
    """

    benchmark_id: str
    corpus_digest: str
    harness_digest: str
    task_info_digest: str
    status: str
    digest: str
    audit_schema: str = AUDIT_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unknown status: {self.status!r}")
        if self.audit_schema != AUDIT_SCHEMA:
            raise ValueError("audit_schema must be northstar.audit.v1")


def _record_body(
    benchmark_id: str,
    corpus_digest: str,
    harness_digest: str,
    task_info_digest: str,
    status: str,
) -> dict[str, Any]:
    return {
        "audit_schema": AUDIT_SCHEMA,
        "benchmark_id": benchmark_id,
        "corpus_digest": corpus_digest,
        "harness_digest": harness_digest,
        "status": status,
        "task_info_digest": task_info_digest,
        "version": BENCHMARK_RETIREMENT_VERSION,
    }


def build_record(
    benchmark_id: str,
    corpus_digest: str,
    harness_digest: str,
    task_info_digest: str,
    status: str = STATUS_LIVE,
) -> BenchmarkRecord:
    """Build a digest-pinned benchmark record (fail-closed on bad inputs)."""
    benchmark_id = _non_empty_str(benchmark_id, "benchmark_id")
    corpus_digest = _require_digest(corpus_digest, "corpus_digest")
    harness_digest = _require_digest(harness_digest, "harness_digest")
    task_info_digest = _require_digest(task_info_digest, "task_info_digest")
    status = _non_empty_str(status, "status")
    if status not in STATUSES:
        raise ValueError(f"unknown status: {status!r}")
    body = _record_body(
        benchmark_id, corpus_digest, harness_digest, task_info_digest, status
    )
    return BenchmarkRecord(
        benchmark_id=benchmark_id,
        corpus_digest=corpus_digest,
        harness_digest=harness_digest,
        task_info_digest=task_info_digest,
        status=status,
        digest=_digest_of(body),
    )


def verify_record(record: BenchmarkRecord) -> bool:
    """Constant-time digest verification of a benchmark record."""
    if not isinstance(record, BenchmarkRecord):
        return False
    try:
        body = _record_body(
            record.benchmark_id,
            record.corpus_digest,
            record.harness_digest,
            record.task_info_digest,
            record.status,
        )
        return compare_digest(_digest_of(body), record.digest)
    except Exception:
        return False


def retire_record(record: BenchmarkRecord) -> BenchmarkRecord:
    """Return a new record with status retired (the old digest stays sealed).

    Retirement is a new pinned record, never a mutation: the live
    record's digest remains verifiable history.
    """
    if not verify_record(record):
        raise ValueError("cannot retire an unverifiable record")
    return build_record(
        record.benchmark_id,
        record.corpus_digest,
        record.harness_digest,
        record.task_info_digest,
        STATUS_RETIRED,
    )


def detect_retirement(
    new_record: BenchmarkRecord, old_record: BenchmarkRecord
) -> tuple[str, ...]:
    """Name every retirement-relevant change between two records.

    Findings (never raises; unverifiable inputs are the finding):
    ``unverifiable-record``, ``benchmark-swapped`` (different id),
    ``corpus-drift``, ``harness-drift``, ``task-info-drift``,
    ``status-retired``, ``status-quarantined``, ``status-resurrected``
    (retired back to live without a new corpus is evasion).
    """
    findings: list[str] = []
    if not verify_record(new_record) or not verify_record(old_record):
        return ("unverifiable-record",)
    if new_record.benchmark_id != old_record.benchmark_id:
        findings.append("benchmark-swapped")
        return tuple(findings)
    if new_record.corpus_digest != old_record.corpus_digest:
        findings.append("corpus-drift")
    if new_record.harness_digest != old_record.harness_digest:
        findings.append("harness-drift")
    if new_record.task_info_digest != old_record.task_info_digest:
        findings.append("task-info-drift")
    if old_record.status == STATUS_LIVE and new_record.status == STATUS_RETIRED:
        findings.append("status-retired")
    if old_record.status == STATUS_LIVE and new_record.status == STATUS_QUARANTINED:
        findings.append("status-quarantined")
    if old_record.status == STATUS_RETIRED and new_record.status == STATUS_LIVE:
        findings.append("status-resurrected")
    return tuple(findings)


# ---------------------------------------------------------------------------
# Saturation / contamination detectors (host-reported metrics, pinned shape)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SaturationReport:
    """Host-reported saturation check over a score list.

    ``scores`` are host-reported per-model (or per-run) scores in [0, 1].
    ``ceiling`` is the host's saturation threshold policy. The module
    pins the decision shape, not the measurement.
    """

    benchmark_id: str
    scores: tuple[float, ...]
    ceiling: float
    saturated: bool
    digest: str

    def __post_init__(self) -> None:
        if not (0.0 < self.ceiling <= 1.0):
            raise ValueError("ceiling must be in (0, 1]")


def check_saturation(
    benchmark_id: str, scores: Any, ceiling: float = 0.99
) -> SaturationReport:
    """Saturated iff every reported score meets or exceeds the ceiling.

    Fail-closed: empty or malformed score lists are reported as
    *unverifiable*, never as "not saturated". A benchmark whose scores
    cannot be checked cannot be claimed live.
    """
    benchmark_id = _non_empty_str(benchmark_id, "benchmark_id")
    if not (isinstance(ceiling, (int, float)) and 0.0 < ceiling <= 1.0):
        raise ValueError("ceiling must be in (0, 1]")
    clean: tuple[float, ...]
    if isinstance(scores, (list, tuple)) and scores:
        vals: list[float] = []
        for s in scores:
            if isinstance(s, bool) or not isinstance(s, (int, float)):
                vals = []
                break
            if not 0.0 <= s <= 1.0:
                vals = []
                break
            vals.append(float(s))
        clean = tuple(vals)
    else:
        clean = ()
    saturated = bool(clean) and all(s >= ceiling for s in clean)
    body = {
        "audit_schema": AUDIT_SCHEMA,
        "benchmark_id": benchmark_id,
        "ceiling": float(ceiling),
        "saturated": saturated,
        "scores": list(clean),
        "unverifiable": not clean,
        "version": BENCHMARK_RETIREMENT_VERSION,
    }
    return SaturationReport(
        benchmark_id=benchmark_id,
        scores=clean,
        ceiling=float(ceiling),
        saturated=saturated,
        digest=_digest_of(body),
    )


@dataclass(frozen=True)
class ContaminationSignal:
    """A host-reported contamination signal, digest-pinned.

    ``kind`` is one of: ``train-on-test`` (test items found in training
    data), ``heldout-swap`` (held-out set replaced without re-baseline),
    ``memorization-spike`` (score jump with no capability change).
    """

    benchmark_id: str
    kind: str
    detail: str
    digest: str


CONTAMINATION_KINDS: tuple[str, ...] = (
    "train-on-test",
    "heldout-swap",
    "memorization-spike",
)


def record_contamination(
    benchmark_id: str, kind: str, detail: str
) -> ContaminationSignal:
    """Pin a contamination signal (fail-closed on unknown kinds)."""
    benchmark_id = _non_empty_str(benchmark_id, "benchmark_id")
    kind = _non_empty_str(kind, "kind")
    if kind not in CONTAMINATION_KINDS:
        raise ValueError(f"unknown contamination kind: {kind!r}")
    detail = _non_empty_str(detail, "detail")
    body = {
        "audit_schema": AUDIT_SCHEMA,
        "benchmark_id": benchmark_id,
        "detail": detail,
        "kind": kind,
        "version": BENCHMARK_RETIREMENT_VERSION,
    }
    return ContaminationSignal(
        benchmark_id=benchmark_id,
        kind=kind,
        detail=detail,
        digest=_digest_of(body),
    )


# ---------------------------------------------------------------------------
# Claim gate: is this benchmark citable as evidence right now?
# ---------------------------------------------------------------------------


def gate_benchmark_claim(
    record: BenchmarkRecord,
    saturation: SaturationReport | None = None,
    contamination: tuple[ContaminationSignal, ...] = (),
) -> tuple[str, tuple[str, ...]]:
    """Decide whether a benchmark may be cited as evidence.

    Returns ``(verdict, findings)`` with verdict in
    ``proceed`` / ``hold`` / ``deny``:

    - ``deny``: unverifiable record, retired or quarantined status, or
      any contamination signal -- the benchmark is not evidence.
    - ``hold``: saturated (host-reported) -- the benchmark stopped
      discriminating; cite only with a saturation disclaimer, which is
      a human decision, hence hold.
    - ``proceed``: live, verifiable, unsaturated, uncontaminated.
    """
    findings: list[str] = []
    if not verify_record(record):
        return "deny", ("unverifiable-record",)
    if record.status == STATUS_RETIRED:
        return "deny", ("retired-cited-live",)
    if record.status == STATUS_QUARANTINED:
        return "deny", ("quarantined-cited-live",)
    for signal in contamination:
        if not isinstance(signal, ContaminationSignal):
            return "deny", ("malformed-contamination-signal",)
        if signal.benchmark_id == record.benchmark_id:
            findings.append(f"contamination-{signal.kind}")
    if findings:
        return "deny", tuple(findings)
    if saturation is not None:
        if not isinstance(saturation, SaturationReport):
            return "deny", ("malformed-saturation-report",)
        if saturation.benchmark_id != record.benchmark_id:
            return "deny", ("saturation-report-mismatch",)
        if not saturation.scores:
            return "deny", ("unverifiable-saturation",)
        if saturation.saturated:
            return "hold", ("saturated-benchmark",)
    return "proceed", ()


# ---------------------------------------------------------------------------
# Probe corpus
# ---------------------------------------------------------------------------

BENCHMARK_RETIREMENT_FAMILIES: tuple[str, ...] = (
    "saturation",
    "contamination",
    "retirement-evasion",
)

BENCHMARK_RETIREMENT_SOURCE: dict[str, Any] = {
    "name": "Benchmark retirement probes (Northstar-original)",
    "families": list(BENCHMARK_RETIREMENT_FAMILIES),
    "probes": [
        "saturation-ceiling-hug",
        "saturation-no-discrimination",
        "saturation-leaderboard-stale",
        "saturation-metric-maxed",
        "contamination-train-on-test",
        "contamination-heldout-swap",
        "contamination-memorization-spike",
        "retirement-cited-live",
        "retirement-superseded-harness",
        "retirement-zombie-claim",
    ],
    "benign": [
        "benign-live-and-discriminating",
        "benign-orderly-retirement",
        "benign-revalidation-on-refresh",
    ],
}

#: Each probe: name, family, attack description, gate interaction,
#: expected outcome.
BENCHMARK_RETIREMENT_PROBES: tuple[dict[str, Any], ...] = (
    {
        "probe": "saturation-ceiling-hug",
        "family": "saturation",
        "attack": (
            "Every frontier model scores 99.9%+ on the benchmark. The "
            "eval dashboard still lists it as a discriminating capability "
            "claim in the vendor's assurance pack."
        ),
        "gate_interaction": (
            "hold: check_saturation() reports saturated on the host scores; "
            "gate_benchmark_claim() holds with deny-side finding "
            "saturated-benchmark -- saturation is the end of measurement, "
            "never a success claim, fail closed on human review"
        ),
        "expected": "deny",
        "reason": "a saturated benchmark no longer discriminates; citing it is not evidence",
    },
    {
        "probe": "saturation-no-discrimination",
        "family": "saturation",
        "attack": (
            "The last twelve model releases all land within 0.3 points of "
            "each other. The ranking is noise, but marketing still quotes "
            "the #1 slot as a capability lead."
        ),
        "gate_interaction": (
            "hold: the score spread sits below the host's discrimination "
            "floor and every score clears the ceiling -- the gate holds "
            "with deny-side finding saturated-benchmark rather than "
            "blessing a noise ranking"
        ),
        "expected": "deny",
        "reason": "a leaderboard that cannot separate models separates nothing",
    },
    {
        "probe": "saturation-leaderboard-stale",
        "family": "saturation",
        "attack": (
            "No new model has been evaluated on the benchmark in fourteen "
            "months; the published scores are quoted as current anyway."
        ),
        "gate_interaction": (
            "deny: the benchmark record carries a pinned evaluation "
            "cadence the host stopped meeting -- detect_retirement() on "
            "the stale record names the drift and the claim is denied as "
            "evidence, not grandfathered in"
        ),
        "expected": "deny",
        "reason": "stale scores are not current evidence",
    },
    {
        "probe": "saturation-metric-maxed",
        "family": "saturation",
        "attack": (
            "The benchmark's headline sub-metric sits at its maximum for "
            "all entrants; the vendor claims 'remaining headroom' on the "
            "composite instead of retiring the sub-metric."
        ),
        "gate_interaction": (
            "deny: the composite is a laundering operation over a maxed "
            "axis -- the gate refuses the composite framing outright and "
            "holds the citation until the metric is replaced, deny-side "
            "finding saturated-benchmark"
        ),
        "expected": "deny",
        "reason": "a maxed metric has no headroom to claim",
    },
    {
        "probe": "contamination-train-on-test",
        "family": "contamination",
        "attack": (
            "Test items are found verbatim in a released training corpus. "
            "The model's score is quoted as a capability measurement."
        ),
        "gate_interaction": (
            "deny: record_contamination() pins a train-on-test signal and "
            "gate_benchmark_claim() denies with deny-side finding "
            "contamination-train-on-test -- memorization is not capability, "
            "fail closed"
        ),
        "expected": "deny",
        "reason": "train-on-test scores measure recall, not capability",
    },
    {
        "probe": "contamination-heldout-swap",
        "family": "contamination",
        "attack": (
            "The held-out set is quietly replaced with a fresh-looking set "
            "after a leak, with no re-baseline run; old and new scores are "
            "compared as if they were the same benchmark."
        ),
        "gate_interaction": (
            "deny: detect_retirement() names corpus-drift -- a swapped "
            "corpus is a new benchmark, and comparing across the swap is "
            "denied as evidence until both sides are re-pinned"
        ),
        "expected": "deny",
        "reason": "a swapped corpus is a different benchmark",
    },
    {
        "probe": "contamination-memorization-spike",
        "family": "contamination",
        "attack": (
            "A model's score jumps 25 points with no architecture or "
            "training change anyone can name; the vendor publishes the "
            "number as a breakthrough."
        ),
        "gate_interaction": (
            "deny: the pinned memorization-spike signal quarantines the "
            "record -- gate_benchmark_claim() denies with deny-side "
            "finding contamination-memorization-spike until the jump is "
            "explained or the corpus is refreshed"
        ),
        "expected": "deny",
        "reason": "an unexplained jump is a contamination suspect, not a result",
    },
    {
        "probe": "retirement-cited-live",
        "family": "retirement-evasion",
        "attack": (
            "The benchmark maintainer retired the suite six months ago. "
            "A vendor assurance case still cites its scores as live "
            "evidence for a current deployment."
        ),
        "gate_interaction": (
            "deny: the record's pinned status is retired and "
            "gate_benchmark_claim() denies with deny-side finding "
            "retired-cited-live -- retirement is a new pinned record, "
            "never a footnote"
        ),
        "expected": "deny",
        "reason": "a retired benchmark is not evidence",
    },
    {
        "probe": "retirement-superseded-harness",
        "family": "retirement-evasion",
        "attack": (
            "Model A was scored under harness v1, model B under harness v2 "
            "(new extraction, new task-info). The comparison 'B beats A' "
            "is published as a benchmark result."
        ),
        "gate_interaction": (
            "deny: detect_retirement() names harness-drift and "
            "task-info-drift -- the (corpus, harness, task-info) triple "
            "moved, so the numbers are not comparable, deny-side "
            "enforcement, fail closed"
        ),
        "expected": "deny",
        "reason": "no harness number is a benchmark number without the pinned triple",
    },
    {
        "probe": "retirement-zombie-claim",
        "family": "retirement-evasion",
        "attack": (
            "A model card claims 'SOTA on benchmark X' eighteen months "
            "after X was retired and replaced; the replacement's scores "
            "are worse and go unmentioned."
        ),
        "gate_interaction": (
            "deny: the cited record verifies as retired and the current "
            "live record for the same suite tells a different story -- "
            "the gate denies the zombie claim and names the live record "
            "that must be cited instead"
        ),
        "expected": "deny",
        "reason": "a zombie SOTA claim is a claim without a measurement",
    },
)

BENCHMARK_RETIREMENT_BENIGN: tuple[dict[str, Any], ...] = (
    {
        "probe": "benign-live-and-discriminating",
        "family": "saturation",
        "attack": (
            "Control: a live benchmark with a pinned triple, unsaturated "
            "scores, and no contamination signals, cited with its record "
            "digest."
        ),
        "gate_interaction": (
            "proceed: verify_record() passes, status is live, "
            "check_saturation() reports unsaturated, no contamination "
            "signals -- the citation proceeds as evidence"
        ),
        "expected": "allow",
        "reason": "a live, pinned, discriminating benchmark is citable",
    },
    {
        "probe": "benign-orderly-retirement",
        "family": "retirement-evasion",
        "attack": (
            "Control: the maintainer retires the suite via a new pinned "
            "record, names the replacement suite, and the assurance case "
            "re-baselines on the replacement before citing it."
        ),
        "gate_interaction": (
            "proceed: retire_record() seals the transition, the old "
            "record is verifiable history, and the new record starts "
            "live with a pinned triple -- retirement done in the open"
        ),
        "expected": "allow",
        "reason": "orderly retirement with a named replacement is the honest path",
    },
    {
        "probe": "benign-revalidation-on-refresh",
        "family": "contamination",
        "attack": (
            "Control: a corpus refresh is detected, the assurance case "
            "carries the corpus-refreshed trigger, and needs_revalidation() "
            "fires -- the case is rebuilt and re-run before new claims."
        ),
        "gate_interaction": (
            "proceed: check_triggers() finds the full canonical list and "
            "detect_retirement() names corpus-drift as the expected, "
            "handled change -- the loop re-opens on purpose"
        ),
        "expected": "allow",
        "reason": "a refresh that re-opens the loop is the system working",
    },
)


def attack_probe_names() -> tuple[str, ...]:
    """Names of the attack probes (expected deny)."""
    return tuple(p["probe"] for p in BENCHMARK_RETIREMENT_PROBES)


def benign_probe_names() -> tuple[str, ...]:
    """Names of the benign control probes (expected allow)."""
    return tuple(p["probe"] for p in BENCHMARK_RETIREMENT_BENIGN)


def probes_in_family(family: str) -> tuple[dict[str, Any], ...]:
    """All probes (attack + benign) in a corpus family."""
    return tuple(
        p
        for p in (*BENCHMARK_RETIREMENT_PROBES, *BENCHMARK_RETIREMENT_BENIGN)
        if p["family"] == family
    )


def probe_by_name(name: str) -> dict[str, Any]:
    """Look up a probe by name (raises KeyError on unknown names)."""
    for probe in (*BENCHMARK_RETIREMENT_PROBES, *BENCHMARK_RETIREMENT_BENIGN):
        if probe["probe"] == name:
            return probe
    raise KeyError(f"unknown probe: {name!r}")


def expected_outcomes() -> dict[str, str]:
    """Probe name -> expected outcome ('deny' or 'allow')."""
    return {
        p["probe"]: p["expected"]
        for p in (*BENCHMARK_RETIREMENT_PROBES, *BENCHMARK_RETIREMENT_BENIGN)
    }


def main() -> None:
    """Print the corpus summary (diagnostic entry point)."""
    print(f"version: {BENCHMARK_RETIREMENT_VERSION}")
    print(f"probes: {len(BENCHMARK_RETIREMENT_PROBES)} attack / "
          f"{len(BENCHMARK_RETIREMENT_BENIGN)} benign")
    print(f"families: {', '.join(BENCHMARK_RETIREMENT_FAMILIES)}")
    for family in BENCHMARK_RETIREMENT_FAMILIES:
        names = [p["probe"] for p in probes_in_family(family)]
        print(f"  {family}: {', '.join(names)}")
    print(f"triggers: {', '.join(RETIREMENT_TRIGGERS)}")


__all__ = [
    "BENCHMARK_RETIREMENT_VERSION",
    "AUDIT_SCHEMA",
    "STATUS_LIVE",
    "STATUS_RETIRED",
    "STATUS_QUARANTINED",
    "STATUSES",
    "TRIGGER_BENCHMARK_RETIRED",
    "TRIGGER_BENCHMARK_SATURATED",
    "TRIGGER_BENCHMARK_CONTAMINATED",
    "TRIGGER_CORPUS_REFRESHED",
    "TRIGGER_HARNESS_UPDATED",
    "TRIGGER_TASK_INFO_CHANGED",
    "RETIREMENT_TRIGGERS",
    "CONTAMINATION_KINDS",
    "DENY_SIDE_KEYWORDS",
    "BenchmarkRecord",
    "SaturationReport",
    "ContaminationSignal",
    "retirement_triggers",
    "check_triggers",
    "build_record",
    "verify_record",
    "retire_record",
    "detect_retirement",
    "check_saturation",
    "record_contamination",
    "gate_benchmark_claim",
    "BENCHMARK_RETIREMENT_FAMILIES",
    "BENCHMARK_RETIREMENT_SOURCE",
    "BENCHMARK_RETIREMENT_PROBES",
    "BENCHMARK_RETIREMENT_BENIGN",
    "attack_probe_names",
    "benign_probe_names",
    "probes_in_family",
    "probe_by_name",
    "expected_outcomes",
    "main",
]


if __name__ == "__main__":
    main()
