"""CI pipeline: GitHub-Actions-style stage/job bookkeeping.

Research note: GitHub Actions (the dominant CI for this ecosystem) models a
workflow as *jobs* — each job runs on a declared ``runs-on`` label, may
declare ``needs:`` dependencies on other jobs, and produces *artifacts*
(content-addressed blobs pinned by digest). The load-bearing semantics are
not the shell commands — they are the *dependency discipline*:

* **define** — a pipeline registers a named set of jobs. ``needs`` edges
  form a DAG (cycles rejected at definition time, not at 03:00 when the
  nightly run deadlocks); topological order is deterministic (Kahn's with
  sorted tie-breaks) so two identical definitions replay identically.
* **run** — the host executes jobs (elsewhere) and reports per-job
  outcomes; this module applies the GitHub *skip* rule: a job whose
  dependency failed is marked ``skipped`` and every downstream job of a
  skipped job is skipped too — a failed job never silently passes its
  dependents on. Jobs never reached need no reported outcome; jobs reached
  without a reported outcome are refused fail-closed.
* **artifact** — a host pins an artifact (name + ``sha256:`` digest) to a
  job of a completed run. Artifacts attach only to *successful* jobs:
  attaching build output to a failed job is a provenance lie, so it is
  refused. The module pins digests, never stores bytes (it cannot prove
  the bytes match — a registered artifact is a claim, not a verified fact).

* **No wall-clock** — every mutation takes a caller-supplied int ``seq``,
  so a run is exactly replayable from the audit trail.
* **Fail-closed** — empty names, bool seqs, unknown jobs, unreported
  outcomes, cycles, and duplicate definitions all raise instead of
  silently succeeding.

Honest scope: this is *pipeline bookkeeping*, not a CI runner — it never
executes commands, has no network, no timers, and cannot prove a reported
``success`` outcome was truthfully earned. A ``RunReport`` says "the host
reported this DAG ran this way", never "the tests really passed".
Outcomes are pinned by digest; attach this module's audit events to the
durable audit writer for crash recovery.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
CI_PIPELINE_VERSION = "ci-pipeline.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ci-pipeline.v1"

#: Integers beyond this magnitude are refused: the JCS float-loss caveat
#: found in batch 5 (``canonical_json`` silently pins colliding digests for
#: ints that lose precision when decoded as IEEE-754 doubles).
_MAX_SAFE_INT = 2 ** 53

#: Job lifecycle states recorded in a run report.
JOB_QUEUED = "queued"
JOB_SUCCESS = "success"
JOB_FAILED = "failed"
JOB_SKIPPED = "skipped"

_AUDIT_KINDS = frozenset({
    "defined",
    "run-completed",
    "job-succeeded",
    "job-failed",
    "job-skipped",
    "artifact-attached",
    "rejected",
})


class CIPipelineError(Exception):
    """Base class for all ci-pipeline errors."""


class DefinitionError(CIPipelineError):
    """A pipeline definition was invalid (programming error)."""


class CycleError(DefinitionError):
    """Job ``needs`` edges form a cycle."""


class UnknownJobError(CIPipelineError):
    """A job id is not part of this pipeline."""


class OutcomeError(CIPipelineError):
    """Reported run outcomes were inconsistent with the pipeline."""


class ArtifactError(CIPipelineError):
    """An artifact attachment was refused."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise CIPipelineError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise CIPipelineError(f"seq must be >= 0, got {seq}")
    return seq


def _check_name(name: Any, what: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise CIPipelineError(f"{what} must be a non-empty str")
    return name


def _digest(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


def _topo_sort(job_ids: Sequence[str], needs: Mapping[str, tuple]) -> tuple:
    """Kahn's algorithm with sorted tie-breaks; raises CycleError on cycles."""
    indegree = {j: 0 for j in job_ids}
    children: dict[str, list] = {j: [] for j in job_ids}
    for job in job_ids:
        for dep in needs[job]:
            children[dep].append(job)
            indegree[job] += 1
    ready = sorted(j for j in job_ids if indegree[j] == 0)
    order: list[str] = []
    while ready:
        job = ready.pop(0)
        order.append(job)
        for child in sorted(children[job]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
        ready.sort()
    if len(order) != len(job_ids):
        raise CycleError("job needs edges contain a cycle")
    return tuple(order)


@dataclass(frozen=True)
class JobSpec:
    """One frozen job declaration inside a pipeline definition."""
    job_id: str
    runs_on: str
    needs: tuple
    digest: str
    version: str = CI_PIPELINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "runs_on": self.runs_on,
            "needs": list(self.needs),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PipelineDefinition:
    """A frozen, validated pipeline definition."""
    pipeline_id: str
    jobs: tuple
    order: tuple
    digest: str
    seq: int
    version: str = CI_PIPELINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "pipeline_id": self.pipeline_id,
            "jobs": [j.as_dict() for j in self.jobs],
            "order": list(self.order),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class JobResult:
    """One frozen per-job outcome inside a run report."""
    job_id: str
    status: str
    digest: str
    version: str = CI_PIPELINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RunReport:
    """Frozen report of one pipeline run."""
    run_id: str
    pipeline_id: str
    results: tuple
    overall: str
    digest: str
    seq: int
    version: str = CI_PIPELINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "pipeline_id": self.pipeline_id,
            "results": [r.as_dict() for r in self.results],
            "overall": self.overall,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ArtifactRecord:
    """Frozen artifact pinned to a job of a completed run."""
    artifact_id: str
    run_id: str
    job_id: str
    name: str
    digest: str
    seq: int
    version: str = CI_PIPELINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "run_id": self.run_id,
            "job_id": self.job_id,
            "name": self.name,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


class CIPipeline:
    """In-memory GitHub-Actions-style CI pipeline registry."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._definitions: dict[str, PipelineDefinition] = {}
        self._runs: dict[str, RunReport] = {}
        self._artifacts: dict[str, ArtifactRecord] = {}
        self._run_counter = 0
        self._artifact_counter = 0

    # -- definition ----------------------------------------------------

    def define(self, pipeline_id: str, jobs: Mapping[str, Mapping[str, Any]],
               seq: int) -> PipelineDefinition:
        """Register a pipeline: job_id -> {"runs_on": str, "needs": [ids]}."""
        _check_seq(seq)
        pipeline_id = _check_name(pipeline_id, "pipeline_id")
        if not isinstance(jobs, Mapping) or not jobs:
            raise DefinitionError("jobs must be a non-empty mapping")
        needs: dict[str, tuple] = {}
        specs: list[JobSpec] = []
        for job_id, spec in jobs.items():
            _check_name(job_id, "job_id")
            if not isinstance(spec, Mapping):
                raise DefinitionError(f"job {job_id!r} spec must be a mapping")
            runs_on = spec.get("runs_on")
            if not isinstance(runs_on, str) or not runs_on.strip():
                raise DefinitionError(
                    f"job {job_id!r} needs a non-empty runs_on label")
            raw_needs = spec.get("needs", ())
            if isinstance(raw_needs, str) or not isinstance(
                    raw_needs, Sequence):
                raise DefinitionError(
                    f"job {job_id!r} needs must be a sequence of job ids")
            dep_tuple = tuple(raw_needs)
            for dep in dep_tuple:
                _check_name(dep, f"needs entry of {job_id!r}")
                if dep == job_id:
                    raise DefinitionError(
                        f"job {job_id!r} cannot depend on itself")
                if dep not in jobs:
                    raise DefinitionError(
                        f"job {job_id!r} needs unknown job {dep!r}")
            if len(set(dep_tuple)) != len(dep_tuple):
                raise DefinitionError(
                    f"job {job_id!r} has duplicate needs entries")
            needs[job_id] = dep_tuple
            specs.append(JobSpec(
                job_id=job_id,
                runs_on=runs_on,
                needs=dep_tuple,
                digest=_digest({
                    "job_id": job_id, "runs_on": runs_on,
                    "needs": list(dep_tuple),
                }),
            ))
        job_ids = tuple(jobs.keys())
        order = _topo_sort(job_ids, needs)
        definition = PipelineDefinition(
            pipeline_id=pipeline_id,
            jobs=tuple(sorted(specs, key=lambda s: s.job_id)),
            order=order,
            digest=_digest({
                "pipeline_id": pipeline_id,
                "order": list(order),
                "jobs": [s.as_dict() for s in sorted(
                    specs, key=lambda s: s.job_id)],
            }),
            seq=seq,
        )
        with self._lock:
            if pipeline_id in self._definitions:
                raise DefinitionError(
                    f"pipeline {pipeline_id!r} already defined")
            self._definitions[pipeline_id] = definition
        return definition

    # -- run -----------------------------------------------------------

    def run(self, pipeline_id: str, outcomes: Mapping[str, bool],
            seq: int) -> RunReport:
        """Record a run: outcomes maps reached job_id -> True (success)."""
        _check_seq(seq)
        with self._lock:
            definition = self._definitions.get(pipeline_id)
        if definition is None:
            raise UnknownJobError(f"unknown pipeline {pipeline_id!r}")
        if not isinstance(outcomes, Mapping):
            raise OutcomeError("outcomes must be a mapping")
        spec_ids = {s.job_id for s in definition.jobs}
        for job_id, ok in outcomes.items():
            if job_id not in spec_ids:
                raise OutcomeError(f"outcome for unknown job {job_id!r}")
            if not isinstance(ok, bool):
                raise OutcomeError(
                    f"outcome for {job_id!r} must be a bool")
        status: dict[str, str] = {}
        for job_id in definition.order:
            spec = next(s for s in definition.jobs if s.job_id == job_id)
            if any(status[d] != JOB_SUCCESS for d in spec.needs):
                status[job_id] = JOB_SKIPPED
                continue
            if job_id not in outcomes:
                raise OutcomeError(
                    f"reached job {job_id!r} has no reported outcome")
            status[job_id] = JOB_SUCCESS if outcomes[job_id] else JOB_FAILED
        results = tuple(
            JobResult(
                job_id=j,
                status=status[j],
                digest=_digest({"run_seq": seq, "job_id": j,
                               "status": status[j]}),
            )
            for j in definition.order
        )
        overall = (JOB_SUCCESS
                   if all(r.status == JOB_SUCCESS for r in results)
                   else JOB_FAILED)
        with self._lock:
            self._run_counter += 1
            run_id = f"run-{self._run_counter}"
            report = RunReport(
                run_id=run_id,
                pipeline_id=pipeline_id,
                results=results,
                overall=overall,
                digest=_digest({
                    "run_id": run_id, "pipeline_id": pipeline_id,
                    "results": [r.as_dict() for r in results],
                    "overall": overall,
                }),
                seq=seq,
            )
            self._runs[run_id] = report
        return report

    # -- artifacts -----------------------------------------------------

    def artifact(self, run_id: str, job_id: str, name: str,
                 digest: str, seq: int) -> ArtifactRecord:
        """Pin an artifact (name + sha256 digest) to a successful job."""
        _check_seq(seq)
        name = _check_name(name, "artifact name")
        _check_name(job_id, "job_id")
        if not isinstance(digest, str) or not digest.startswith("sha256:") \
                or len(digest) != len("sha256:") + 64:
            raise ArtifactError("digest must be a sha256:<64-hex> pin")
        with self._lock:
            report = self._runs.get(run_id)
        if report is None:
            raise ArtifactError(f"unknown run {run_id!r}")
        result = next((r for r in report.results if r.job_id == job_id),
                      None)
        if result is None:
            raise ArtifactError(
                f"job {job_id!r} not part of run {run_id!r}")
        if result.status != JOB_SUCCESS:
            raise ArtifactError(
                f"artifacts attach only to successful jobs "
                f"(job {job_id!r} is {result.status})")
        with self._lock:
            for rec in self._artifacts.values():
                if rec.run_id == run_id and rec.name == name:
                    raise ArtifactError(
                        f"artifact {name!r} already attached to run {run_id!r}")
            self._artifact_counter += 1
            record = ArtifactRecord(
                artifact_id=f"artifact-{self._artifact_counter}",
                run_id=run_id,
                job_id=job_id,
                name=name,
                digest=digest,
                seq=seq,
            )
            self._artifacts[record.artifact_id] = record
        return record

    # -- views ----------------------------------------------------------

    def definition(self, pipeline_id: str) -> PipelineDefinition:
        with self._lock:
            definition = self._definitions.get(pipeline_id)
        if definition is None:
            raise UnknownJobError(f"unknown pipeline {pipeline_id!r}")
        return definition

    def report(self, run_id: str) -> RunReport:
        with self._lock:
            report = self._runs.get(run_id)
        if report is None:
            raise CIPipelineError(f"unknown run {run_id!r}")
        return report

    def pipelines(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._definitions))

    def runs(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._runs))

    def artifacts(self, run_id: str | None = None) -> tuple:
        with self._lock:
            records = tuple(self._artifacts.values())
        if run_id is not None:
            records = tuple(r for r in records if r.run_id == run_id)
        return tuple(sorted(records, key=lambda r: r.artifact_id))


def ci_pipeline_audit_event(kind: str, seq: int,
                            pipeline_id: str = "",
                            run_id: str = "") -> dict[str, Any]:
    """Shape a pipeline event as an ``audit.ndjson/1``-style record."""
    if kind not in _AUDIT_KINDS:
        raise CIPipelineError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    return {
        "schema": "audit.ndjson/1",
        "event": kind,
        "pipeline_id": pipeline_id,
        "run_id": run_id,
        "audit_seq": seq,
        "module_version": CI_PIPELINE_VERSION,
        "module_schema": SCHEMA_PIN,
    }


def main() -> None:
    pipe = CIPipeline()
    definition = pipe.define("ci", {
        "build": {"runs_on": "ubuntu-latest"},
        "test": {"runs_on": "ubuntu-latest", "needs": ["build"]},
        "deploy": {"runs_on": "ubuntu-latest", "needs": ["test"]},
    }, seq=0)
    assert definition.order == ("build", "test", "deploy"), definition.order
    report = pipe.run("ci", {"build": True, "test": False}, seq=1)
    statuses = {r.job_id: r.status for r in report.results}
    assert statuses == {"build": JOB_SUCCESS, "test": JOB_FAILED,
                        "deploy": JOB_SKIPPED}, statuses
    ok = pipe.run("ci", {"build": True, "test": True, "deploy": True}, seq=2)
    assert ok.overall == JOB_SUCCESS
    record = pipe.artifact(ok.run_id, "build", "dist.tar.gz",
                           "sha256:" + "ab" * 32, seq=3)
    assert record.name == "dist.tar.gz"
    print("ci-pipeline OK: define, topological run, skip rule, artifacts")


if __name__ == "__main__":
    main()
