"""Chaos engineering — simulated fault-injection experiment bookkeeping.

Research note (chaos engineering literature): Chaos Monkey (Netflix)
and Gremlin model chaos as *declared experiments* with a pinned
fault vocabulary (kill, latency injection, partition, resource
pressure), a *blast radius* (how much of the fleet is in scope), a
*steady-state hypothesis* (what "healthy" means, checked before and
after), and a strict lifecycle: defined -> running -> (aborted |
completed). Safety rails are first-class: abort must be immediate,
terminal, and auditable; an experiment may only run inside its
declared blast radius; re-running a terminal experiment is refused.

This module takes the intersection for a single-host deterministic
ledger:

* **Experiments, not injections**: ``experiment`` books a declared
  experiment (fault type, targets, blast radius, duration in logical
  seqs, steady-state hypothesis). No fault is ever injected.
* **Blast as a booked decision**: ``blast`` moves an experiment
  defined -> running and books a ``BlastRecord``. The host declares
  the start; the module cannot observe it.
* **Abort is terminal**: ``abort`` moves running -> aborted and
  books an ``AbortRecord``. Terminal states never leave.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool /
negative / rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback), sha256 digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: this module books *declared* chaos experiments
deterministically. It injects no faults, observes no blast effects,
and cannot prove a target was disturbed — a ``blasted`` record means
"the host declared the start", never "faults were injected". The
steady-state hypothesis is a booked string, not a verified
measurement. Production still needs a real fault-injection agent, a
safety interlock, and an on-call rotation.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CHAOS_ENGINEERING_VERSION = "chaos-engineering.v1"

#: Schema pin carried by records and audit events.
CHAOS_ENGINEERING_SCHEMA = "northstar.chaos-engineering.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned fault vocabulary (Gremlin/Chaos-Monkey-shaped attack set).
FAULT_KILL_POD = "kill-pod"
FAULT_NETWORK_LATENCY = "network-latency"
FAULT_NETWORK_PARTITION = "network-partition"
FAULT_DISK_PRESSURE = "disk-pressure"
FAULT_CPU_PRESSURE = "cpu-pressure"
FAULT_MEMORY_PRESSURE = "memory-pressure"
FAULT_CLOCK_SKEW = "clock-skew"
FAULT_DNS_BLACKHOLE = "dns-blackhole"
FAULT_TYPES = (
    FAULT_KILL_POD,
    FAULT_NETWORK_LATENCY,
    FAULT_NETWORK_PARTITION,
    FAULT_DISK_PRESSURE,
    FAULT_CPU_PRESSURE,
    FAULT_MEMORY_PRESSURE,
    FAULT_CLOCK_SKEW,
    FAULT_DNS_BLACKHOLE,
)

#: Pinned blast-radius vocabulary (scope of the experiment).
RADIUS_SINGLE = "single"
RADIUS_ZONE = "zone"
RADIUS_REGION = "region"
BLAST_RADII = (RADIUS_SINGLE, RADIUS_ZONE, RADIUS_REGION)

#: Experiment lifecycle states.
STATE_DEFINED = "defined"
STATE_RUNNING = "running"
STATE_ABORTED = "aborted"
EXPERIMENT_STATES = (STATE_DEFINED, STATE_RUNNING, STATE_ABORTED)

#: Audit event kinds.
KIND_EXPERIMENT_DEFINED = "chaos.experiment-defined"
KIND_BLASTED = "chaos.blasted"
KIND_ABORTED = "chaos.aborted"
KIND_REJECTED = "chaos.rejected"
_KINDS = (
    KIND_EXPERIMENT_DEFINED,
    KIND_BLASTED,
    KIND_ABORTED,
    KIND_REJECTED,
)

_DIGEST_PREFIX = "sha256:"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ChaosEngineeringError(ValueError):
    """Base error for the chaos engineering ledger."""


class BadExperimentError(ChaosEngineeringError):
    """Malformed experiment definition (bad fault, targets, radius)."""


class DuplicateExperimentError(ChaosEngineeringError):
    """An experiment with this id is already defined."""


class UnknownExperimentError(ChaosEngineeringError):
    """No experiment with this id is defined."""


class BadBlastError(ChaosEngineeringError):
    """Blast refused (experiment not in defined state)."""


class AlreadyRunningError(ChaosEngineeringError):
    """The experiment is already running."""


class BadAbortError(ChaosEngineeringError):
    """Abort refused (bad reason, or experiment never ran)."""


class NotRunningError(ChaosEngineeringError):
    """Abort refused: the experiment is not running."""


class AlreadyAbortedError(ChaosEngineeringError):
    """The experiment is already aborted (terminal)."""


class SeqOrderError(ChaosEngineeringError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ChaosEngineeringError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ChaosEngineeringError(f"{field_name} must be a non-empty string")
    return value


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise ChaosEngineeringError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ChaosEngineeringError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ChaosEngineeringError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExperimentRecord:
    """A pinned chaos experiment definition (state starts ``defined``)."""

    experiment_id: str
    name: str
    fault_type: str
    targets: tuple
    blast_radius: str
    duration_seq: int
    hypothesis: str
    seq: int
    digest: str
    state: str = STATE_DEFINED
    schema: str = CHAOS_ENGINEERING_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return self.digest == _pin(
            [
                "experiment",
                self.experiment_id,
                self.name,
                self.fault_type,
                list(self.targets),
                self.blast_radius,
                self.duration_seq,
                self.hypothesis,
                self.seq,
            ],
            seed,
        )


@dataclass(frozen=True)
class BlastRecord:
    """A booked blast start (defined -> running)."""

    blast_id: str
    experiment_id: str
    seq: int
    digest: str
    schema: str = CHAOS_ENGINEERING_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return self.digest == _pin(
            ["blast", self.blast_id, self.experiment_id, self.seq], seed
        )


@dataclass(frozen=True)
class AbortRecord:
    """A booked abort (running -> aborted; terminal)."""

    abort_id: str
    experiment_id: str
    reason: str
    seq: int
    digest: str
    schema: str = CHAOS_ENGINEERING_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return self.digest == _pin(
            ["abort", self.abort_id, self.experiment_id, self.reason, self.seq],
            seed,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def chaos_engineering_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the chaos ledger."""
    if kind not in _KINDS:
        raise ChaosEngineeringError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise ChaosEngineeringError("detail must be a mapping")
    # Targets never cross the audit boundary; pins only.
    banned = {"targets", "target"}
    if any(k in detail for k in banned):
        raise ChaosEngineeringError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": CHAOS_ENGINEERING_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class ChaosEngineering:
    """Deterministic chaos-experiment bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads validate the seq shape but do not consume it and write no
    audit rows.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._experiments: dict[str, ExperimentRecord] = {}
        self._states: dict[str, str] = {}
        self._blasts: dict[str, BlastRecord] = {}
        self._blast_ids: list[str] = []
        self._aborts: dict[str, AbortRecord] = {}
        self._blast_counter = 0
        self._abort_counter = 0
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(chaos_engineering_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _validate_targets(self, targets: Any) -> tuple:
        if (
            not isinstance(targets, (list, tuple))
            or not targets
            or not all(isinstance(t, str) and t.strip() for t in targets)
        ):
            raise BadExperimentError(
                "targets must be a non-empty list of non-empty strings"
            )
        cleaned = tuple(t.strip() for t in targets)
        if len(set(cleaned)) != len(cleaned):
            raise BadExperimentError("duplicate targets")
        return cleaned

    # -- experiments ----------------------------------------------------

    def experiment(
        self,
        experiment_id: str,
        name: str,
        fault_type: str,
        targets: Any,
        seq: int,
        blast_radius: str = RADIUS_SINGLE,
        duration_seq: int = 100,
        hypothesis: str = "",
    ) -> ExperimentRecord:
        """Book a chaos experiment definition (state ``defined``).

        ``hypothesis`` is the steady-state statement (free text, e.g.
        ``"error-rate-below 1%"``); it is booked, never verified.
        """
        seq = self._next_seq(seq)
        with self._lock:
            try:
                experiment_id = _check_nonempty_str(experiment_id, "experiment_id")
                name = _check_nonempty_str(name, "name")
                if fault_type not in FAULT_TYPES:
                    raise BadExperimentError(f"unknown fault_type: {fault_type!r}")
                cleaned_targets = self._validate_targets(targets)
                if blast_radius not in BLAST_RADII:
                    raise BadExperimentError(
                        f"unknown blast_radius: {blast_radius!r}"
                    )
                if (
                    isinstance(duration_seq, bool)
                    or not isinstance(duration_seq, int)
                    or duration_seq <= 0
                ):
                    raise BadExperimentError("duration_seq must be a positive int")
                if not isinstance(hypothesis, str):
                    raise BadExperimentError("hypothesis must be a string")
                if experiment_id in self._experiments:
                    raise DuplicateExperimentError(
                        f"experiment already defined: {experiment_id!r}"
                    )
            except ChaosEngineeringError as exc:
                self._reject(seq, str(exc))
                raise
            digest = _pin(
                [
                    "experiment",
                    experiment_id,
                    name,
                    fault_type,
                    list(cleaned_targets),
                    blast_radius,
                    duration_seq,
                    hypothesis,
                    seq,
                ],
                self._seed,
            )
            record = ExperimentRecord(
                experiment_id=experiment_id,
                name=name,
                fault_type=fault_type,
                targets=cleaned_targets,
                blast_radius=blast_radius,
                duration_seq=duration_seq,
                hypothesis=hypothesis,
                seq=seq,
                digest=digest,
            )
            self._experiments[experiment_id] = record
            self._states[experiment_id] = STATE_DEFINED
            self._emit(
                KIND_EXPERIMENT_DEFINED,
                seq,
                experiment_id=experiment_id,
                fault_type=fault_type,
                blast_radius=blast_radius,
                digest=digest,
            )
            return record

    # -- blast ----------------------------------------------------------

    def blast(self, experiment_id: str, seq: int) -> BlastRecord:
        """Book a blast start (defined -> running). Fail-closed on state."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                experiment_id = _check_nonempty_str(experiment_id, "experiment_id")
                if experiment_id not in self._experiments:
                    raise UnknownExperimentError(
                        f"unknown experiment: {experiment_id!r}"
                    )
                state = self._states[experiment_id]
                if state == STATE_RUNNING:
                    raise AlreadyRunningError(
                        f"experiment already running: {experiment_id!r}"
                    )
                if state == STATE_ABORTED:
                    raise BadBlastError(
                        f"experiment is terminal (aborted): {experiment_id!r}"
                    )
            except ChaosEngineeringError as exc:
                self._reject(seq, str(exc))
                raise
            self._blast_counter += 1
            blast_id = f"blt-{self._blast_counter}"
            digest = _pin(
                ["blast", blast_id, experiment_id, seq], self._seed
            )
            record = BlastRecord(
                blast_id=blast_id,
                experiment_id=experiment_id,
                seq=seq,
                digest=digest,
            )
            self._blasts[blast_id] = record
            self._blast_ids.append(blast_id)
            self._states[experiment_id] = STATE_RUNNING
            self._emit(
                KIND_BLASTED,
                seq,
                blast_id=blast_id,
                experiment_id=experiment_id,
                digest=digest,
            )
            return record

    # -- abort ----------------------------------------------------------

    def abort(self, experiment_id: str, seq: int, reason: str = "") -> AbortRecord:
        """Book an abort (running -> aborted; terminal)."""
        seq = self._next_seq(seq)
        with self._lock:
            try:
                experiment_id = _check_nonempty_str(experiment_id, "experiment_id")
                if experiment_id not in self._experiments:
                    raise UnknownExperimentError(
                        f"unknown experiment: {experiment_id!r}"
                    )
                if not isinstance(reason, str):
                    raise BadAbortError("reason must be a string")
                state = self._states[experiment_id]
                if state == STATE_ABORTED:
                    raise AlreadyAbortedError(
                        f"experiment already aborted: {experiment_id!r}"
                    )
                if state != STATE_RUNNING:
                    raise NotRunningError(
                        f"experiment is not running: {experiment_id!r}"
                    )
            except ChaosEngineeringError as exc:
                self._reject(seq, str(exc))
                raise
            self._abort_counter += 1
            abort_id = f"abt-{self._abort_counter}"
            digest = _pin(
                ["abort", abort_id, experiment_id, reason, seq], self._seed
            )
            record = AbortRecord(
                abort_id=abort_id,
                experiment_id=experiment_id,
                reason=reason,
                seq=seq,
                digest=digest,
            )
            self._aborts[abort_id] = record
            self._states[experiment_id] = STATE_ABORTED
            self._emit(
                KIND_ABORTED,
                seq,
                abort_id=abort_id,
                experiment_id=experiment_id,
                digest=digest,
            )
            return record

    # -- views -----------------------------------------------------------

    def experiment_record(self, experiment_id: str) -> ExperimentRecord:
        """Return the booked experiment definition."""
        with self._lock:
            try:
                return self._experiments[experiment_id]
            except KeyError:
                raise UnknownExperimentError(
                    f"unknown experiment: {experiment_id!r}"
                ) from None

    def status(self, experiment_id: str) -> str:
        """Return the lifecycle state (defined / running / aborted)."""
        with self._lock:
            try:
                return self._states[experiment_id]
            except KeyError:
                raise UnknownExperimentError(
                    f"unknown experiment: {experiment_id!r}"
                ) from None

    def experiment_ids(self) -> tuple:
        """Defined experiment ids, sorted."""
        with self._lock:
            return tuple(sorted(self._experiments))

    def running_ids(self) -> tuple:
        """Experiment ids currently in running state, sorted."""
        with self._lock:
            return tuple(sorted(e for e, s in self._states.items() if s == STATE_RUNNING))

    def blast_record(self, blast_id: str) -> BlastRecord:
        """Return a booked blast record."""
        with self._lock:
            try:
                return self._blasts[blast_id]
            except KeyError:
                raise UnknownExperimentError(
                    f"unknown blast: {blast_id!r}"
                ) from None

    def abort_record(self, abort_id: str) -> AbortRecord:
        """Return a booked abort record."""
        with self._lock:
            try:
                return self._aborts[abort_id]
            except KeyError:
                raise UnknownExperimentError(
                    f"unknown abort: {abort_id!r}"
                ) from None

    def blasts_for(self, experiment_id: str) -> tuple:
        """Blast records for one experiment, in booking order."""
        with self._lock:
            if experiment_id not in self._experiments:
                raise UnknownExperimentError(
                    f"unknown experiment: {experiment_id!r}"
                )
            return tuple(b for b in (self._blasts[i] for i in self._blast_ids)
                         if b.experiment_id == experiment_id)

    def stats(self) -> Mapping[str, int]:
        """Ledger counts (pure view)."""
        with self._lock:
            return {
                "experiments": len(self._experiments),
                "blasts": len(self._blasts),
                "aborts": len(self._aborts),
                "running": sum(1 for s in self._states.values() if s == STATE_RUNNING),
            }

    def audit_log(self) -> tuple:
        """Booked audit events, in order (pure view)."""
        with self._lock:
            return tuple(self._audit_log)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    ce = ChaosEngineering()
    exp = ce.experiment(
        "exp-1", "kill checkout pods", FAULT_KILL_POD,
        ["checkout-0", "checkout-1"], 1,
        blast_radius=RADIUS_ZONE, hypothesis="error-rate-below 1%",
    )
    assert exp.verify()
    assert ce.status("exp-1") == STATE_DEFINED
    blast = ce.blast("exp-1", 2)
    assert blast.verify()
    assert ce.status("exp-1") == STATE_RUNNING
    abort = ce.abort("exp-1", 3, reason="steady-state violated")
    assert abort.verify()
    assert ce.status("exp-1") == STATE_ABORTED
    assert CHAOS_ENGINEERING_VERSION == "chaos-engineering.v1"
    print("chaos-engineering OK: experiment, blast, abort, pins, audit")


if __name__ == "__main__":
    main()
