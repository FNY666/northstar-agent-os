"""Load generator: Locust-style virtual-user population bookkeeping, simulated.

Research note: *load generation* is the "who acts and when" half of load
testing; *measurement* is the other half (see the sibling ``load_tester``
module, which books k6-shaped plans, measured samples, aggregates, and
thresholds). Locust's generator side has three concepts:

* **User classes** — a named population (``HttpUser``) with a *weight*
  (3 browse users for every 1 checkout user) and a *wait time* between
  tasks (``between(1, 3)`` seconds, or constant). This module pins the
  weight and the wait-time window as deterministic bookkeeping.
* **Scenarios** — the ordered task set a user population executes, each
  task carrying a relative weight (``@task(3)``). This module records the
  task list and its weights; it never executes tasks.
* **Spawning / ramping** — Locust spawns users at a *spawn rate* up to a
  target count; a ramp plan raises (or lowers) that target across stages.
  This module books spawn events (deterministic user ids, deterministic
  per-user wait times drawn from an HMAC-SHA256 stream) and pins ramp
  stages, plus a ``users_at()`` view that interpolates the target count
  for any plan tick.

Fail-closed: unknown/duplicate class or scenario ids, zero or negative
weights, inverted wait windows, unknown wait distributions, spawn counts
above the ceiling, empty or malformed ramp stages, and seq rewinds all
raise; nothing silently degrades to a vacuous "all green".

Honest scope: this is *spawning bookkeeping*, not a traffic generator —
the wait times are hash-derived, no requests ever leave this module, and
``users_at()`` computes a planned target, never an observed population.
Pair with the sibling ``load_tester`` for the measurement half, and with a
real Locust/k6 run for ground truth.

Version pin: load-generator.v1
Schema pin: northstar.load-generator.v1
"""

from __future__ import annotations

import hashlib
import hmac
import math
import threading
from dataclasses import dataclass
from typing import Any

#: Module version.
LOAD_GENERATOR_VERSION = "load-generator.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.load-generator.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "northstar.audit.ndjson/1"

#: Wait-time distributions a user class may declare.
WAIT_DISTRIBUTIONS = ("constant", "uniform", "exponential")

#: Fail-closed ceilings.
MAX_USER_CLASSES = 1024
MAX_TASKS_PER_SCENARIO = 256
MAX_USERS_PER_SPAWN = 1_000_000
MAX_RAMP_STAGES = 128
MAX_WAIT_MS = 3_600_000

#: Audit event kinds emitted by this module.
AUDIT_KINDS = (
    "user-class-defined",
    "scenario-defined",
    "users-spawned",
    "ramp-defined",
    "rejected",
)


class LoadGeneratorError(Exception):
    """Base fail-closed load-generator error."""


class DuplicateUserClassError(LoadGeneratorError):
    """A user-class id was defined twice."""


class UnknownUserClassError(LoadGeneratorError):
    """Operation on a user-class id that was never defined."""


class DuplicateScenarioError(LoadGeneratorError):
    """A scenario id was defined twice."""


class UnknownScenarioError(LoadGeneratorError):
    """Operation on a scenario id that was never defined."""


class UnknownSpawnError(LoadGeneratorError):
    """Operation on a spawn report id that was never recorded."""


class UnknownRampError(LoadGeneratorError):
    """Operation on a ramp plan id that was never recorded."""


class BadWeightError(LoadGeneratorError):
    """A weight was zero, negative, a bool, or not an int."""


class BadWaitError(LoadGeneratorError):
    """A wait-time window or distribution was malformed."""


class BadStageError(LoadGeneratorError):
    """A ramp stage was malformed."""


class SpawnLimitError(LoadGeneratorError):
    """A spawn request exceeded the fail-closed user ceiling."""


class SeqOrderError(LoadGeneratorError):
    """A caller seq was not strictly increasing."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise LoadGeneratorError(
            f"{what} must be an int, got {type(seq).__name__}"
        )
    if seq < 0:
        raise LoadGeneratorError(f"{what} must be non-negative, got {seq}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise LoadGeneratorError(
            f"{what} must be a non-empty str, got {value!r}"
        )
    return value


def _check_weight(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadWeightError(
            f"{what} must be an int, got {type(value).__name__}"
        )
    if value <= 0:
        raise BadWeightError(f"{what} must be positive, got {value}")
    return value


def _encode(value: Any) -> bytes:
    """Type-tagged canonical encoding (bool != int; NaN/inf refused)."""
    if isinstance(value, bool):
        return b"b:" + str(int(value)).encode()
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise LoadGeneratorError(
                f"int magnitude {value} exceeds the 2**53 digest bound"
            )
        return b"i:" + str(value).encode()
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise LoadGeneratorError("NaN/inf floats are refused")
        return b"f:" + repr(value).encode()
    if isinstance(value, str):
        return b"s:" + value.encode("utf-8")
    if isinstance(value, (tuple, list)):
        return b"l:" + b"\x1f".join(_encode(v) for v in value)
    raise LoadGeneratorError(f"cannot digest {type(value).__name__}")


def _digest(*parts: Any) -> str:
    body = b"\x1e".join(_encode(p) for p in parts)
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _unit_fraction(stream: bytes, salt: bytes) -> float:
    """Deterministic f in [0, 1) from an HMAC-SHA256 stream and salt."""
    mac = hmac.new(stream, salt, hashlib.sha256).digest()
    return int.from_bytes(mac[:8], "big") / 2**64


@dataclass(frozen=True)
class UserClass:
    """A pinned virtual-user population: weight and wait-time window."""

    version: str
    class_id: str
    weight: int
    wait_min_ms: int
    wait_max_ms: int
    wait_dist: str
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "class_id": self.class_id,
            "weight": self.weight,
            "wait_min_ms": self.wait_min_ms,
            "wait_max_ms": self.wait_max_ms,
            "wait_dist": self.wait_dist,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TaskSpec:
    """One weighted task inside a scenario."""

    name: str
    weight: int

    def __post_init__(self) -> None:
        _check_id(self.name, "task name")
        _check_weight(self.weight, "task weight")

    def as_dict(self) -> dict:
        return {"name": self.name, "weight": self.weight}


@dataclass(frozen=True)
class ScenarioPlan:
    """A pinned scenario: user-class mix plus weighted task list."""

    version: str
    scenario_id: str
    user_classes: tuple
    tasks: tuple
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "scenario_id": self.scenario_id,
            "user_classes": [
                {"class_id": c, "weight": w} for c, w in self.user_classes
            ],
            "tasks": [t.as_dict() for t in self.tasks],
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class SpawnRecord:
    """One booked virtual user: class assignment + wait time."""

    user_id: str
    scenario_id: str
    class_id: str
    wait_ms: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "scenario_id": self.scenario_id,
            "class_id": self.class_id,
            "wait_ms": self.wait_ms,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class SpawnReport:
    """A pinned batch of spawned users."""

    version: str
    spawn_id: str
    scenario_id: str
    users: tuple
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "spawn_id": self.spawn_id,
            "scenario_id": self.scenario_id,
            "users": [u.as_dict() for u in self.users],
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RampStage:
    """One ramp stage: hold ``target_users`` for ``duration_seqs``."""

    duration_seqs: int
    target_users: int

    def __post_init__(self) -> None:
        for name, value in (
            ("duration_seqs", self.duration_seqs),
            ("target_users", self.target_users),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise BadStageError(
                    f"{name} must be an int, got {type(value).__name__}"
                )
            if value < 0:
                raise BadStageError(f"{name} must be non-negative, got {value}")

    def as_dict(self) -> dict:
        return {
            "duration_seqs": self.duration_seqs,
            "target_users": self.target_users,
        }


@dataclass(frozen=True)
class RampPlan:
    """A pinned ramp plan over a scenario."""

    version: str
    ramp_id: str
    scenario_id: str
    stages: tuple
    peak_users: int
    total_spawn_deltas: int
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "ramp_id": self.ramp_id,
            "scenario_id": self.scenario_id,
            "stages": [s.as_dict() for s in self.stages],
            "peak_users": self.peak_users,
            "total_spawn_deltas": self.total_spawn_deltas,
            "seq": self.seq,
            "digest": self.digest,
        }


class LoadGenerator:
    """Locust-style virtual-user population bookkeeping, simulated."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._classes: dict[str, UserClass] = {}
        self._scenarios: dict[str, ScenarioPlan] = {}
        self._spawns: dict[str, SpawnReport] = {}
        self._ramps: dict[str, RampPlan] = {}
        self._user_counter = 0
        self._spawn_counter = 0
        self._ramp_counter = 0
        self._last_seq = -1
        self._audit_log: list[dict] = []

    def _claim_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly increasing "
                f"(last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, detail: dict) -> None:
        self._audit_log.append(
            load_generator_audit_event(kind, seq, detail)
        )

    def define_user_class(
        self,
        class_id: str,
        weight: int,
        seq: int,
        *,
        wait_min_ms: int = 0,
        wait_max_ms: int = 0,
        wait_dist: str = "constant",
    ) -> UserClass:
        """Pin a user class: relative weight plus wait-time window."""
        class_id = _check_id(class_id, "class_id")
        seq = self._claim_seq(seq)
        with self._lock:
            if class_id in self._classes:
                raise DuplicateUserClassError(
                    f"user class {class_id!r} already defined"
                )
            if len(self._classes) >= MAX_USER_CLASSES:
                raise LoadGeneratorError("user-class ceiling reached")
            weight = _check_weight(weight, "weight")
            for name, value in (
                ("wait_min_ms", wait_min_ms),
                ("wait_max_ms", wait_max_ms),
            ):
                if isinstance(value, bool) or not isinstance(value, int):
                    raise BadWaitError(
                        f"{name} must be an int, got {type(value).__name__}"
                    )
                if value < 0 or value > MAX_WAIT_MS:
                    raise BadWaitError(
                        f"{name} must be in [0, {MAX_WAIT_MS}], got {value}"
                    )
            if wait_min_ms > wait_max_ms:
                raise BadWaitError(
                    f"wait_min_ms {wait_min_ms} exceeds "
                    f"wait_max_ms {wait_max_ms}"
                )
            if wait_dist not in WAIT_DISTRIBUTIONS:
                raise BadWaitError(
                    f"wait_dist must be one of {WAIT_DISTRIBUTIONS}, "
                    f"got {wait_dist!r}"
                )
            if wait_dist == "constant" and wait_min_ms != wait_max_ms:
                raise BadWaitError(
                    "constant wait_dist requires wait_min_ms == wait_max_ms"
                )
            digest = _digest(
                class_id,
                weight,
                wait_min_ms,
                wait_max_ms,
                wait_dist,
                seq,
            )
            record = UserClass(
                version=LOAD_GENERATOR_VERSION,
                class_id=class_id,
                weight=weight,
                wait_min_ms=wait_min_ms,
                wait_max_ms=wait_max_ms,
                wait_dist=wait_dist,
                seq=seq,
                digest=digest,
            )
            self._classes[class_id] = record
            self._audit(
                "user-class-defined",
                seq,
                {"class_id": class_id, "digest": digest},
            )
            return record

    def scenario(
        self,
        scenario_id: str,
        user_classes: Any,
        tasks: Any,
        seq: int,
    ) -> ScenarioPlan:
        """Pin a scenario: user-class mix plus weighted task list."""
        scenario_id = _check_id(scenario_id, "scenario_id")
        seq = self._claim_seq(seq)
        with self._lock:
            if scenario_id in self._scenarios:
                raise DuplicateScenarioError(
                    f"scenario {scenario_id!r} already defined"
                )
            if (
                isinstance(user_classes, (str, bytes))
                or not isinstance(user_classes, (tuple, list))
                or not user_classes
            ):
                raise LoadGeneratorError(
                    "user_classes must be a non-empty sequence of "
                    "(class_id, weight) pairs"
                )
            mix = []
            for pair in user_classes:
                if (
                    not isinstance(pair, (tuple, list))
                    or len(pair) != 2
                ):
                    raise LoadGeneratorError(
                        "user_classes entries must be (class_id, weight) "
                        f"pairs, got {pair!r}"
                    )
                class_id = _check_id(pair[0], "class_id")
                if class_id not in self._classes:
                    raise UnknownUserClassError(
                        f"unknown user class {class_id!r}"
                    )
                mix.append((class_id, _check_weight(pair[1], "mix weight")))
            if (
                isinstance(tasks, (str, bytes))
                or not isinstance(tasks, (tuple, list))
                or not tasks
                or len(tasks) > MAX_TASKS_PER_SCENARIO
            ):
                raise LoadGeneratorError(
                    "tasks must be a non-empty sequence of (name, weight) "
                    f"pairs (max {MAX_TASKS_PER_SCENARIO})"
                )
            names = set()
            checked_tasks = []
            for pair in tasks:
                if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                    raise LoadGeneratorError(
                        "task entries must be (name, weight) pairs, "
                        f"got {pair!r}"
                    )
                name = _check_id(pair[0], "task name")
                if name in names:
                    raise LoadGeneratorError(
                        f"duplicate task name {name!r}"
                    )
                names.add(name)
                checked_tasks.append(
                    TaskSpec(name=name, weight=_check_weight(pair[1], "task"))
                )
            mix_body = ",".join(f"{c}:{w}" for c, w in mix)
            task_body = ",".join(
                f"{t.name}:{t.weight}" for t in checked_tasks
            )
            digest = _digest(scenario_id, mix_body, task_body, seq)
            plan = ScenarioPlan(
                version=LOAD_GENERATOR_VERSION,
                scenario_id=scenario_id,
                user_classes=tuple(mix),
                tasks=tuple(checked_tasks),
                seq=seq,
                digest=digest,
            )
            self._scenarios[scenario_id] = plan
            self._audit(
                "scenario-defined", seq,
                {"scenario_id": scenario_id, "digest": digest},
            )
            return plan

    def _wait_ms(self, user_class: UserClass, stream: bytes) -> int:
        lo, hi, dist = (
            user_class.wait_min_ms,
            user_class.wait_max_ms,
            user_class.wait_dist,
        )
        if dist == "constant":
            return lo
        fraction = _unit_fraction(stream, b"wait:" + user_class.class_id.encode())
        if dist == "uniform":
            return lo + int(fraction * (hi - lo + 1)) if hi > lo else lo
        # exponential: mean = (lo + hi) / 2, drawn deterministically
        mean = (lo + hi) / 2.0
        wait = -math.log(1.0 - fraction) * mean
        return min(int(wait), MAX_WAIT_MS)

    def spawn(
        self, scenario_id: str, count: int, seq: int
    ) -> SpawnReport:
        """Book ``count`` user spawns across the scenario's class mix."""
        scenario_id = _check_id(scenario_id, "scenario_id")
        if isinstance(count, bool) or not isinstance(count, int):
            raise SpawnLimitError(
                f"count must be an int, got {type(count).__name__}"
            )
        if count <= 0:
            raise SpawnLimitError(f"count must be positive, got {count}")
        if count > MAX_USERS_PER_SPAWN:
            raise SpawnLimitError(
                f"count {count} exceeds the {MAX_USERS_PER_SPAWN} ceiling"
            )
        seq = self._claim_seq(seq)
        with self._lock:
            plan = self._scenarios.get(scenario_id)
            if plan is None:
                raise UnknownScenarioError(
                    f"unknown scenario {scenario_id!r}"
                )
            mix = plan.user_classes
            total_weight = sum(w for _, w in mix)
            # largest-remainder assignment across the class mix
            floors = []
            remainders = []
            for idx, (class_id, weight) in enumerate(mix):
                quota = count * weight / total_weight
                floor = int(quota)
                floors.append(floor)
                remainders.append((quota - floor, idx))
            leftover = count - sum(floors)
            remainders.sort(key=lambda r: (-r[0], r[1]))
            for k in range(leftover):
                floors[remainders[k][1]] += 1
            self._spawn_counter += 1
            spawn_id = f"spawn-{self._spawn_counter}"
            users = []
            stream = plan.digest.encode("utf-8")
            for idx, (class_id, weight) in enumerate(mix):
                user_class = self._classes[class_id]
                for _ in range(floors[idx]):
                    self._user_counter += 1
                    user_id = f"user-{self._user_counter}"
                    salt = b"user:" + str(self._user_counter).encode()
                    wait_ms = self._wait_ms(user_class, stream + salt)
                    digest = _digest(
                        user_id, scenario_id, class_id, wait_ms, seq
                    )
                    users.append(
                        SpawnRecord(
                            user_id=user_id,
                            scenario_id=scenario_id,
                            class_id=class_id,
                            wait_ms=wait_ms,
                            digest=digest,
                        )
                    )
            digest = _digest(
                spawn_id,
                scenario_id,
                tuple(u.user_id for u in users),
                seq,
            )
            report = SpawnReport(
                version=LOAD_GENERATOR_VERSION,
                spawn_id=spawn_id,
                scenario_id=scenario_id,
                users=tuple(users),
                seq=seq,
                digest=digest,
            )
            self._spawns[spawn_id] = report
            self._audit(
                "users-spawned",
                seq,
                {
                    "spawn_id": spawn_id,
                    "scenario_id": scenario_id,
                    "count": len(users),
                    "digest": digest,
                },
            )
            return report

    def ramp(self, scenario_id: str, stages: Any, seq: int) -> RampPlan:
        """Pin a ramp plan: stage targets across caller-seq durations."""
        scenario_id = _check_id(scenario_id, "scenario_id")
        seq = self._claim_seq(seq)
        with self._lock:
            if scenario_id not in self._scenarios:
                raise UnknownScenarioError(
                    f"unknown scenario {scenario_id!r}"
                )
            if (
                isinstance(stages, (str, bytes))
                or not isinstance(stages, (tuple, list))
                or not stages
                or len(stages) > MAX_RAMP_STAGES
            ):
                raise BadStageError(
                    "stages must be a non-empty sequence of "
                    f"(duration_seqs, target_users) pairs (max {MAX_RAMP_STAGES})"
                )
            checked = []
            for value in stages:
                if isinstance(value, RampStage):
                    checked.append(value)
                elif (
                    isinstance(value, (tuple, list)) and len(value) == 2
                ):
                    checked.append(
                        RampStage(
                            duration_seqs=value[0],
                            target_users=value[1],
                        )
                    )
                else:
                    raise BadStageError(
                        "stage must be a RampStage or "
                        f"(duration_seqs, target_users) pair, got {value!r}"
                    )
            for stage in checked:
                if stage.target_users > MAX_USERS_PER_SPAWN:
                    raise BadStageError(
                        f"target_users {stage.target_users} exceeds the "
                        f"{MAX_USERS_PER_SPAWN} ceiling"
                    )
            peak = max(s.target_users for s in checked)
            previous = 0
            deltas = 0
            for stage in checked:
                if stage.target_users > previous:
                    deltas += stage.target_users - previous
                previous = stage.target_users
            stage_body = ",".join(
                f"{s.duration_seqs}:{s.target_users}" for s in checked
            )
            self._ramp_counter += 1
            ramp_id = f"ramp-{self._ramp_counter}"
            digest = _digest(ramp_id, scenario_id, stage_body, seq)
            plan = RampPlan(
                version=LOAD_GENERATOR_VERSION,
                ramp_id=ramp_id,
                scenario_id=scenario_id,
                stages=tuple(checked),
                peak_users=peak,
                total_spawn_deltas=deltas,
                seq=seq,
                digest=digest,
            )
            self._ramps[ramp_id] = plan
            self._audit(
                "ramp-defined",
                seq,
                {
                    "ramp_id": ramp_id,
                    "scenario_id": scenario_id,
                    "digest": digest,
                },
            )
            return plan

    def users_at(self, ramp_id: str, tick: Any) -> int:
        """Planned user count at plan ``tick`` (linear stage interpolation).

        Pure view: consumes no seq, pins nothing. Ticks past the plan end
        clamp to the final target; ramps up and down both interpolate.
        """
        ramp_id = _check_id(ramp_id, "ramp_id")
        if isinstance(tick, bool) or not isinstance(tick, int):
            raise LoadGeneratorError(
                f"tick must be an int, got {type(tick).__name__}"
            )
        if tick < 0:
            raise LoadGeneratorError(f"tick must be non-negative, got {tick}")
        with self._lock:
            plan = self._ramps.get(ramp_id)
            if plan is None:
                raise UnknownRampError(f"unknown ramp {ramp_id!r}")
            stages = plan.stages
            elapsed = 0
            previous = 0
            for stage in stages:
                if tick < elapsed + stage.duration_seqs or stage.duration_seqs == 0:
                    if stage.duration_seqs == 0:
                        return stage.target_users
                    fraction = (tick - elapsed) / stage.duration_seqs
                    return int(
                        previous + (stage.target_users - previous) * fraction
                    )
                elapsed += stage.duration_seqs
                previous = stage.target_users
            return previous

    def user_class(self, class_id: str) -> UserClass:
        class_id = _check_id(class_id, "class_id")
        with self._lock:
            record = self._classes.get(class_id)
            if record is None:
                raise UnknownUserClassError(
                    f"unknown user class {class_id!r}"
                )
            return record

    def user_class_ids(self) -> tuple:
        with self._lock:
            return tuple(self._classes)

    def scenario_plan(self, scenario_id: str) -> ScenarioPlan:
        scenario_id = _check_id(scenario_id, "scenario_id")
        with self._lock:
            plan = self._scenarios.get(scenario_id)
            if plan is None:
                raise UnknownScenarioError(
                    f"unknown scenario {scenario_id!r}"
                )
            return plan

    def scenario_ids(self) -> tuple:
        with self._lock:
            return tuple(self._scenarios)

    def spawn_report(self, spawn_id: str) -> SpawnReport:
        spawn_id = _check_id(spawn_id, "spawn_id")
        with self._lock:
            report = self._spawns.get(spawn_id)
            if report is None:
                raise UnknownSpawnError(f"unknown spawn {spawn_id!r}")
            return report

    def ramp_plan(self, ramp_id: str) -> RampPlan:
        ramp_id = _check_id(ramp_id, "ramp_id")
        with self._lock:
            plan = self._ramps.get(ramp_id)
            if plan is None:
                raise UnknownRampError(f"unknown ramp {ramp_id!r}")
            return plan

    def audit_log(self) -> tuple:
        with self._lock:
            return tuple(self._audit_log)


def load_generator_audit_event(
    kind: str, seq: int, detail: dict
) -> dict:
    """Shape an ``audit.ndjson/1`` record for a load-generator event."""
    if kind not in AUDIT_KINDS:
        raise LoadGeneratorError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    if not isinstance(detail, dict):
        raise LoadGeneratorError("detail must be a dict")
    event = {
        "schema": AUDIT_SCHEMA,
        "module": LOAD_GENERATOR_VERSION,
        "event": kind,
        "audit_seq": seq,
    }
    event.update(detail)
    return event


def main() -> None:
    """Self-check: classes, scenarios, spawn, wait times, ramp, refusal."""
    gen = LoadGenerator()
    assert gen.user_class_ids() == ()

    browse = gen.define_user_class(
        "browse", 3, 0, wait_min_ms=1000, wait_max_ms=3000,
        wait_dist="uniform",
    )
    assert browse.digest.startswith("sha256:")
    checkout = gen.define_user_class("checkout", 1, 1)
    assert checkout.wait_min_ms == 0 and checkout.wait_max_ms == 0
    assert gen.user_class_ids() == ("browse", "checkout")

    plan = gen.scenario(
        "shop",
        [("browse", 3), ("checkout", 1)],
        [("view", 5), ("buy", 1)],
        2,
    )
    assert plan.digest.startswith("sha256:")
    assert gen.scenario_ids() == ("shop",)

    report = gen.spawn("shop", 40, 3)
    assert report.spawn_id == "spawn-1"
    assert len(report.users) == 40
    # largest remainder: 40 * 3/4 = 30 browse, 40 * 1/4 = 10 checkout
    classes = [u.class_id for u in report.users]
    assert classes.count("browse") == 30
    assert classes.count("checkout") == 10
    assert report.users[0].user_id == "user-1"
    assert report.users[-1].user_id == "user-40"
    assert all(u.wait_ms == 0 for u in report.users if u.class_id == "checkout")
    assert all(
        1000 <= u.wait_ms <= 3000
        for u in report.users
        if u.class_id == "browse"
    )
    # deterministic replay across instances
    gen2 = LoadGenerator()
    gen2.define_user_class(
        "browse", 3, 0, wait_min_ms=1000, wait_max_ms=3000,
        wait_dist="uniform",
    )
    gen2.define_user_class("checkout", 1, 1)
    gen2.scenario(
        "shop", [("browse", 3), ("checkout", 1)],
        [("view", 5), ("buy", 1)], 2,
    )
    replay = gen2.spawn("shop", 40, 3)
    assert [u.wait_ms for u in replay.users] == [
        u.wait_ms for u in report.users
    ]
    assert [u.class_id for u in replay.users] == classes
    assert replay.users[0].digest == report.users[0].digest

    ramp = gen.ramp("shop", [(10, 20), (10, 40)], 4)
    assert ramp.peak_users == 40
    assert ramp.total_spawn_deltas == 40
    assert gen.users_at("ramp-1", 0) == 0
    assert gen.users_at("ramp-1", 5) == 10
    assert gen.users_at("ramp-1", 10) == 20
    assert gen.users_at("ramp-1", 15) == 30
    assert gen.users_at("ramp-1", 20) == 40
    assert gen.users_at("ramp-1", 999) == 40
    assert gen.ramp_plan("ramp-1") is ramp
    assert gen.spawn_report("spawn-1") is report

    # refusal paths
    try:
        gen.define_user_class("browse", 1, 5)
    except DuplicateUserClassError:
        pass
    else:
        raise AssertionError("duplicate class accepted")
    try:
        gen.define_user_class("x", 0, 6)
    except BadWeightError:
        pass
    else:
        raise AssertionError("zero weight accepted")
    try:
        gen.define_user_class(
            "y", 1, 7, wait_min_ms=5, wait_max_ms=4
        )
    except BadWaitError:
        pass
    else:
        raise AssertionError("inverted wait window accepted")
    try:
        gen.define_user_class("z", 1, 8, wait_dist="weibull")
    except BadWaitError:
        pass
    else:
        raise AssertionError("unknown wait dist accepted")
    try:
        gen.define_user_class("w", 1, 9, wait_min_ms=1, wait_max_ms=2)
    except BadWaitError:
        pass
    else:
        raise AssertionError("constant with unequal window accepted")
    try:
        gen.scenario("shop", [("browse", 1)], [("t", 1)], 10)
    except DuplicateScenarioError:
        pass
    else:
        raise AssertionError("duplicate scenario accepted")
    try:
        gen.scenario("bad", [("ghost", 1)], [("t", 1)], 11)
    except UnknownUserClassError:
        pass
    else:
        raise AssertionError("unknown class accepted")
    try:
        gen.spawn("shop", MAX_USERS_PER_SPAWN + 1, 12)
    except SpawnLimitError:
        pass
    else:
        raise AssertionError("spawn ceiling not enforced")
    try:
        gen.spawn("ghost", 10, 13)
    except UnknownScenarioError:
        pass
    else:
        raise AssertionError("unknown scenario accepted")
    try:
        gen.ramp("shop", [], 14)
    except BadStageError:
        pass
    else:
        raise AssertionError("empty stages accepted")
    try:
        gen.ramp("shop", [(-1, 5)], 15)
    except BadStageError:
        pass
    else:
        raise AssertionError("negative duration accepted")
    try:
        gen.users_at("ghost-ramp", 0)
    except UnknownRampError:
        pass
    else:
        raise AssertionError("unknown ramp accepted")
    try:
        gen.users_at("ramp-1", -1)
    except LoadGeneratorError:
        pass
    else:
        raise AssertionError("negative tick accepted")
    try:
        gen.define_user_class("late", 1, 4)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind accepted")

    # audit event shapes
    event = load_generator_audit_event(
        "users-spawned", 16, {"spawn_id": "spawn-1", "count": 40}
    )
    assert event["schema"] == AUDIT_SCHEMA
    assert event["module"] == "load-generator.v1"
    assert event["event"] == "users-spawned"
    try:
        load_generator_audit_event("bogus-kind", 0, {})
    except LoadGeneratorError:
        pass
    else:
        raise AssertionError("unknown audit kind accepted")

    print(
        "load-generator OK: classes, scenarios, spawn, wait, ramp, refusals"
    )


if __name__ == "__main__":
    main()
