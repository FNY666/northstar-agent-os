"""Ansible playbook interface: config management as a deterministic state machine.

Research motivation: configuration management is where an agent's intent
meets a fleet. Ansible playbooks decide *what changes on which hosts* --
a task that runs against the wrong host is a blast-radius incident, a
task that is not idempotent turns a re-run into an outage, and a
``--check`` mode that lies about what would change makes review
meaningless. This module is the *bookkeeping* half of an Ansible-shaped
runner: it records playbook definitions, computes what a ``--check``
dry-run would change, and simulates a run with deterministic
idempotency semantics -- but it never opens an SSH connection, never
touches a host, and never executes a payload itself. The host binds
(task, host) decisions to real machines through its own transport.

Public API:

- ``AnsiblePlaybook`` -- RLock-guarded registry.
  ``define(play_id, tasks, hosts, seq)`` registers a frozen
  ``PlayDefinition`` (task list + host inventory). ``check(play_id,
  seq)`` dry-runs the play without mutating converged state and
  returns a frozen ``CheckReport``. ``run(play_id, seq)`` simulates a
  run and returns a frozen ``RunReport`` (per-host ``HostResult``,
  per-task ``TaskResult``). ``hosts(play_id)`` / ``tasks(play_id)``
  views.
- ``TaskSpec`` -- frozen: ``name``, ``module``, ``args`` mapping,
  ``notify`` (handler names), ``simulate_fail`` (explicit test hook).
- Idempotency model: idempotent modules (``file``, ``copy``,
  ``template``, ``lineinfile``, ``service``, ``package``) report
  ``changed=True`` on first run against a host and ``changed=False``
  once converged; non-idempotent modules (``command``, ``shell``,
  ``raw``) always report ``changed=True``. A ``simulate_fail`` task
  fails and stops the play on that host (Ansible default).
- ``ansible_playbook_audit_event(kind, seq, ...)`` --
  ``audit.ndjson/1`` records, fixed kind vocabulary: ``"defined"`` /
  ``"checked"`` / ``"ran"`` / ``"rejected"``.

Honest scope:

- The module answers "what would change, and what changed" -- it does
  not *perform* any change. Convergence is bookkeeping over the
  module's own simulated host state, not a proof about real machines;
  a host that lies about its state gets a consistent record of lies
  (same GIGO boundary as every other bookkeeping module).
- ``check`` mode never mutates converged state; ``run`` is the only
  state-changing call. Caller-supplied int seqs are the only notion
  of time/order (no wall-clock); seqs must be non-negative and are
  recorded on every mutation.
- Task args must be canonicalizable (digest-pinned); ``simulate_fail``
  exists only so hosts can test failure handling without a network.

Version pin: ``ansible-playbook.v1`` / schema pin
``northstar.ansible-playbook.v1``.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

VERSION = "ansible-playbook.v1"
SCHEMA = "northstar.ansible-playbook.v1"
AUDIT_FORMAT = "audit.ndjson/1"

_AUDIT_KINDS = ("defined", "checked", "ran", "rejected")

# Modules whose first application converges a host to a desired state;
# re-application with identical args reports changed=False.
IDEMPOTENT_MODULES = frozenset(
    {"file", "copy", "template", "lineinfile", "service", "package", "user", "group"}
)
# Modules that perform an action every time they run.
ALWAYS_CHANGED_MODULES = frozenset({"command", "shell", "raw", "script"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PlaybookError(Exception):
    """Base class for ansible-playbook errors."""


class DuplicatePlayError(PlaybookError):
    """A playbook id is already registered."""


class UnknownPlayError(PlaybookError):
    """No registered playbook with that id."""


class PlayValidationError(PlaybookError):
    """A playbook definition is invalid."""


class TaskFailedError(PlaybookError):
    """A task failed during a simulated run (host-reported failure)."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _check_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlayValidationError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlayValidationError("seq must be an int")
    if value < 0:
        raise PlayValidationError("seq must be non-negative")
    return value


def _check_canonical_value(value: Any, where: str) -> None:
    """Recursive payload check: fail-closed on JCS float-loss values.

    JSON/JCS cannot exactly represent ints with magnitude > 2**53 or
    integral floats with magnitude > 2**53, so digest pins over such
    values would be unsound. Refuse them at the boundary.
    """
    if isinstance(value, bool):
        return  # bools are canonical
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise PlayValidationError(
                f"{where}: int magnitude exceeds 2**53 (JCS float-loss)"
            )
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise PlayValidationError(
                f"{where}: NaN/inf floats are not canonicalizable"
            )
        if value.is_integer() and abs(value) > 2**53:
            raise PlayValidationError(
                f"{where}: integral float exceeds 2**53 (JCS float-loss)"
            )
        return
    if isinstance(value, str) or value is None:
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_canonical_value(item, where)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PlayValidationError(f"{where}: non-str mapping key")
            _check_canonical_value(item, where)
        return
    raise PlayValidationError(
        f"{where}: value of type {type(value).__name__} is not canonicalizable"
    )


def _canonical(value: Any) -> str:
    """Canonical JSON for digest pinning; bool is distinct from int.

    Caller must ensure JCS-unsafe values (ints or integral floats with
    magnitude > 2**53) were refused at the boundary first.
    """
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=_canonical_fallback,
        )
    except (TypeError, ValueError) as exc:
        raise PlayValidationError(f"value is not canonicalizable: {exc}") from exc


def _canonical_fallback(value: Any) -> Any:
    if isinstance(value, (tuple, frozenset)):
        return list(value)
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    raise TypeError(f"not canonicalizable: {type(value).__name__}")


def _digest(body: str) -> str:
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _task_pin(module: str, args: Mapping[str, Any]) -> str:
    return _digest(_canonical({"module": module, "args": dict(args)}))


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaskSpec:
    """Immutable definition of one playbook task."""

    name: str
    module: str
    args: Tuple[Tuple[str, Any], ...] = ()
    notify: Tuple[str, ...] = ()
    simulate_fail: bool = False

    def __post_init__(self) -> None:
        _check_str(self.name, "task name")
        _check_str(self.module, "task module")
        if not isinstance(self.args, tuple):
            raise PlayValidationError("task args must be a tuple of (key, value)")
        seen = set()
        for pair in self.args:
            if (
                not isinstance(pair, tuple) or len(pair) != 2
                or not isinstance(pair[0], str) or not pair[0]
            ):
                raise PlayValidationError(
                    "task args must be (non-empty str key, value) pairs"
                )
            if pair[0] in seen:
                raise PlayValidationError(f"duplicate arg key {pair[0]!r}")
            seen.add(pair[0])
        # Fail-closed: args must be canonicalizable before pinning.
        for pair in self.args:
            _check_canonical_value(pair[1], f"task {self.name!r} arg {pair[0]!r}")
        if not isinstance(self.notify, tuple):
            raise PlayValidationError("task notify must be a tuple of str")
        for handler in self.notify:
            _check_str(handler, "handler name")
        if not isinstance(self.simulate_fail, bool):
            raise PlayValidationError("simulate_fail must be a bool")

    def pin(self) -> str:
        """Deterministic digest pin of (module, args)."""
        return _task_pin(self.module, dict(self.args))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "module": self.module,
            "args": dict(self.args),
            "notify": list(self.notify),
            "simulate_fail": self.simulate_fail,
            "pin": self.pin(),
        }


@dataclass(frozen=True)
class PlayDefinition:
    """Immutable registered playbook: tasks + host inventory."""

    play_id: str
    tasks: Tuple[TaskSpec, ...]
    hosts: Tuple[str, ...]
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "play_id": self.play_id,
            "tasks": [t.as_dict() for t in self.tasks],
            "hosts": list(self.hosts),
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CheckResult:
    """Dry-run outcome of one task on one host (no state mutated)."""

    host: str
    task_name: str
    module: str
    would_change: bool
    handlers_notified: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "task_name": self.task_name,
            "module": self.module,
            "would_change": self.would_change,
            "handlers_notified": list(self.handlers_notified),
        }


@dataclass(frozen=True)
class CheckReport:
    """Frozen ``--check`` dry-run report."""

    play_id: str
    seq: int
    results: Tuple[CheckResult, ...]
    would_change_count: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "play_id": self.play_id,
            "seq": self.seq,
            "results": [r.as_dict() for r in self.results],
            "would_change_count": self.would_change_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TaskResult:
    """Outcome of one task on one host during a simulated run."""

    task_name: str
    module: str
    changed: bool
    failed: bool
    handlers_notified: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "task_name": self.task_name,
            "module": self.module,
            "changed": self.changed,
            "failed": self.failed,
            "handlers_notified": list(self.handlers_notified),
        }


@dataclass(frozen=True)
class HostResult:
    """Per-host outcome of a simulated run."""

    host: str
    task_results: Tuple[TaskResult, ...]
    failed: bool
    failed_task: Optional[str]
    changed_count: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "task_results": [t.as_dict() for t in self.task_results],
            "failed": self.failed,
            "failed_task": self.failed_task,
            "changed_count": self.changed_count,
        }


@dataclass(frozen=True)
class RunReport:
    """Frozen report of a simulated playbook run."""

    play_id: str
    seq: int
    host_results: Tuple[HostResult, ...]
    total_changed: int
    total_failed: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "play_id": self.play_id,
            "seq": self.seq,
            "host_results": [h.as_dict() for h in self.host_results],
            "total_changed": self.total_changed,
            "total_failed": self.total_failed,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class AnsiblePlaybook:
    """RLock-guarded playbook registry with simulated check/run semantics."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._plays: Dict[str, PlayDefinition] = {}
        # Simulated convergence state: (play_id, host) -> set of task pins
        # that have converged (idempotent modules only).
        self._converged: Dict[Tuple[str, str], set] = {}
        self._last_seq = -1

    # -- definition ------------------------------------------------------

    def define(
        self,
        play_id: str,
        tasks: Sequence[TaskSpec],
        hosts: Sequence[str],
        seq: int,
    ) -> PlayDefinition:
        seq = _check_seq(seq)
        _check_str(play_id, "play_id")
        if not isinstance(tasks, (list, tuple)) or not tasks:
            raise PlayValidationError("tasks must be a non-empty list of TaskSpec")
        tasks_t = tuple(tasks)
        for task in tasks_t:
            if not isinstance(task, TaskSpec):
                raise PlayValidationError("tasks must be TaskSpec instances")
        names = [t.name for t in tasks_t]
        if len(set(names)) != len(names):
            raise PlayValidationError("duplicate task names in playbook")
        if not isinstance(hosts, (list, tuple)) or not hosts:
            raise PlayValidationError("hosts must be a non-empty list of str")
        hosts_t = tuple(hosts)
        for host in hosts_t:
            _check_str(host, "host")
        if len(set(hosts_t)) != len(hosts_t):
            raise PlayValidationError("duplicate hosts in inventory")
        with self._lock:
            if seq <= self._last_seq:
                raise PlayValidationError(
                    "seq must strictly increase across mutations"
                )
            if play_id in self._plays:
                raise DuplicatePlayError(f"playbook {play_id!r} already defined")
            body = _canonical({
                "play_id": play_id,
                "tasks": [t.as_dict() for t in tasks_t],
                "hosts": list(hosts_t),
            })
            play = PlayDefinition(
                play_id=play_id,
                tasks=tasks_t,
                hosts=hosts_t,
                seq=seq,
                digest=_digest(body),
            )
            self._plays[play_id] = play
            self._last_seq = seq
            return play

    def get(self, play_id: str) -> PlayDefinition:
        _check_str(play_id, "play_id")
        with self._lock:
            try:
                return self._plays[play_id]
            except KeyError:
                raise UnknownPlayError(f"unknown playbook {play_id!r}") from None

    def hosts(self, play_id: str) -> Tuple[str, ...]:
        return self.get(play_id).hosts

    def tasks(self, play_id: str) -> Tuple[TaskSpec, ...]:
        return self.get(play_id).tasks

    # -- simulation core --------------------------------------------------

    @staticmethod
    def _would_change(play_id: str, host: str, task: TaskSpec,
                      converged: Dict[Tuple[str, str], set]) -> bool:
        """Deterministic idempotency decision (no mutation)."""
        if task.module in ALWAYS_CHANGED_MODULES:
            return True
        pin = task.pin()
        return pin not in converged.get((play_id, host), set())

    def check(self, play_id: str, seq: int) -> CheckReport:
        """Dry-run (``--check``): what would change, without mutating state."""
        seq = _check_seq(seq)
        play = self.get(play_id)
        results: List[CheckResult] = []
        with self._lock:
            snapshot = {k: set(v) for k, v in self._converged.items()}
            for host in play.hosts:
                for task in play.tasks:
                    if task.simulate_fail:
                        results.append(CheckResult(
                            host=host, task_name=task.name, module=task.module,
                            would_change=False, handlers_notified=(),
                        ))
                        break  # play would stop on this host
                    changed = self._would_change(play_id, host, task, snapshot)
                    # A dry-run must not converge, so simulate against the
                    # pre-check snapshot only (no mutation of self state).
                    results.append(CheckResult(
                        host=host, task_name=task.name, module=task.module,
                        would_change=changed,
                        handlers_notified=task.notify if changed else (),
                    ))
            count = sum(1 for r in results if r.would_change)
            body = _canonical({
                "play_id": play_id, "seq": seq,
                "results": [r.as_dict() for r in results],
            })
            return CheckReport(
                play_id=play_id, seq=seq,
                results=tuple(results), would_change_count=count,
                digest=_digest(body),
            )

    def run(self, play_id: str, seq: int) -> RunReport:
        """Simulate a run: applies idempotent tasks, converging host state."""
        seq = _check_seq(seq)
        play = self.get(play_id)
        host_results: List[HostResult] = []
        with self._lock:
            if seq <= self._last_seq:
                raise PlayValidationError(
                    "seq must strictly increase across mutations"
                )
            for host in play.hosts:
                task_results: List[TaskResult] = []
                failed = False
                failed_task: Optional[str] = None
                key = (play_id, host)
                converged = self._converged.setdefault(key, set())
                for task in play.tasks:
                    if task.simulate_fail:
                        task_results.append(TaskResult(
                            task_name=task.name, module=task.module,
                            changed=False, failed=True,
                            handlers_notified=(),
                        ))
                        failed = True
                        failed_task = task.name
                        break
                    changed = self._would_change(play_id, host, task,
                                                self._converged)
                    if changed and task.module in IDEMPOTENT_MODULES:
                        converged.add(task.pin())
                    task_results.append(TaskResult(
                        task_name=task.name, module=task.module,
                        changed=changed, failed=False,
                        handlers_notified=task.notify if changed else (),
                    ))
                changed_count = sum(1 for t in task_results if t.changed)
                host_results.append(HostResult(
                    host=host, task_results=tuple(task_results),
                    failed=failed, failed_task=failed_task,
                    changed_count=changed_count,
                ))
            total_changed = sum(h.changed_count for h in host_results)
            total_failed = sum(1 for h in host_results if h.failed)
            body = _canonical({
                "play_id": play_id, "seq": seq,
                "hosts": [h.as_dict() for h in host_results],
            })
            report = RunReport(
                play_id=play_id, seq=seq,
                host_results=tuple(host_results),
                total_changed=total_changed, total_failed=total_failed,
                digest=_digest(body),
            )
            self._last_seq = seq
            return report

    def is_converged(self, play_id: str, host: str, task_name: str) -> bool:
        """Whether an idempotent task has converged on a host."""
        play = self.get(play_id)
        task = next((t for t in play.tasks if t.name == task_name), None)
        if task is None:
            raise PlayValidationError(f"unknown task {task_name!r}")
        with self._lock:
            return task.pin() in self._converged.get((play_id, host), set())


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def ansible_playbook_audit_event(
    kind: str,
    seq: int,
    play_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a playbook event.

    ``kind`` is one of ``"defined"`` / ``"checked"`` / ``"ran"`` /
    ``"rejected"``.
    """
    if not isinstance(kind, str) or kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    record: Dict[str, Any] = {
        "format": AUDIT_FORMAT,
        "schema": SCHEMA,
        "kind": kind,
        "seq": _check_seq(seq),
    }
    if play_id is not None:
        record["play_id"] = _check_str(play_id, "play_id")
    return record


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    pb = AnsiblePlaybook()
    tasks = (
        TaskSpec(name="write-conf", module="copy",
                 args=(("dest", "/etc/app.conf"),), notify=("restart-app",)),
        TaskSpec(name="ensure-svc", module="service",
                 args=(("name", "app"), ("state", "started"),)),
        TaskSpec(name="ping", module="command", args=(("cmd", "uptime"),)),
    )
    play = pb.define("deploy", tasks, ["web1", "web2"], seq=1)
    assert play.digest.startswith("sha256:")
    # Dry-run predicts changes on both hosts; converges nothing.
    report = pb.check("deploy", seq=2)
    assert report.would_change_count == 6
    assert not pb.is_converged("deploy", "web1", "write-conf")
    # First run changes idempotent tasks; command always changes.
    run1 = pb.run("deploy", seq=3)
    assert run1.total_failed == 0
    assert run1.total_changed == 6
    assert pb.is_converged("deploy", "web1", "write-conf")
    # Second run: idempotent tasks report no change; command still changes.
    run2 = pb.run("deploy", seq=4)
    assert run2.total_changed == 2
    # Failing task stops the play on its host.
    failing = (
        TaskSpec(name="boom", module="command", args=(("cmd", "x"),),
                 simulate_fail=True),
    )
    pb.define("bad", failing, ["db1"], seq=5)
    run3 = pb.run("bad", seq=6)
    assert run3.total_failed == 1
    assert run3.host_results[0].failed_task == "boom"
    # Audit shapes.
    rec = ansible_playbook_audit_event("ran", seq=7, play_id="deploy")
    assert rec["format"] == AUDIT_FORMAT and rec["schema"] == SCHEMA
    print("ansible-playbook OK: define, check, run, idempotency, failure")


if __name__ == "__main__":
    main()
