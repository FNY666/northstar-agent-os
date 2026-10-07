"""GTD task manager interface (Todoist-style task bookkeeping).

Research motivation: personal task managers (Todoist, Things, OmniFocus)
all converge on the same shape -- tasks with priorities, labels/contexts,
projects/areas, due dates, and a completable lifecycle. GTD adds the
organizing discipline on top: capture, clarify, organize, reflect, engage.

This module pins the deterministic bookkeeping half of that shape:

- ``TaskManager`` -- owns tasks and projects. ``add()`` captures a task
  (title, description, project, labels, priority, due marker),
  ``complete()`` closes it, ``reopen()`` re-arms it, ``prioritize()``
  sets its priority, ``set_due()`` pins a due marker, ``label()`` /
  ``unlabel()`` manage GTD contexts, ``create_project()`` owns the
  project ledger, and ``next_actions()`` lists open work sorted the
  Todoist way (priority, then due, then creation order).
- ``task_manager_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``added`` / ``completed`` / ``reopened`` / ``prioritized`` /
  ``due-set`` / ``labeled`` / ``project-created`` / ``rejected``);
  caller-supplied seqs only.

Conventions pinned here:

- Priorities are Todoist-style ``1``..``4`` where **p1 is the highest
  urgency** and p4 is unprioritized (default). ``next_actions()`` sorts
  by priority ascending, so p1 tasks surface first.
- Due markers are caller-supplied int seqs, never wall-clock: the host
  maps its own seqs to time. A due marker must be a positive int.
- Labels are GTD contexts (``@home``, ``@errands``); the ``@`` prefix
  is a convention only, any non-empty string is accepted.
- Task ids are monotonic ``task-N``; project ids are ``proj-N``.
- A completed task cannot be completed again (fail-closed,
  ``AlreadyCompletedError``); an open task cannot be re-completed by
  ``reopen()`` (``NotCompletedError``).

Fail-closed edges (fail loudly, never guess):

- Unknown task/project ids raise ``UnknownTaskError`` /
  ``UnknownProjectError``.
- Empty/whitespace titles, priorities outside 1..4, non-positive or
  bool due markers, and empty label strings are refused.
- Caller seqs must be strictly increasing positive ints
  (``SeqOrderError``); seqs advance only on successful mutation.
- Digest pins are ``sha256:`` over type-tagged canonical bodies
  (bool != int; NaN/inf refused), so identical content replays to
  identical pins.

Honest scope:

- This module books *reported* task state. It cannot verify that a
  completed task was actually done; ``complete()`` records the claim.
- ``next_actions()`` is a deterministic sort over reported fields,
  not a judgment about what matters -- priority is caller-asserted.
- Due markers order tasks; they carry no wall-clock meaning on their
  own.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence, Tuple

TASK_MANAGER_VERSION = "task-manager.v1"
SCHEMA_PIN = "northstar.task-manager.v1"

_TASK_AUDIT_KINDS = (
    "added",
    "completed",
    "reopened",
    "prioritized",
    "due-set",
    "labeled",
    "project-created",
    "rejected",
)

_STATE_OPEN = "open"
_STATE_COMPLETED = "completed"

_MIN_PRIORITY = 1
_MAX_PRIORITY = 4
_DEFAULT_PRIORITY = 4


class TaskError(ValueError):
    """Base fail-closed error for the task manager."""


class UnknownTaskError(TaskError):
    """The task id is not in the ledger."""


class UnknownProjectError(TaskError):
    """The project id is not in the ledger."""


class DuplicateProjectError(TaskError):
    """A project with this name already exists."""


class AlreadyCompletedError(TaskError):
    """The task is already completed."""


class NotCompletedError(TaskError):
    """The task is not completed (cannot be reopened)."""


class BadTaskError(TaskError):
    """A task field failed validation."""


class BadProjectError(TaskError):
    """A project field failed validation."""


class SeqOrderError(TaskError):
    """Caller-supplied seq did not increase monotonically."""


def _digest_tagged(parts: Tuple[Tuple[str, object], ...]) -> str:
    """sha256 pin over type-tagged canonical encoding.

    bool != int, NaN/inf refused (same discipline as the batch line), so
    the pin binds content without float-serialization ambiguity.
    """
    buf = []
    for tag, value in parts:
        if isinstance(value, bool):
            body = "bool:" + ("1" if value else "0")
        elif isinstance(value, int):
            if abs(value) >= 2**53:
                raise TaskError("integer exceeds safe range for pinning")
            body = "int:" + str(value)
        elif isinstance(value, str):
            body = "str:" + value
        elif isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise TaskError("non-finite float refused for pinning")
            if value.is_integer() and abs(value) < 2**53:
                raise TaskError("integral float refused for pinning")
            raise TaskError("float refused for pinning")
        elif value is None:
            body = "none:"
        elif isinstance(value, tuple):
            inner = ",".join(
                _digest_tagged(((tag, v),)).split(":", 1)[1] for v in value
            )
            body = "tuple:[" + ",".join(inner) + "]"
        else:
            raise TaskError(f"unpinable type for {tag}: {type(value).__name__}")
        buf.append(tag + "=" + body)
    return "sha256:" + hashlib.sha256("|".join(buf).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProjectRecord:
    """A project/area the task ledger knows about."""

    project_id: str
    name: str
    task_count: int = 0
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "task_count": self.task_count,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TaskRecord:
    """A single captured task, frozen at the mutation that produced it."""

    task_id: str
    title: str
    description: str
    project_id: Optional[str]
    labels: Tuple[str, ...]
    priority: int
    due_seq: Optional[int]
    state: str
    created_seq: int
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "description": self.description,
            "project_id": self.project_id,
            "labels": list(self.labels),
            "priority": self.priority,
            "due_seq": self.due_seq,
            "state": self.state,
            "created_seq": self.created_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CompletionRecord:
    """A completed-task transition."""

    task_id: str
    completed_seq: int
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "completed_seq": self.completed_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TaskList:
    """A frozen view over a task query."""

    tasks: Tuple[TaskRecord, ...]
    total: int
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "tasks": [t.as_dict() for t in self.tasks],
            "total": self.total,
            "digest": self.digest,
        }


class TaskManager:
    """GTD/Todoist-shaped task bookkeeping.

    RLock-guarded, caller-supplied strictly increasing int seqs, no
    wall-clock, fail-closed, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tasks: Dict[str, TaskRecord] = {}
        self._projects: Dict[str, ProjectRecord] = {}
        self._task_counter = 0
        self._project_counter = 0
        self._last_seq = 0

    # -- internals ----------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
            raise SeqOrderError("seq must be a positive int")
        if seq <= self._last_seq:
            raise SeqOrderError("seq must increase monotonically")

    def _task_digest(self, record: TaskRecord) -> str:
        return _digest_tagged(
            (
                ("task_id", record.task_id),
                ("title", record.title),
                ("description", record.description),
                ("project_id", record.project_id),
                ("labels", record.labels),
                ("priority", record.priority),
                ("due_seq", record.due_seq),
                ("state", record.state),
                ("created_seq", record.created_seq),
            )
        )

    def _project_digest(self, record: ProjectRecord) -> str:
        return _digest_tagged(
            (
                ("project_id", record.project_id),
                ("name", record.name),
                ("task_count", record.task_count),
            )
        )

    def _bump_project_count(self, project_id: Optional[str], delta: int) -> None:
        if project_id is None:
            return
        project = self._projects[project_id]
        updated = ProjectRecord(
            project_id=project.project_id,
            name=project.name,
            task_count=project.task_count + delta,
        )
        self._projects[project_id] = ProjectRecord(
            project_id=updated.project_id,
            name=updated.name,
            task_count=updated.task_count,
            digest=self._project_digest(updated),
        )

    @staticmethod
    def _clean_title(title: object) -> str:
        if not isinstance(title, str) or not title.strip():
            raise BadTaskError("title must be a non-empty string")
        return title.strip()

    @staticmethod
    def _clean_labels(labels: object) -> Tuple[str, ...]:
        if labels is None:
            return ()
        if isinstance(labels, str) or not isinstance(labels, Sequence):
            raise BadTaskError("labels must be a sequence of strings")
        cleaned = []
        for label in labels:
            if not isinstance(label, str) or not label.strip():
                raise BadTaskError("labels must be non-empty strings")
            cleaned.append(label.strip())
        if len(set(cleaned)) != len(cleaned):
            raise BadTaskError("duplicate labels refused")
        return tuple(sorted(cleaned))

    @staticmethod
    def _clean_priority(priority: object) -> int:
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise BadTaskError("priority must be an int 1..4")
        if not _MIN_PRIORITY <= priority <= _MAX_PRIORITY:
            raise BadTaskError("priority must be an int 1..4")
        return priority

    @staticmethod
    def _clean_due(due_seq: object) -> Optional[int]:
        if due_seq is None:
            return None
        if isinstance(due_seq, bool) or not isinstance(due_seq, int) or due_seq <= 0:
            raise BadTaskError("due_seq must be a positive int")
        return due_seq

    def _replace(self, record: TaskRecord) -> TaskRecord:
        """Return a digest-pinned copy of a mutated task record."""
        return TaskRecord(
            task_id=record.task_id,
            title=record.title,
            description=record.description,
            project_id=record.project_id,
            labels=record.labels,
            priority=record.priority,
            due_seq=record.due_seq,
            state=record.state,
            created_seq=record.created_seq,
            digest=self._task_digest(record),
        )

    # -- projects ------------------------------------------------------

    def create_project(self, name: str, seq: int) -> ProjectRecord:
        """Create a project/area; names are unique (fail-closed)."""
        with self._lock:
            if not isinstance(name, str) or not name.strip():
                raise BadProjectError("project name must be a non-empty string")
            cleaned = name.strip()
            for existing in self._projects.values():
                if existing.name == cleaned:
                    raise DuplicateProjectError(f"project exists: {cleaned!r}")
            self._check_seq(seq)
            self._project_counter += 1
            record = ProjectRecord(
                project_id=f"proj-{self._project_counter}", name=cleaned
            )
            record = ProjectRecord(
                project_id=record.project_id,
                name=record.name,
                task_count=0,
                digest=self._project_digest(record),
            )
            self._projects[record.project_id] = record
            self._last_seq = seq
            return record

    def project(self, project_id: str) -> ProjectRecord:
        with self._lock:
            try:
                return self._projects[project_id]
            except KeyError:
                raise UnknownProjectError(f"unknown project: {project_id!r}")

    def projects(self) -> Tuple[ProjectRecord, ...]:
        with self._lock:
            return tuple(sorted(self._projects.values(), key=lambda p: p.project_id))

    # -- capture -------------------------------------------------------

    def add(
        self,
        title: str,
        seq: int,
        *,
        description: str = "",
        project_id: Optional[str] = None,
        labels: Optional[Sequence[str]] = None,
        priority: int = _DEFAULT_PRIORITY,
        due_seq: Optional[int] = None,
    ) -> TaskRecord:
        """Capture a task into the ledger."""
        with self._lock:
            title = self._clean_title(title)
            if not isinstance(description, str):
                raise BadTaskError("description must be a string")
            if project_id is not None:
                if not isinstance(project_id, str) or project_id not in self._projects:
                    raise UnknownProjectError(f"unknown project: {project_id!r}")
            labels = self._clean_labels(labels)
            priority = self._clean_priority(priority)
            due_seq = self._clean_due(due_seq)
            self._check_seq(seq)
            self._task_counter += 1
            record = TaskRecord(
                task_id=f"task-{self._task_counter}",
                title=title,
                description=description,
                project_id=project_id,
                labels=labels,
                priority=priority,
                due_seq=due_seq,
                state=_STATE_OPEN,
                created_seq=seq,
            )
            record = self._replace(record)
            self._tasks[record.task_id] = record
            self._bump_project_count(project_id, 1)
            self._last_seq = seq
            return record

    # -- lifecycle -----------------------------------------------------

    def complete(self, task_id: str, seq: int) -> CompletionRecord:
        """Mark an open task completed (terminal transition)."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            if record.state == _STATE_COMPLETED:
                raise AlreadyCompletedError(f"already completed: {task_id!r}")
            self._check_seq(seq)
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=record.project_id,
                labels=record.labels,
                priority=record.priority,
                due_seq=record.due_seq,
                state=_STATE_COMPLETED,
                created_seq=record.created_seq,
            )
            self._tasks[task_id] = self._replace(updated)
            completion = CompletionRecord(task_id=task_id, completed_seq=seq)
            completion = CompletionRecord(
                task_id=completion.task_id,
                completed_seq=completion.completed_seq,
                digest=_digest_tagged(
                    (("task_id", task_id), ("completed_seq", seq))
                ),
            )
            self._last_seq = seq
            return completion

    def reopen(self, task_id: str, seq: int) -> TaskRecord:
        """Re-arm a completed task back to open."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            if record.state != _STATE_COMPLETED:
                raise NotCompletedError(f"not completed: {task_id!r}")
            self._check_seq(seq)
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=record.project_id,
                labels=record.labels,
                priority=record.priority,
                due_seq=record.due_seq,
                state=_STATE_OPEN,
                created_seq=record.created_seq,
            )
            updated = self._replace(updated)
            self._tasks[task_id] = updated
            self._last_seq = seq
            return updated

    # -- organize ------------------------------------------------------

    def prioritize(self, task_id: str, priority: int, seq: int) -> TaskRecord:
        """Set the task priority (1..4, p1 highest urgency)."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            priority = self._clean_priority(priority)
            self._check_seq(seq)
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=record.project_id,
                labels=record.labels,
                priority=priority,
                due_seq=record.due_seq,
                state=record.state,
                created_seq=record.created_seq,
            )
            updated = self._replace(updated)
            self._tasks[task_id] = updated
            self._last_seq = seq
            return updated

    def set_due(self, task_id: str, due_seq: Optional[int], seq: int) -> TaskRecord:
        """Pin (or clear, with None) the task's due marker."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            due_seq = self._clean_due(due_seq)
            self._check_seq(seq)
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=record.project_id,
                labels=record.labels,
                priority=record.priority,
                due_seq=due_seq,
                state=record.state,
                created_seq=record.created_seq,
            )
            updated = self._replace(updated)
            self._tasks[task_id] = updated
            self._last_seq = seq
            return updated

    def label(self, task_id: str, seq: int, *labels: str) -> TaskRecord:
        """Attach GTD context labels to a task."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            new_labels = self._clean_labels(labels)
            merged = self._clean_labels(tuple(record.labels) + new_labels)
            self._check_seq(seq)
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=record.project_id,
                labels=merged,
                priority=record.priority,
                due_seq=record.due_seq,
                state=record.state,
                created_seq=record.created_seq,
            )
            updated = self._replace(updated)
            self._tasks[task_id] = updated
            self._last_seq = seq
            return updated

    def unlabel(self, task_id: str, seq: int, *labels: str) -> TaskRecord:
        """Detach GTD context labels from a task."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            remove = set(self._clean_labels(labels))
            remaining = tuple(l for l in record.labels if l not in remove)
            self._check_seq(seq)
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=record.project_id,
                labels=remaining,
                priority=record.priority,
                due_seq=record.due_seq,
                state=record.state,
                created_seq=record.created_seq,
            )
            updated = self._replace(updated)
            self._tasks[task_id] = updated
            self._last_seq = seq
            return updated

    def move_to_project(
        self, task_id: str, project_id: Optional[str], seq: int
    ) -> TaskRecord:
        """Move a task to a project (None detaches it)."""
        with self._lock:
            try:
                record = self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            if project_id is not None and (
                not isinstance(project_id, str) or project_id not in self._projects
            ):
                raise UnknownProjectError(f"unknown project: {project_id!r}")
            self._check_seq(seq)
            old_project = record.project_id
            updated = TaskRecord(
                task_id=record.task_id,
                title=record.title,
                description=record.description,
                project_id=project_id,
                labels=record.labels,
                priority=record.priority,
                due_seq=record.due_seq,
                state=record.state,
                created_seq=record.created_seq,
            )
            updated = self._replace(updated)
            self._tasks[task_id] = updated
            if old_project != project_id:
                self._bump_project_count(old_project, -1)
                self._bump_project_count(project_id, 1)
            self._last_seq = seq
            return updated

    # -- views ---------------------------------------------------------

    def task(self, task_id: str) -> TaskRecord:
        with self._lock:
            try:
                return self._tasks[task_id]
            except KeyError:
                raise UnknownTaskError(f"unknown task: {task_id!r}")

    def tasks(
        self,
        *,
        project_id: Optional[str] = None,
        label: Optional[str] = None,
        state: Optional[str] = _STATE_OPEN,
    ) -> TaskList:
        """Query tasks by project, label, and state (default: open)."""
        with self._lock:
            if state is not None and state not in (_STATE_OPEN, _STATE_COMPLETED):
                raise BadTaskError("state must be 'open', 'completed', or None")
            if project_id is not None and project_id not in self._projects:
                raise UnknownProjectError(f"unknown project: {project_id!r}")
            matched = [
                t
                for t in self._tasks.values()
                if (state is None or t.state == state)
                and (project_id is None or t.project_id == project_id)
                and (label is None or label in t.labels)
            ]
            matched.sort(key=lambda t: t.task_id)
            digest = _digest_tagged(
                tuple(("task", t.digest) for t in matched) + (("total", len(matched)),)
            )
            return TaskList(tasks=tuple(matched), total=len(matched), digest=digest)

    def next_actions(self, limit: int = 25) -> TaskList:
        """GTD next actions: open tasks sorted by (priority, due, created).

        Priority 1 surfaces first; tasks without a due marker sort after
        due ones at the same priority; ties break by creation seq.
        """
        with self._lock:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
                raise BadTaskError("limit must be a positive int")
            open_tasks = [t for t in self._tasks.values() if t.state == _STATE_OPEN]
            open_tasks.sort(
                key=lambda t: (
                    t.priority,
                    t.due_seq if t.due_seq is not None else 2**53 - 1,
                    t.created_seq,
                )
            )
            chosen = tuple(open_tasks[:limit])
            digest = _digest_tagged(
                tuple(("task", t.digest) for t in chosen)
                + (("total", len(chosen)), ("limit", limit))
            )
            return TaskList(tasks=chosen, total=len(chosen), digest=digest)

    def counts(self) -> dict:
        with self._lock:
            open_count = sum(1 for t in self._tasks.values() if t.state == _STATE_OPEN)
            done_count = sum(
                1 for t in self._tasks.values() if t.state == _STATE_COMPLETED
            )
            return {
                "open": open_count,
                "completed": done_count,
                "projects": len(self._projects),
            }


def task_manager_audit_event(
    kind: str,
    seq: int,
    detail: str = "",
) -> dict:
    """Shape an ``audit.ndjson/1`` record for task manager activity.

    Carries ids and digest pins only -- never task titles or bodies.
    """
    if kind not in _TASK_AUDIT_KINDS:
        raise TaskError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise TaskError("seq must be a positive int")
    if not isinstance(detail, str):
        raise TaskError("detail must be str")
    return {
        "kind": kind,
        "seq": seq,
        "detail": detail,
        "module": TASK_MANAGER_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    m = TaskManager()
    p = m.create_project("inbox-zero", 1)
    assert p.project_id == "proj-1" and p.name == "inbox-zero"
    t1 = m.add("file taxes", 2, priority=1, due_seq=100, project_id=p.project_id)
    t2 = m.add("buy milk", 3, labels=("@errands",), priority=3)
    assert t1.task_id == "task-1" and t2.task_id == "task-2"
    assert t1.labels == () and t2.labels == ("@errands",)
    nxt = m.next_actions()
    assert [t.task_id for t in nxt.tasks] == ["task-1", "task-2"]
    m.label(t1.task_id, 4, "@home")
    assert "@home" in m.task(t1.task_id).labels
    m.prioritize(t2.task_id, 2, 5)
    assert m.task(t2.task_id).priority == 2
    done = m.complete(t1.task_id, 6)
    assert done.task_id == "task-1" and m.task("task-1").state == "completed"
    assert m.next_actions().total == 1
    evt = task_manager_audit_event("completed", 6, detail="task-1")
    assert evt["schema"] == SCHEMA_PIN
    print("task-manager OK: project, add, next-actions, label, prioritize, complete")


if __name__ == "__main__":
    main()
