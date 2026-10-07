"""Iterated distillation and amplification (IDA) as a safety-instrumented primitive.

Research context (Christiano et al., "Supervising strong learners by
amplifying weak experts"): a weak agent becomes strong by answering
questions through *amplification* — breaking a task into subquestions,
delegating them to copies of itself, and combining the results — and
*distillation* — training the weak agent to imitate the amplified
system. Repeating the loop scales oversight to tasks the weak agent
could not do alone.

As a production primitive, amplification is also an attack surface and
a budget hazard:

* **Decomposition smuggling.** Each subtask looks benign in isolation
  while the composition is dangerous. Lineage is therefore structural:
  every non-root task has exactly one parent, and a task decomposed
  twice is refused (the tree cannot be rewritten to smuggle subtasks).
* **Budget explosion.** Recursive amplification multiplies calls.
  ``max_depth`` and ``max_branching`` caps are enforced at
  decomposition time, fail-closed.
* **Partial combination.** A result assembled from a cherry-picked
  subset of leaves is not the amplified answer. ``combine`` requires
  an output for *every* leaf unless the caller explicitly opts into
  ``allow_partial=True``, which is recorded on the result.
* **Distillation ledger.** Each completed combination is recorded as a
  ``DistillationPair`` (task id, leaf count, combined digest, seq) so
  the host can train the weak agent on (task, amplified answer) pairs.

Usage::

    amp = Amplifier()
    root = amp.register_root("audit the quarterly ledger", task_id="t0", seq=1)
    tree = amp.amplify("t0", plan={"t0": ["check revenue", "check expenses"]},
                       depth=1, seq=2)
    leaves = amp.leaves("t0")                      # the two subtasks
    result = amp.combine("t0",
                         {leaf.task_id: "clean" for leaf in leaves},
                         synthesized="ledger is clean", seq=3)
    amp.distillation_ledger()                      # (DistillationPair(...),)

The module manages *structure* (decomposition tree, depth, lineage,
combination bookkeeping) and *records* results. It does not solve
tasks and does not semantically merge outputs: ``synthesized`` is the
caller's own combination of the leaf outputs, and the module pins its
digest. A combined result is "every leaf answered and the caller's
combination is pinned", never "the answer is correct".

Honest scope:

* The module cannot see whether a decomposition is *sensible*; it
  enforces that it is *bounded, lineage-consistent, and complete*.
* Leaf outputs are recorded verbatim (and digested); the module does
  not validate their content.
* No wall-clock anywhere: all sequence numbers are caller-supplied
  ints, all sizes are caller-supplied data.
* Stdlib only. Deterministic: tree order is registration order.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable, Mapping

#: Version of the amplification rule described here.
ITERATED_AMPLIFICATION_VERSION = "iterated-amplification.v1"

#: Schema pin stamped on serialized records.
SCHEMA_PIN = "northstar.iterated-amplification.v1"

#: Default cap on decomposition depth (root = depth 0).
DEFAULT_MAX_DEPTH = 8

#: Default cap on children per decomposition.
DEFAULT_MAX_BRANCHING = 16


class AmplificationError(ValueError):
    """Raised for structural amplification violations (fail-closed)."""


def _require_non_empty_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AmplificationError(f"{name} must be a non-empty string")
    return value


def _require_int_seq(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AmplificationError(f"{name} must be a non-negative int seq")
    return value


def _digest_pin(*parts: str) -> str:
    body = "\x00".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Task:
    """One node of the amplification tree.

    ``parent_id`` is ``None`` for roots. ``depth`` is 0 for roots and
    counts decomposition levels below.
    """

    task_id: str
    description: str
    parent_id: str | None
    depth: int
    seq: int

    def __post_init__(self) -> None:
        _require_non_empty_str(self.task_id, "task_id")
        _require_non_empty_str(self.description, "description")
        if self.parent_id is not None:
            _require_non_empty_str(self.parent_id, "parent_id")
        _require_int_seq(self.depth, "depth")
        _require_int_seq(self.seq, "seq")
        if self.parent_id is None and self.depth != 0:
            raise AmplificationError("root task must have depth 0")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "task_id": self.task_id,
            "description": self.description,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class Decomposition:
    """One recorded breakdown: parent task -> ordered child task ids.

    ``digest`` pins (parent_id, child ids, seq) so an auditor can verify
    the tree was not rewritten after the fact.
    """

    parent_id: str
    child_ids: tuple[str, ...]
    seq: int
    digest: str

    def __post_init__(self) -> None:
        _require_non_empty_str(self.parent_id, "parent_id")
        if not self.child_ids:
            raise AmplificationError("decomposition needs at least one child")
        for cid in self.child_ids:
            _require_non_empty_str(cid, "child_id")
        if len(set(self.child_ids)) != len(self.child_ids):
            raise AmplificationError("child ids must be unique")
        if self.parent_id in self.child_ids:
            raise AmplificationError("parent cannot be its own child")
        _require_int_seq(self.seq, "seq")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise AmplificationError("digest must be a sha256: pin")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "parent_id": self.parent_id,
            "child_ids": list(self.child_ids),
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class AmplificationTree:
    """Frozen snapshot of a (sub)tree: root plus every descendant."""

    root_id: str
    task_ids: tuple[str, ...]
    parent_of: tuple[tuple[str, str | None], ...]
    depth_of: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        _require_non_empty_str(self.root_id, "root_id")
        if self.root_id not in self.task_ids:
            raise AmplificationError("root_id must be in task_ids")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "root_id": self.root_id,
            "task_ids": list(self.task_ids),
            "parent_of": [list(p) for p in self.parent_of],
            "depth_of": [list(d) for d in self.depth_of],
        }


@dataclass(frozen=True)
class AmplifiedResult:
    """One completed combination over a task's leaves."""

    root_id: str
    leaf_ids: tuple[str, ...]
    leaf_digests: tuple[str, ...]
    combined_digest: str
    partial: bool
    seq: int

    def __post_init__(self) -> None:
        _require_non_empty_str(self.root_id, "root_id")
        if not self.leaf_ids:
            raise AmplificationError("result needs at least one leaf")
        if len(self.leaf_ids) != len(self.leaf_digests):
            raise AmplificationError("leaf ids and digests must align")
        for lid in self.leaf_ids:
            _require_non_empty_str(lid, "leaf_id")
        for dg in self.leaf_digests:
            if not isinstance(dg, str) or not dg.startswith("sha256:"):
                raise AmplificationError("leaf digest must be a sha256: pin")
        if not isinstance(self.combined_digest, str) or not self.combined_digest.startswith(
            "sha256:"
        ):
            raise AmplificationError("combined_digest must be a sha256: pin")
        if not isinstance(self.partial, bool):
            raise AmplificationError("partial must be a bool")
        _require_int_seq(self.seq, "seq")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "root_id": self.root_id,
            "leaf_ids": list(self.leaf_ids),
            "leaf_digests": list(self.leaf_digests),
            "combined_digest": self.combined_digest,
            "partial": self.partial,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class DistillationPair:
    """One (task, amplified answer) pair for the distillation loop."""

    task_id: str
    leaf_count: int
    combined_digest: str
    seq: int

    def __post_init__(self) -> None:
        _require_non_empty_str(self.task_id, "task_id")
        _require_int_seq(self.leaf_count, "leaf_count")
        if self.leaf_count < 1:
            raise AmplificationError("leaf_count must be >= 1")
        if not isinstance(self.combined_digest, str) or not self.combined_digest.startswith(
            "sha256:"
        ):
            raise AmplificationError("combined_digest must be a sha256: pin")
        _require_int_seq(self.seq, "seq")

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "task_id": self.task_id,
            "leaf_count": self.leaf_count,
            "combined_digest": self.combined_digest,
            "seq": self.seq,
        }


class Amplifier:
    """Owns the decomposition tree and combination bookkeeping.

    All methods are deterministic; tree order is registration order.
    """

    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_branching: int = DEFAULT_MAX_BRANCHING,
    ) -> None:
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 1:
            raise AmplificationError("max_depth must be a positive int")
        if (
            isinstance(max_branching, bool)
            or not isinstance(max_branching, int)
            or max_branching < 1
        ):
            raise AmplificationError("max_branching must be a positive int")
        self._max_depth = max_depth
        self._max_branching = max_branching
        self._tasks: dict[str, Task] = {}
        self._children: dict[str, tuple[str, ...]] = {}
        self._distillation: list[DistillationPair] = []

    @property
    def max_depth(self) -> int:
        return self._max_depth

    @property
    def max_branching(self) -> int:
        return self._max_branching

    # -- registration & decomposition ------------------------------------

    def register_root(self, description: str, *, task_id: str, seq: int) -> Task:
        """Record a root task (no parent, depth 0)."""
        _require_non_empty_str(task_id, "task_id")
        if task_id in self._tasks:
            raise AmplificationError(f"task id already registered: {task_id!r}")
        task = Task(
            task_id=task_id,
            description=description,
            parent_id=None,
            depth=0,
            seq=_require_int_seq(seq, "seq"),
        )
        self._tasks[task_id] = task
        self._children[task_id] = ()
        return task

    def decompose(
        self, parent_id: str, child_descriptions: Iterable[str], *, seq: int
    ) -> Decomposition:
        """Break a task into subtasks; records the decomposition.

        Fail-closed: unknown parent, already-decomposed parent, empty or
        oversized child list, depth-cap breach, and id collisions all
        raise ``AmplificationError``.
        """
        _require_non_empty_str(parent_id, "parent_id")
        parent = self._tasks.get(parent_id)
        if parent is None:
            raise AmplificationError(f"unknown parent task: {parent_id!r}")
        if self._children[parent_id]:
            raise AmplificationError(
                f"task already decomposed: {parent_id!r} (tree rewrite refused)"
            )
        children = list(child_descriptions)
        if not children:
            raise AmplificationError("decomposition needs at least one child")
        if len(children) > self._max_branching:
            raise AmplificationError(
                f"branching {len(children)} exceeds cap {self._max_branching}"
            )
        if parent.depth + 1 > self._max_depth:
            raise AmplificationError(
                f"depth {parent.depth + 1} exceeds cap {self._max_depth}"
            )
        child_ids: list[str] = []
        for i, desc in enumerate(children):
            _require_non_empty_str(desc, f"child_descriptions[{i}]")
            cid = f"{parent_id}.{i}"
            if cid in self._tasks:
                raise AmplificationError(f"child id collision: {cid!r}")
            child_ids.append(cid)
        seq = _require_int_seq(seq, "seq")
        digest = _digest_pin(parent_id, *child_ids, str(seq))
        decomposition = Decomposition(
            parent_id=parent_id, child_ids=tuple(child_ids), seq=seq, digest=digest
        )
        for i, cid in enumerate(child_ids):
            self._tasks[cid] = Task(
                task_id=cid,
                description=children[i],
                parent_id=parent_id,
                depth=parent.depth + 1,
                seq=seq,
            )
        self._children[parent_id] = tuple(child_ids)
        for cid in child_ids:
            self._children[cid] = ()
        return decomposition

    def amplify(
        self,
        task_id: str,
        plan: Mapping[str, Iterable[str]],
        *,
        depth: int,
        seq: int,
    ) -> AmplificationTree:
        """Recursively decompose per ``plan`` up to ``depth`` levels.

        ``plan`` maps a task id to its child descriptions. ``depth`` is
        the number of decomposition rounds below ``task_id`` (0 means
        the root alone). Entries naming unknown task ids raise.
        """
        _require_non_empty_str(task_id, "task_id")
        if task_id not in self._tasks:
            raise AmplificationError(f"unknown task: {task_id!r}")
        if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
            raise AmplificationError("depth must be a non-negative int")
        if not isinstance(plan, Mapping):
            raise AmplificationError("plan must be a mapping")
        for key in plan:
            _require_non_empty_str(key, "plan key")
            if key not in self._tasks and not self._is_future_id(key):
                raise AmplificationError(f"plan names unknown task: {key!r}")
        seq = _require_int_seq(seq, "seq")

        frontier = [task_id]
        for _ in range(depth):
            nxt: list[str] = []
            for tid in frontier:
                raw = plan.get(tid)
                if raw is None:
                    continue
                children = list(raw)
                if not children:
                    continue
                dec = self.decompose(tid, children, seq=seq)
                nxt.extend(dec.child_ids)
            if not nxt:
                break
            frontier = nxt
        return self.tree(task_id)

    def _is_future_id(self, key: str) -> bool:
        # A plan key may name a task that will exist once an ancestor is
        # decomposed (e.g. "t0.0" before "t0" is decomposed). Allow the
        # dotted-descendant shape; anything else must already exist.
        parts = key.split(".")
        return len(parts) > 1 and parts[0] in self._tasks

    # -- inspection ------------------------------------------------------

    def tree(self, task_id: str) -> AmplificationTree:
        """Frozen snapshot of the subtree rooted at ``task_id``."""
        _require_non_empty_str(task_id, "task_id")
        if task_id not in self._tasks:
            raise AmplificationError(f"unknown task: {task_id!r}")
        ordered: list[str] = []
        stack = [task_id]
        while stack:
            tid = stack.pop(0)
            ordered.append(tid)
            stack.extend(self._children[tid])
        return AmplificationTree(
            root_id=task_id,
            task_ids=tuple(ordered),
            parent_of=tuple((t.task_id, t.parent_id) for t in (self._tasks[i] for i in ordered)),
            depth_of=tuple((t.task_id, t.depth) for t in (self._tasks[i] for i in ordered)),
        )

    def leaves(self, task_id: str) -> tuple[Task, ...]:
        """Tasks under ``task_id`` with no children, registration order."""
        _require_non_empty_str(task_id, "task_id")
        if task_id not in self._tasks:
            raise AmplificationError(f"unknown task: {task_id!r}")
        return tuple(
            self._tasks[tid]
            for tid in self._descendants(task_id)
            if not self._children[tid]
        )

    def _descendants(self, task_id: str) -> list[str]:
        ordered: list[str] = []
        stack = [task_id]
        while stack:
            tid = stack.pop(0)
            ordered.append(tid)
            stack.extend(self._children[tid])
        return ordered

    def verify_tree(self, task_id: str) -> bool:
        """Structural audit: lineage, depth, uniqueness. Never raises."""
        try:
            tree = self.tree(task_id)
        except AmplificationError:
            return False
        seen: set[str] = set()
        for tid in tree.task_ids:
            if tid in seen:
                return False
            seen.add(tid)
            task = self._tasks[tid]
            if tid == tree.root_id:
                if task.parent_id is not None or task.depth != 0:
                    return False
            else:
                parent = self._tasks.get(task.parent_id or "")
                if parent is None:
                    return False
                if task.depth != parent.depth + 1:
                    return False
                if tid not in self._children.get(task.parent_id or "", ()):
                    return False
            if len(self._children[tid]) > self._max_branching:
                return False
            if task.depth > self._max_depth:
                return False
        return True

    # -- combination & distillation --------------------------------------

    def combine(
        self,
        task_id: str,
        leaf_outputs: Mapping[str, str],
        *,
        synthesized: str,
        seq: int,
        allow_partial: bool = False,
    ) -> AmplifiedResult:
        """Pin a combination of every leaf's output.

        ``leaf_outputs`` maps each leaf task id to its output text.
        Coverage is strict by default: a missing leaf or an unknown id
        raises ``AmplificationError``. With ``allow_partial=True`` the
        result is recorded with ``partial=True`` instead.
        """
        _require_non_empty_str(task_id, "task_id")
        if task_id not in self._tasks:
            raise AmplificationError(f"unknown task: {task_id!r}")
        if not isinstance(leaf_outputs, Mapping):
            raise AmplificationError("leaf_outputs must be a mapping")
        _require_non_empty_str(synthesized, "synthesized")
        if not isinstance(allow_partial, bool):
            raise AmplificationError("allow_partial must be a bool")
        seq = _require_int_seq(seq, "seq")

        leaves = self.leaves(task_id)
        leaf_ids = tuple(leaf.task_id for leaf in leaves)
        if not leaf_ids:
            raise AmplificationError("no leaves to combine")
        unknown = [k for k in leaf_outputs if k not in leaf_ids]
        if unknown:
            raise AmplificationError(f"outputs for unknown leaves: {unknown!r}")
        missing = [lid for lid in leaf_ids if lid not in leaf_outputs]
        if missing and not allow_partial:
            raise AmplificationError(f"missing leaf outputs: {missing!r}")
        covered = tuple(lid for lid in leaf_ids if lid in leaf_outputs)
        for lid in covered:
            out = leaf_outputs[lid]
            if not isinstance(out, str) or not out.strip():
                raise AmplificationError(f"leaf output must be non-empty: {lid!r}")
        leaf_digests = tuple(_digest_pin(lid, leaf_outputs[lid]) for lid in covered)
        combined_digest = _digest_pin("combined", task_id, *leaf_digests, synthesized)
        result = AmplifiedResult(
            root_id=task_id,
            leaf_ids=covered,
            leaf_digests=leaf_digests,
            combined_digest=combined_digest,
            partial=bool(missing),
            seq=seq,
        )
        self._distillation.append(
            DistillationPair(
                task_id=task_id,
                leaf_count=len(covered),
                combined_digest=combined_digest,
                seq=seq,
            )
        )
        return result

    def distillation_ledger(self) -> tuple[DistillationPair, ...]:
        """(task, amplified answer) pairs for the distillation loop."""
        return tuple(self._distillation)

    def amplification_audit_event(self, result: AmplifiedResult, *, seq: int) -> dict:
        """Audit-shaped record for a completed combination."""
        if not isinstance(result, AmplifiedResult):
            raise AmplificationError("result must be an AmplifiedResult")
        event = result.as_dict()
        event["audit_seq"] = _require_int_seq(seq, "seq")
        return event


def main() -> None:
    amp = Amplifier(max_depth=2, max_branching=4)
    amp.register_root("audit the quarterly ledger", task_id="t0", seq=1)
    tree = amp.amplify(
        "t0",
        plan={
            "t0": ["check revenue", "check expenses"],
            "t0.0": ["revenue: subscriptions", "revenue: services"],
        },
        depth=2,
        seq=2,
    )
    assert tree.root_id == "t0"
    leaves = amp.leaves("t0")
    assert [l.task_id for l in leaves] == ["t0.1", "t0.0.0", "t0.0.1"], [l.task_id for l in leaves]
    assert amp.verify_tree("t0")
    result = amp.combine(
        "t0",
        {l.task_id: "clean" for l in leaves},
        synthesized="ledger is clean",
        seq=3,
    )
    assert result.partial is False
    assert len(result.leaf_ids) == 3
    assert len(amp.distillation_ledger()) == 1
    # Partial combination is recorded, not silent.
    amp2 = Amplifier()
    amp2.register_root("r", task_id="r", seq=1)
    amp2.decompose("r", ["a", "b"], seq=2)
    partial = amp2.combine(
        "r", {"r.0": "ok"}, synthesized="half done", seq=3, allow_partial=True
    )
    assert partial.partial is True
    print(
        "iterated-amplification OK: decompose -> amplify -> combine -> "
        f"distill (schema {SCHEMA_PIN})"
    )


if __name__ == "__main__":
    main()
