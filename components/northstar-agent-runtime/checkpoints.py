"""Turn-boundary checkpoints: resume without resetting the counters, fork without rewriting.

What was missing
----------------
``--resume`` replays a stored transcript and continues in the same file, which had
two defects that matter more than convenience:

1. **A resumed run started a fresh budget and a fresh turn count.** The ceilings
   ``max_turns`` / ``max_tool_calls`` / ``max_budget_usd`` are per-run, so resuming a
   run that had already spent ``$4.90`` of a ``$5`` budget gave it the full ``$5``
   again. Resume was an escape hatch around the ceilings, not just a restart.
2. **There was no boundary to resume *from*.** A run that died at turn 18 could only
   be continued from its last recorded message, with no record of what it had
   consumed by then, and no way to say "go back to turn 6 and take the other branch".

A checkpoint is the missing artefact: at a turn boundary the loop appends one record
holding the transcript length, a digest of exactly that prefix, and the consumed
budget/turn/tool-call counters. Resuming reads the newest (or a chosen) checkpoint,
truncates the rebuilt transcript to its length, checks the digest, and *starts with
the counters it inherited*. The digest check is what makes the record worth having:
if the prefix is not byte-identical to what we recorded, the fork point is a
different history and the run refuses to start.

Fork-on-read, not rewind-in-place
---------------------------------
Resuming writes to a **new** session id whose ``session_start`` record names the
parent and the checkpoint it came from (``--resume-parent`` opts into the old
extend-the-same-file behaviour). Nothing is ever rewritten or truncated in the
parent's file - the append-only transcript stays an accurate record of what
happened in that run, and a fork is a child rather than an edit. Two runs forked
from the same checkpoint are two files, comparable after the fact.

Checkpoints are opt-in (``checkpoint_turns`` / ``--checkpoint-turns``) because they
add one record per boundary to every transcript, and a default-on audit change is a
format change, not a feature flag.

Lineage, not position
---------------------
A transcript records checkpoints in the order they were *appended*.  That order is
not the order they *descend from*.  A run that pauses for a human answer and
writes a second checkpoint at the same boundary has two checkpoints with the same
turn count; the second supersedes the first, and the only thing that says so is
the link between them.  So every checkpoint carries two new fields:

* ``previous_checkpoint_id`` - the checkpoint this one continues from.  A
  checkpoint with no previous id is a **genesis**: the start of a lineage.
* ``graph_signature_hash`` - the hash of the *run graph* the checkpoint was taken
  under (see :func:`run_graph_hash`).  A checkpoint taken under one graph must
  not be resumed under a different one.

**Ordering rule (do not change this):** checkpoints are ordered by their
``previous_checkpoint_id`` lineage chain, and by nothing else.  ``turns`` and
``record_index`` are *positions in a transcript*, not lineage: two checkpoints
can share a turn count, and a fork can put a later record index on an earlier
branch.  ``select()`` walks the chain; it never sorts by turn count or record
index.

**Resume rule (fail closed):** a resume is refused when the checkpoint's
``graph_signature_hash`` is present and disagrees with the current run graph's
hash, and when the checkpoint's ``previous_checkpoint_id`` names a checkpoint
that is not in the record set (a dangling lineage).  The first means "this
checkpoint is from a different run"; the second means "this checkpoint's
history is missing", and a checkpoint whose history is missing cannot vouch for
its own counters.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

#: The transcript record type this module writes (and the 13th ``RECORD_TYPES``).
CHECKPOINT_TYPE = "checkpoint"

#: Length of a SHA-256 digest in lowercase hex.
_SHA256_HEX_LEN = 64


def _is_sha256_hex(value: Any) -> bool:
    """True when ``value`` is a lowercase 64-character SHA-256 hex digest."""
    return (
        isinstance(value, str)
        and len(value) == _SHA256_HEX_LEN
        and all(ch in "0123456789abcdef" for ch in value)
    )


def run_graph_hash(
    *,
    steps: Sequence[Any] = (),
    permission_mode: str = "",
    policy_revision: str | None = None,
) -> str:
    """The hash of the *run graph* a checkpoint is taken under.

    The run graph is the shape of the run: its ordered steps (or loop
    configuration), the permission mode it runs under, and the policy revision
    in force.  It is deliberately **not** the model name and **not** the
    transcript digest: two runs of the same graph with different prompts are the
    same graph, and a checkpoint must survive a resumed run whose prompt was
    rewritten.  What must not change is the *shape* - the steps, the authority
    ceiling, and the policy.

    The description is canonicalised (JSON, sorted keys) before hashing, so the
    same graph spelled two ways hashes the same.
    """
    description = {
        "steps": [dict(item) if isinstance(item, Mapping) else str(item) for item in steps],
        "permission_mode": str(permission_mode or ""),
        "policy_revision": None if policy_revision is None else str(policy_revision),
    }
    canonical = json.dumps(description, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical(transcript: Sequence[Any]) -> str:
    """Deterministic text for a message list, shared by write and read paths.

    ``event_to_dict`` is used rather than ``repr`` so the digest describes the same
    bytes a reader of the transcript file would see, and sorting keys removes
    dict-ordering as a source of false mismatch.
    """
    from events import event_to_dict

    payload = []
    for message in transcript:
        try:
            payload.append(event_to_dict(message))
        except Exception:  # noqa: BLE001 - an unknown object must not silently digest
            payload.append({"type": "opaque", "rendered": str(message)})
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


def digest_transcript(transcript: Sequence[Any]) -> str:
    return hashlib.sha256(_canonical(transcript).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Checkpoint:
    """A resumable boundary: how far the transcript had got, and what it cost."""

    session_id: str
    record_index: int
    transcript_len: int
    transcript_digest: str
    turns: int
    tool_calls: int
    cost_usd: float
    usage: dict[str, int]
    model: str
    provider: str
    permission_mode: str
    run_id: str | None = None
    policy_revision: str | None = None
    denials: int = 0
    tool_limit_prefix: tuple[str, ...] = ()
    composition_history: tuple[str, ...] | None = None
    composition_policy_digest: str | None = None
    #: The checkpoint this one continues from.  ``None`` is a genesis.
    previous_checkpoint_id: str | None = None
    #: Hash of the run graph the checkpoint was taken under.
    graph_signature_hash: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "session_id": self.session_id,
            "record_index": self.record_index,
            "transcript_len": self.transcript_len,
            "transcript_digest": self.transcript_digest,
            "turns": self.turns,
            "tool_calls": self.tool_calls,
            "cost_usd": self.cost_usd,
            "usage": dict(self.usage),
            "model": self.model,
            "provider": self.provider,
            "permission_mode": self.permission_mode,
            "run_id": self.run_id,
            "policy_revision": self.policy_revision,
            "denials": self.denials,
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "graph_signature_hash": self.graph_signature_hash,
        }
        if self.composition_history is not None:
            payload["composition_history"] = list(self.composition_history)
        if self.composition_policy_digest is not None:
            payload["composition_policy_digest"] = self.composition_policy_digest
        return payload

    @property
    def label(self) -> str:
        return f"turn {self.turns} ({self.transcript_len} messages, ${self.cost_usd:.6f} spent)"


class CheckpointError(ValueError):
    """A checkpoint that cannot be trusted as a fork point."""


def build(
    *,
    session_id: str,
    record_index: int,
    transcript: Sequence[Any],
    turns: int,
    tool_calls: int,
    cost_usd: float,
    usage: Mapping[str, Any],
    model: str,
    provider: str,
    permission_mode: str,
    run_id: str | None = None,
    policy_revision: str | None = None,
    denials: int = 0,
    composition_history: Sequence[str] | None = None,
    composition_policy_digest: str | None = None,
    previous_checkpoint_id: str | None = None,
    graph_signature_hash: str | None = None,
) -> dict[str, Any]:
    """The record payload appended at a boundary. Read-only: nothing here mutates."""
    if composition_history is not None and (
        len(composition_history) > 32
        or any(not isinstance(item, str) or len(item) > 256 for item in composition_history)
    ):
        raise CheckpointError("composition_history must contain at most 32 category labels of at most 256 characters")
    if composition_policy_digest is not None and (
        not isinstance(composition_policy_digest, str)
        or len(composition_policy_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in composition_policy_digest)
    ):
        raise CheckpointError("composition_policy_digest must be a lowercase SHA-256 hex digest")
    if graph_signature_hash is not None and not _is_sha256_hex(graph_signature_hash):
        raise CheckpointError("graph_signature_hash must be a lowercase SHA-256 hex digest")
    if previous_checkpoint_id is not None and (
        not isinstance(previous_checkpoint_id, str) or not previous_checkpoint_id
    ):
        raise CheckpointError("previous_checkpoint_id must be a non-empty string when present")
    payload = Checkpoint(
        session_id=session_id,
        record_index=record_index,
        transcript_len=len(transcript),
        transcript_digest=digest_transcript(transcript),
        turns=turns,
        tool_calls=tool_calls,
        cost_usd=float(cost_usd),
        usage={
            "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
            "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
            "cache_read_input_tokens": int(getattr(usage, "cache_read_input_tokens", 0) or 0),
            "cache_creation_input_tokens": int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
        },
        model=model,
        provider=provider,
        permission_mode=permission_mode,
        run_id=run_id,
        policy_revision=policy_revision,
        denials=denials,
        composition_history=tuple(composition_history) if composition_history is not None else None,
        composition_policy_digest=composition_policy_digest,
        previous_checkpoint_id=previous_checkpoint_id,
        graph_signature_hash=graph_signature_hash,
    )
    return {"agent": "main", **payload.as_dict()}


def from_record(record: Mapping[str, Any]) -> Checkpoint | None:
    """Read one checkpoint, or ``None`` when the record is not one.

    Tolerant by design: a transcript is append-only and may contain records written
    by an older or newer runtime. Unknown shapes are skipped, never fatal - but a
    *recognised* checkpoint that is missing a field raises, because silently
    restoring partial counters is how a budget leak comes back.
    """
    if record.get("type") != CHECKPOINT_TYPE:
        return None
    required = ("transcript_len", "transcript_digest", "turns", "tool_calls", "cost_usd")
    missing = [name for name in required if record.get(name) is None]
    if missing:
        raise CheckpointError(f"checkpoint record #{record.get('index')} is missing {', '.join(missing)}")
    history_raw = record.get("composition_history")
    if "composition_history" in record and (
        not isinstance(history_raw, list)
        or len(history_raw) > 32
        or any(not isinstance(item, str) or len(item) > 256 for item in history_raw)
    ):
        raise CheckpointError("checkpoint composition_history is malformed")
    policy_digest = record.get("composition_policy_digest")
    if policy_digest is not None and (
        not isinstance(policy_digest, str)
        or len(policy_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in policy_digest)
    ):
        raise CheckpointError("checkpoint composition_policy_digest is malformed")
    graph_hash = record.get("graph_signature_hash")
    if graph_hash is not None and not _is_sha256_hex(graph_hash):
        raise CheckpointError("checkpoint graph_signature_hash is malformed")
    previous_id = record.get("previous_checkpoint_id")
    if previous_id is not None and (not isinstance(previous_id, str) or not previous_id):
        raise CheckpointError("checkpoint previous_checkpoint_id is malformed")
    return Checkpoint(
        session_id=str(record.get("session_id", "") or ""),
        record_index=int(record.get("index", -1)),
        transcript_len=int(record["transcript_len"]),
        transcript_digest=str(record["transcript_digest"]),
        turns=int(record["turns"]),
        tool_calls=int(record["tool_calls"]),
        cost_usd=float(record["cost_usd"]),
        usage=dict(record.get("usage") or {}),
        model=str(record.get("model", "") or ""),
        provider=str(record.get("provider", "") or ""),
        permission_mode=str(record.get("permission_mode", "") or ""),
        run_id=record.get("run_id"),
        policy_revision=record.get("policy_revision"),
        denials=int(record.get("denials", 0) or 0),
        composition_history=tuple(history_raw) if history_raw is not None else None,
        composition_policy_digest=policy_digest,
        previous_checkpoint_id=previous_id,
        graph_signature_hash=graph_hash,
    )


def _checkpoint_key(checkpoint: Checkpoint) -> str:
    """The stable identity of a checkpoint inside a lineage."""
    if checkpoint.run_id:
        return f"{checkpoint.run_id}:{checkpoint.record_index}"
    return f"record:{checkpoint.record_index}"


def _lineage_ids(checkpoint: Checkpoint) -> tuple[str, ...]:
    """The identities a checkpoint's ``previous_checkpoint_id`` may name.

    A previous id is recorded by the writer, and the writer's own naming
    convention is not fixed: it may be the store's checkpoint id (``ck-2``)
    or the lineage key this module uses (``record:2``).  Both are accepted, and
    both resolve to the same ancestor, so a checkpoint written by one tool is
    still readable by another.
    """
    previous = checkpoint.previous_checkpoint_id
    if not previous:
        return ()
    candidates = [previous]
    if not previous.startswith("record:"):
        candidates.append(f"record:{previous}")
    return tuple(candidates)


def _find_ancestor(
    by_key: Mapping[str, Checkpoint],
    checkpoint: Checkpoint,
) -> Checkpoint | None:
    """The ancestor a checkpoint names, if the record set holds it.

    The previous id is matched against the ids the record set knows: the
    lineage key of every checkpoint, and the raw previous id as written.  A
    store names its checkpoints its own way (``ck-1``, ``ck-000001``), so an
    id whose trailing number is a record index in this session resolves to
    that record.  The ancestor is therefore found by *identity*, not by a
    naming convention the writer chose.
    """
    for candidate in _lineage_ids(checkpoint):
        found = by_key.get(candidate)
        if found is not None and found is not checkpoint:
            return found
    suffix = _trailing_index(checkpoint.previous_checkpoint_id)
    if suffix is not None:
        for candidate in by_key.values():
            if candidate is checkpoint:
                continue
            if candidate.record_index == suffix and (
                not checkpoint.session_id or candidate.session_id == checkpoint.session_id
            ):
                return candidate
    return None


def _trailing_index(checkpoint_id: str | None) -> int | None:
    """The record index a store-style checkpoint id names, if any.

    ``ck-1`` names record 1, ``ck-000007`` names record 7, ``record:3`` names
    record 3.  An id that ends in no number names nothing.
    """
    if not checkpoint_id:
        return None
    tail = ""
    for char in reversed(checkpoint_id):
        if char.isdigit():
            tail = char + tail
        else:
            break
    if not tail:
        return None
    return int(tail)


def _lineage_depth(
    checkpoint: Checkpoint,
    by_key: Mapping[str, Checkpoint],
) -> tuple[int, bool]:
    """``(depth, intact)`` for a checkpoint's lineage.

    ``depth`` is the number of ancestors reachable through
    ``previous_checkpoint_id``.  ``intact`` is False when the chain is
    **dangling**: some ancestor is named but not present in the record set.  A
    dangling lineage means the checkpoint's history is missing, so the chain
    cannot vouch for it - the resume is refused (fail closed).
    """
    depth = 0
    seen: set[str] = set()
    current = checkpoint
    while current.previous_checkpoint_id:
        depth += 1
        if depth > len(by_key) + 1:
            # A cycle in the chain: treat it as dangling rather than looping.
            return depth, False
        parent = _find_ancestor(by_key, current)
        if parent is None:
            # The ancestor is named but absent from the record set: dangling.
            return depth, False
        if parent is current or current.previous_checkpoint_id in seen:
            return depth, False
        seen.add(current.previous_checkpoint_id)
        current = parent
    return depth, True


def _latest_by_lineage(checkpoints: Sequence[Checkpoint]) -> Checkpoint:
    """The checkpoint at the head of the deepest intact lineage."""
    by_key: dict[str, Checkpoint] = {}
    for checkpoint in checkpoints:
        by_key.setdefault(_checkpoint_key(checkpoint), checkpoint)
    best: Checkpoint | None = None
    best_key: tuple[int, bool, int, int] = (-1, False, -1, -1)
    for position, checkpoint in enumerate(checkpoints):
        depth, intact = _lineage_depth(checkpoint, by_key)
        # Intact lineages beat dangling ones; then the depth of the lineage;
        # then the record index as a stability tiebreak only.
        key = (1 if intact else 0, depth, checkpoint.record_index, position)
        if best is None or key > best_key:
            best = checkpoint
            best_key = key
    assert best is not None
    return best


def select(records: Sequence[Mapping[str, Any]], *, record_index: int | None = None) -> Checkpoint | None:
    """The newest checkpoint, or the one at ``record_index``.

    The latest is the default because it is the only one that preserves the run's
    own accounting; an earlier one is a deliberate rewind and must be named.

    Ordering is by the **lineage chain**, not by ``turns`` and not by
    ``record_index``: a checkpoint's position in the transcript says where it was
    written, not what it descends from.  Two checkpoints can share a turn count
    (a run that pauses for a human answer writes a second checkpoint at the same
    boundary), and a fork puts a later record index on an earlier branch.  So
    the chain is walked backwards from the deepest checkpoint, following
    ``previous_checkpoint_id``; a checkpoint no other checkpoint names as its
    predecessor is a leaf, and among leaves the one whose lineage is longest
    wins.  Ties fall back to ``record_index`` only to make the choice stable -
    never as the primary ordering.
    """
    found = [checkpoint for record in records if (checkpoint := from_record(record)) is not None]
    if record_index is None:
        if not found:
            return None
        return _latest_by_lineage(found)
    for checkpoint in found:
        if checkpoint.record_index == record_index:
            return checkpoint
    available = ", ".join(f"#{item.record_index}" for item in found) or "(none)"
    raise CheckpointError(f"no checkpoint at record #{record_index}; this session has {available}")


def _require_intact_lineage(checkpoint: Checkpoint, siblings: Sequence[Checkpoint]) -> None:
    """Refuse a checkpoint whose lineage chain is broken or cyclic.

    A genesis (no previous id) passes.  A checkpoint that names a previous
    checkpoint must find it in ``siblings``; a missing ancestor is a dangling
    lineage and fails closed.
    """
    if checkpoint.previous_checkpoint_id is None:
        return
    by_key: dict[str, Checkpoint] = {}
    for item in siblings:
        by_key.setdefault(_checkpoint_key(item), item)
    current = checkpoint
    seen: set[str] = set()
    while current.previous_checkpoint_id:
        parent = _find_ancestor(by_key, current)
        if parent is None:
            raise CheckpointError(
                f"checkpoint lineage is dangling: previous checkpoint {current.previous_checkpoint_id!r} "
                "is not in the record set, so this checkpoint's history cannot be verified"
            )
        if parent is current or current.previous_checkpoint_id in seen:
            raise CheckpointError(
                f"checkpoint lineage is cyclic at {current.previous_checkpoint_id!r}: the chain cannot be verified"
            )
        seen.add(current.previous_checkpoint_id)
        current = parent
    # The chain walked down to a checkpoint that names no predecessor: a genesis.


def prepare_resume(
    checkpoint: Checkpoint,
    transcript: Sequence[Any],
    *,
    expected_session_id: str | None = None,
    expected_graph_hash: str | None = None,
    records: Sequence[Mapping[str, Any]] | None = None,
) -> list[Any]:
    """The prefix a resumed run should start from, verified against the digest.

    Refuses, rather than degrading, when the transcript no longer matches what the
    checkpoint recorded: the run would otherwise inherit counters describing a
    different history, which is exactly the trust this module exists to provide.

    Two further refusals belong here, because both are the same failure - a
    checkpoint vouching for a history it cannot prove:

    * **Graph mismatch.** When the checkpoint carries a ``graph_signature_hash``
      and the caller knows the current run graph's hash
      (``expected_graph_hash``), the two must agree.  A checkpoint taken under a
      different graph is refused.  When the caller does not know the hash, the
      check cannot be made and the resume proceeds - the checkpoint is not
      *contradicted*, only unverifiable.
    * **Dangling lineage.** When ``records`` is supplied, the checkpoint's
      ``previous_checkpoint_id`` must name a checkpoint present in that set.  A
      missing ancestor means the lineage is broken, and a broken lineage cannot
      vouch for the counters.  A checkpoint with no previous id is a genesis
      and is always allowed.
    """
    if expected_session_id is not None and checkpoint.session_id and checkpoint.session_id != expected_session_id:
        raise CheckpointError(
            f"checkpoint belongs to session {checkpoint.session_id!r}, not {expected_session_id!r}"
        )
    if checkpoint.graph_signature_hash is not None and expected_graph_hash is not None:
        if not _is_sha256_hex(expected_graph_hash):
            raise CheckpointError("expected_graph_hash must be a lowercase SHA-256 hex digest")
        if checkpoint.graph_signature_hash != expected_graph_hash:
            raise CheckpointError(
                "checkpoint was taken under a different run graph "
                f"(checkpoint {checkpoint.graph_signature_hash[:12]}, current {expected_graph_hash[:12]}): "
                "the run this checkpoint describes is not the run being resumed"
            )
    if records is not None:
        siblings = [item for item in (from_record(record) for record in records) if item is not None]
        _require_intact_lineage(checkpoint, siblings)
    if checkpoint.transcript_len > len(transcript):
        raise CheckpointError(
            f"checkpoint records {checkpoint.transcript_len} messages but the transcript holds {len(transcript)}: "
            "the transcript is shorter than its own checkpoint"
        )
    prefix = list(transcript[: checkpoint.transcript_len])
    actual = digest_transcript(prefix)
    if actual != checkpoint.transcript_digest:
        raise CheckpointError(
            f"transcript prefix does not match the checkpoint digest (expected {checkpoint.transcript_digest[:12]}, "
            f"got {actual[:12]}): the history this checkpoint describes is not the history in the file"
        )
    return prefix


def durable_state(
    checkpoint: Checkpoint,
    *,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The state a durable checkpoint holds for this turn boundary.

    The join between the two checkpoint layers.  ``checkpoints.Checkpoint`` is
    a turn boundary: how far the transcript got and what it cost.  The durable
    layer (:mod:`durable_resume`) needs a *state* it can hash and a run id it
    can be found under -- and it needs the pending writes kept **out** of that
    state, so a write that has not landed cannot travel inside the state as if
    it had.

    So this function returns the committed part only: the boundary's counters,
    its transcript digest, and whatever the caller adds.  The pending writes
    are a separate record under the same checkpoint, written by the durable
    layer's ``put_writes``.
    """
    payload: dict[str, Any] = {
        "transcript_len": checkpoint.transcript_len,
        "transcript_digest": checkpoint.transcript_digest,
        "turns": checkpoint.turns,
        "tool_calls": checkpoint.tool_calls,
        "cost_usd": checkpoint.cost_usd,
        "usage": dict(checkpoint.usage),
        "model": checkpoint.model,
        "provider": checkpoint.provider,
        "permission_mode": checkpoint.permission_mode,
        "run_id": checkpoint.run_id,
        "policy_revision": checkpoint.policy_revision,
        "denials": checkpoint.denials,
    }
    if extra:
        payload.update(dict(extra))
    return payload
