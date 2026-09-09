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
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

#: The transcript record type this module writes (and the 13th ``RECORD_TYPES``).
CHECKPOINT_TYPE = "checkpoint"


def canonical_parts(transcript: Sequence[Any]) -> list[str]:
    """The transcript as one canonical JSON element per message, in order.

    ``event_to_dict`` is used rather than ``repr`` so the digest describes the same
    bytes a reader of the transcript file would see, and sorting keys removes
    dict-ordering as a source of false mismatch.

    Split out of :func:`_canonical` for the *reader* side (``session_replay``): verifying
    every checkpoint in a file means digesting every prefix of the transcript, and having the
    per-message element is what turns that into one pass instead of a serialisation per
    boundary. ``digest_parts(canonical_parts(t)) == digest_transcript(t)`` holds by
    construction - both are defined here, against the same join.
    """
    from events import event_to_dict

    parts: list[str] = []
    for message in transcript:
        try:
            element = event_to_dict(message)
        except Exception:  # noqa: BLE001 - an unknown object must not silently digest
            element = {"type": "opaque", "rendered": str(message)}
        parts.append(json.dumps(element, sort_keys=True, ensure_ascii=False, default=str))
    return parts


def _canonical(transcript: Sequence[Any]) -> str:
    """The whole transcript as JSON: ``"["`` + the parts + ``"]"`` - and nothing else."""
    return "[" + ",".join(canonical_parts(transcript)) + "]"


def digest_parts(parts: Sequence[str]) -> str:
    """Digest of already-canonicalised parts; equals ``digest_transcript`` of their source."""
    return hashlib.sha256(("[" + ",".join(parts) + "]").encode("utf-8")).hexdigest()


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

    def as_dict(self) -> dict[str, Any]:
        return {
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
        }

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
) -> dict[str, Any]:
    """The record payload appended at a boundary. Read-only: nothing here mutates."""
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
    )


def select(records: Sequence[Mapping[str, Any]], *, record_index: int | None = None) -> Checkpoint | None:
    """The newest checkpoint, or the one at ``record_index``.

    The latest is the default because it is the only one that preserves the run's
    own accounting; an earlier one is a deliberate rewind and must be named.
    """
    found = [checkpoint for record in records if (checkpoint := from_record(record)) is not None]
    if record_index is None:
        return found[-1] if found else None
    for checkpoint in found:
        if checkpoint.record_index == record_index:
            return checkpoint
    available = ", ".join(f"#{item.record_index}" for item in found) or "(none)"
    raise CheckpointError(f"no checkpoint at record #{record_index}; this session has {available}")


def prepare_resume(
    checkpoint: Checkpoint,
    transcript: Sequence[Any],
    *,
    expected_session_id: str | None = None,
) -> list[Any]:
    """The prefix a resumed run should start from, verified against the digest.

    Refuses, rather than degrading, when the transcript no longer matches what the
    checkpoint recorded: the run would otherwise inherit counters describing a
    different history, which is exactly the trust this module exists to provide.
    """
    if expected_session_id is not None and checkpoint.session_id and checkpoint.session_id != expected_session_id:
        raise CheckpointError(
            f"checkpoint belongs to session {checkpoint.session_id!r}, not {expected_session_id!r}"
        )
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
