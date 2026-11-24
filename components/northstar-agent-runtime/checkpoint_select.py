"""Select the checkpoint a code resume should fork from.

A resume forks the parent transcript at a checkpoint.  Everything the parent
did *after* that checkpoint is discarded, so any tool call in that tail may be
replayed by the resumed run - and a tool call may have changed the worktree
already.  The runtime refuses such a fork unless the operator acknowledges the
replay; this module decides the same thing up front, so the operator learns
about it before the resumed run starts rather than from its refusal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from checkpoints import CheckpointError, from_record
from code_task import CodeTaskError
from sessions import SessionIntegrityError, SessionStore


def _post_checkpoint_tool_calls(checkpoint: Any, records: Sequence[Mapping[str, Any]]) -> int:
    """Count the tool calls a fork at ``checkpoint`` would discard."""
    count = 0
    for record in records:
        if int(record.get("index") or 0) <= int(checkpoint.transcript_len):
            continue
        if str(record.get("type") or "") != "assistant":
            continue
        blocks = record.get("content")
        if not isinstance(blocks, Sequence) or isinstance(blocks, (str, bytes)):
            continue
        for block in blocks:
            if not isinstance(block, Mapping):
                continue
            if str(block.get("type") or "") == "tool_use":
                count += 1
    return count


def select_resume_checkpoint(
    sessions_dir: str | Path,
    session_id: str,
) -> tuple[Any, int]:
    """Return the checkpoint a resume should use and how many calls it discards.

    The newest checkpoint is the only one that preserves the parent's own
    accounting; an earlier one is a deliberate rewind and would discard more of
    the run, so it is not chosen here.
    """
    directory = Path(sessions_dir)
    store = SessionStore(directory, session_id=session_id)
    try:
        records, _dropped = store.read(session_id)
    except (OSError, ValueError) as error:
        raise CodeTaskError(f"cannot read the parent session transcript: {error}") from error
    except SessionIntegrityError as error:
        # The transcript's own chain did not verify. The runtime refuses to
        # resume such a transcript on its own, so a resume cannot be
        # authorised from it either; the reason is the operator's to fix.
        raise CodeTaskError(
            f"the parent session transcript does not verify: {error}"
        ) from error

    found = []
    for record in records:
        try:
            checkpoint = from_record(record)
        except CheckpointError:
            raise
        if checkpoint is not None:
            found.append(checkpoint)
    if not found:
        raise CodeTaskError(
            f"session {session_id!r} has no checkpoints "
            "(run it with --checkpoint-turns N to make boundaries resumable)"
        )
    checkpoint = found[-1]
    discarded = _post_checkpoint_tool_calls(checkpoint, records)
    return checkpoint, discarded
