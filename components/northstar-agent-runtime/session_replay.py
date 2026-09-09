"""Replay a session transcript as frames, and verify what a checkpoint would give back.

``sessions show`` prints records. This module answers the two questions a record list cannot:
**what did the run actually do, turn by turn** (prompts, tool calls, denials, compactions, the
final verdict), and **is the boundary I want to resume from still trustworthy**. The second is
the reason this file exists:

* A checkpoint's value is its ``transcript_digest``: it binds a transcript *prefix* to the
  counters consumed at that moment. Recomputing that digest is the only way to know a fork point
  still describes the history in the file - a transcript that was edited, truncated or left
  half-written would otherwise hand a resumed run counters describing a different run.
* The recomputation here is the writer's own canonical form, so **a checkpoint that verifies in
  this listing is a checkpoint ``run --resume-from`` will accept** - deliberately the same code
  path, not a second approximation of it. Being able to check that before spending a run on it,
  read-only and without a lease, is the whole point of making it a command.
* Folding is a pure function of the records, so a replay is diffable: two runs forked from one
  checkpoint produce two transcripts whose frames can be compared line by line, and `--json`
  gives the same shape to a machine.

Nothing here writes, locks, or claims a lease; it reads the records it is given and prints.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

#: Verdicts for one checkpoint. ``verified`` is the only one that passes.
VERIFIED = "verified"
DIGEST_MISMATCH = "digest-mismatch"
PREFIX_SHORT = "prefix-short"
MALFORMED = "malformed"

CONTENT_PREVIEW = 160
#: Envelope keys a `note` frame hides, so the frame says what is new rather than repeating the record id.
_NOTE_HIDDEN_KEYS = ("index", "ts", "session_id", "type", "agent")
INPUT_PREVIEW = 60
#: Records that belong to the turn in progress rather than becoming frames of their own.
_TURN_ATTACHMENTS = frozenset({"tool_result", "hook", "subagent", "informational", "denial"})


@dataclass(frozen=True)
class CheckpointReport:
    """One checkpoint, plus whether the transcript still agrees with it."""

    record_index: int
    status: str
    detail: str = ""
    turn: int = 0
    transcript_len: int = 0
    tool_calls: int = 0
    cost_usd: float = 0.0
    denials: int = 0
    digest: str = ""
    model: str = ""
    provider: str = ""
    permission_mode: str = ""
    boundary: str = ""

    @property
    def verified(self) -> bool:
        return self.status == VERIFIED

    @property
    def digest_prefix(self) -> str:
        return self.digest[:12]

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_index": self.record_index,
            "status": self.status,
            "detail": self.detail,
            "turn": self.turn,
            "transcript_len": self.transcript_len,
            "tool_calls": self.tool_calls,
            "cost_usd": self.cost_usd,
            "denials": self.denials,
            "transcript_digest": self.digest,
            "model": self.model,
            "provider": self.provider,
            "permission_mode": self.permission_mode,
            "boundary": self.boundary,
        }

    def line(self) -> str:
        lead = "" if self.verified else "  ! "
        return (
            f"{lead}#{self.record_index:<4} turn {self.turn:<3} {self.transcript_len:>3} msgs  "
            f"{self.tool_calls} call(s)  ${self.cost_usd:.6f}  digest {self.digest_prefix or '(none)'}  "
            f"[{self.status}]"
        )


@dataclass(frozen=True)
class Frame:
    """One readable step of a run, and the transcript records that produced it."""

    index: int
    kind: str
    records: tuple[int, ...]
    label: str = ""
    tools: tuple[str, ...] = ()
    tool_errors: int = 0
    denials: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    agent: str = "main"
    #: How many ``governance_drift`` records this frame carries. Zero on every transcript that
    #: never caught its own policy tree moving, so the frame shape - and every consumer of it -
    #: is exactly what it was before.
    governance_drift: int = 0
    checkpoint: CheckpointReport | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "index": self.index,
            "kind": self.kind,
            "records": list(self.records),
            "label": self.label,
            "tools": list(self.tools),
            "tool_errors": self.tool_errors,
            "denials": self.denials,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "agent": self.agent,
        }
        if self.cost_usd is not None:
            payload["cost_usd"] = self.cost_usd
        if self.governance_drift:
            payload["governance_drift"] = self.governance_drift
        if self.checkpoint is not None:
            payload["checkpoint"] = self.checkpoint.as_dict()
        return payload

    def line(self) -> str:
        span = f"#{self.records[0]}" if len(self.records) == 1 else f"#{self.records[0]}-#{self.records[-1]}"
        who = "" if self.agent == "main" else f" [{self.agent}]"
        parts = [f"f{self.index:<3} {self.kind:<11} {span:<10}", f"{self.label}{who}"]
        if self.tools:
            parts.append("calls: " + ", ".join(self.tools))
        if self.tool_errors:
            parts.append(f"{self.tool_errors} tool error(s)")
        if self.denials:
            parts.append(f"{self.denials} denial(s)")
        if self.governance_drift:
            parts.append(f"{self.governance_drift} governance drift(s)")
        if self.input_tokens or self.output_tokens:
            parts.append(f"tok {self.input_tokens}+{self.output_tokens}")
        if self.cost_usd is not None:
            parts.append(f"${self.cost_usd:.6f}")
        return "  " + "  ".join(part for part in parts if part)


@dataclass
class _Turn:
    """The turn being absorbed: an assistant record plus everything that followed it."""

    started_at: int
    number: int
    agent: str = "main"
    records: list[int] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    tool_errors: int = 0
    denials: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def absorb(self, record: Mapping[str, Any]) -> None:
        index = int(record.get("index", -1) or -1)
        self.records.append(index)
        kind = str(record.get("type", ""))
        names, errors, text = _content_blocks(record.get("content"))
        self.tools.extend(names)
        self.text.extend(text)
        self.tool_errors += errors
        if kind == "denial":
            self.denials += 1

    def frame(self, index: int) -> Frame:
        label = f"turn {self.number}"
        if self.text:
            label += ": " + _preview(" ".join(self.text))
        return Frame(
            index=index,
            kind="turn",
            records=tuple([self.started_at, *self.records]),
            label=label,
            tools=tuple(self.tools),
            tool_errors=self.tool_errors,
            denials=self.denials,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            agent=self.agent,
        )


@dataclass(frozen=True)
class Replay:
    """A transcript folded into frames, with its fork points verified and its lineage named."""

    session_id: str
    frames: tuple[Frame, ...]
    checkpoints: tuple[CheckpointReport, ...]
    result: dict[str, Any]
    lineage: dict[str, Any]
    sealed: bool
    truncated_at: int | None = None
    dropped_trailing_lines: int = 0
    inherited_messages: int = 0

    @property
    def verified(self) -> bool:
        return all(report.verified for report in self.checkpoints)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "turns": sum(1 for frame in self.frames if frame.kind == "turn"),
            "tool_calls": sum(len(frame.tools) for frame in self.frames),
            "tool_errors": sum(frame.tool_errors for frame in self.frames),
            "denials": sum(frame.denials for frame in self.frames),
            "records": sum(len(frame.records) for frame in self.frames),
            # Its own count, never folded into "denials": a denial says the gate refused an
            # action, drift says the gate itself moved. A reader filters those differently.
            "governance_drift": sum(frame.governance_drift for frame in self.frames),
        }

    def summary(self) -> str:
        counts = self.counts
        checkpoints = "no checkpoints" if not self.checkpoints else (
            f"{len(self.checkpoints)} checkpoint(s), all verified" if self.verified else f"{len(self.checkpoints)} checkpoint(s), UNVERIFIED"
        )
        drift = (
            "" if not counts["governance_drift"] else f"{counts['governance_drift']} governance drift record(s), "
        )
        return (
            f"# {counts['turns']} turn(s), {counts['tool_calls']} tool call(s), {counts['tool_errors']} tool error(s), "
            f"{drift}{counts['denials']} denial(s), {checkpoints}, result={self.result.get('subtype', '(no result)')}, "
            f"sealed={'yes' if self.sealed else 'NO'}"
        )

    def render(self) -> str:
        lines = [f"== replay: {self.session_id or '(memory)'} =="]
        for frame in self.frames:
            lines.append(frame.line())
            if frame.checkpoint is not None and not frame.checkpoint.verified:
                lines.append(f"      ! {frame.checkpoint.detail}")
        if self.lineage.get("parent_session"):
            record = self.lineage.get("checkpoint_record")
            lines.append(
                f"# forked from session {self.lineage['parent_session']} record #{record if record is not None else '?'} "
                f"(inherits {self.lineage.get('turns_inherited')} turn(s), "
                f"{self.lineage.get('tool_calls_inherited')} call(s), ${float(self.lineage.get('cost_usd_inherited') or 0):.6f})"
            )
        if self.truncated_at is not None:
            lines.append(
                f"# cut at record #{self.truncated_at - 1}: everything after it is history a run resumed here would not see "
                f"({self.inherited_messages} message(s) inherited)"
            )
        if self.dropped_trailing_lines:
            lines.append(f"# note: {self.dropped_trailing_lines} torn trailing line(s) skipped (expected after a crash)")
        lines.append(self.summary())
        return "\n".join(lines)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": "northstar.replay.v1",
            "session_id": self.session_id,
            "frames": [frame.as_dict() for frame in self.frames],
            "checkpoints": [report.as_dict() for report in self.checkpoints],
            "lineage": self.lineage,
            "sealed": self.sealed,
            "truncated_at": self.truncated_at,
            "inherited_messages": self.inherited_messages,
            "counts": self.counts,
            "result": self.result,
            "verified": self.verified,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True, default=str)


# ----------------------------------------------------------------- primitives --

def _preview(value: Any, limit: int = CONTENT_PREVIEW) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _content_blocks(content: Any) -> tuple[list[str], int, list[str]]:
    """`(tool calls, error count, prose)` from API-shaped content blocks."""
    calls: list[str] = []
    errors = 0
    text: list[str] = []
    for block in content or ():
        if not isinstance(block, dict):
            text.append(str(block))
            continue
        kind = block.get("type")
        if kind == "tool_use":
            calls.append(f"{block.get('name')} {_preview(block.get('input', {}), INPUT_PREVIEW)}")
        elif kind == "tool_result":
            errors += 1 if block.get("is_error") else 0
            text.append(_preview(block.get("content", ""), INPUT_PREVIEW))
        elif kind == "text":
            text.append(str(block.get("text", "")))
        else:
            text.append(_preview(block, INPUT_PREVIEW))
    return calls, errors, [piece for piece in text if piece.strip()]


def _usage_tokens(record: Mapping[str, Any]) -> tuple[int, int]:
    usage = record.get("usage") or record.get("total_usage") or {}
    if not isinstance(usage, Mapping):
        return 0, 0
    return int(usage.get("input_tokens", 0) or 0), int(usage.get("output_tokens", 0) or 0)


def describe_checkpoint(
    record: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    *,
    transcript: Sequence[Any] | None = None,
    prefix_digest: str | None = None,
) -> CheckpointReport:
    """Verify one checkpoint *record* against the transcript it lives in.

    A recognised checkpoint that cannot be read is reported as :data:`MALFORMED` rather than
    raised: a listing has to survive one bad record to be useful during an incident, and the
    status line is where an operator needs to see it.

    ``transcript`` / ``prefix_digest`` are the batch path - see :func:`checkpoint_reports`, which
    has already rebuilt the transcript and digested this boundary's prefix. Left out, the report
    is computed the long way, which is what an ad-hoc single question ("is *this* fork point
    sound?") wants; supplied, nothing here walks the file again.
    """
    from checkpoints import CheckpointError, digest_transcript, from_record
    from sessions import transcript_from_records

    index = int(record.get("index", -1) or -1)
    try:
        checkpoint = from_record(record)
    except CheckpointError as error:
        return CheckpointReport(record_index=index, status=MALFORMED, detail=str(error))
    if checkpoint is None:
        return CheckpointReport(record_index=index, status=MALFORMED, detail="not a checkpoint record")
    fields = {
        "turn": checkpoint.turns,
        "transcript_len": checkpoint.transcript_len,
        "tool_calls": checkpoint.tool_calls,
        "cost_usd": checkpoint.cost_usd,
        "denials": checkpoint.denials,
        "digest": checkpoint.transcript_digest,
        "model": checkpoint.model,
        "provider": checkpoint.provider,
        "permission_mode": checkpoint.permission_mode,
        "boundary": str(record.get("boundary", "") or ""),
    }
    # The digest covers the *model-facing transcript*, not the file's records: a `session_start`
    # or a `checkpoint` line is written for the reader and never sent to a provider. So the
    # rebuild happens first and the cut happens after it - the same order `prepare_resume` uses,
    # which is what makes "verified here" mean "accepted by a resume".
    if transcript is None:
        transcript = transcript_from_records(list(records))
    if checkpoint.transcript_len > len(transcript):
        return CheckpointReport(
            record_index=index,
            status=PREFIX_SHORT,
            detail=(
                f"this boundary claims {checkpoint.transcript_len} messages but the transcript holds {len(transcript)}: "
                "the file is shorter than its own checkpoint"
            ),
            **fields,
        )
    actual = (
        prefix_digest
        if prefix_digest is not None
        else digest_transcript(transcript[: checkpoint.transcript_len])
    )
    if actual != checkpoint.transcript_digest:
        return CheckpointReport(
            record_index=index,
            status=DIGEST_MISMATCH,
            detail=(
                f"the prefix digests to {actual[:12]} but this boundary recorded {checkpoint.transcript_digest[:12]}: "
                "the history in this file is not the history this boundary describes, and a resume would refuse it"
            ),
            **fields,
        )
    return CheckpointReport(record_index=index, status=VERIFIED, **fields)


def checkpoint_reports(records: Sequence[Mapping[str, Any]]) -> tuple[CheckpointReport, ...]:
    """Every checkpoint in ``records``, in transcript order, each verified against the prefix.

    One pass over the transcript, not one per boundary. The obvious implementation - "for each
    checkpoint, rebuild the transcript and digest its prefix" - is quadratic in the length of
    the file: the 2026-09 audit measured 10.4 s for a 1200-boundary lineage, all of it in the
    *reader*, which is the component a human reaches for during an incident. So the transcript is
    rebuilt once, its canonical parts are hashed left to right with a running SHA-256, and each
    boundary takes the digest of its own prefix from a copy of that hash. Byte-identical to
    per-prefix ``digest_transcript``, because both routes are ``checkpoints.digest_parts``.
    """
    import hashlib

    from checkpoints import CHECKPOINT_TYPE, canonical_parts
    from sessions import transcript_from_records

    marked: list[tuple[int, Mapping[str, Any]]] = []
    for record in records:
        if record.get("type") != CHECKPOINT_TYPE:
            continue
        try:
            length = int(record.get("transcript_len", 0) or 0)
        except (TypeError, ValueError):
            length = -1  # malformed: let describe_checkpoint say so, digest nothing for it
        marked.append((length, record))
    if not marked:
        return ()

    transcript = transcript_from_records(list(records))
    parts = canonical_parts(transcript)
    wanted = {length for length, _ in marked if 0 <= length <= len(parts)}
    digests: dict[int, str] = {}
    if 0 in wanted:
        digests[0] = hashlib.sha256(b"[]").hexdigest()
    remaining = wanted - {0}
    running = hashlib.sha256(b"[")
    for position, part in enumerate(parts, start=1):
        if position > 1:
            running.update(b",")
        running.update(part.encode("utf-8"))
        if position in remaining:
            closed = running.copy()
            closed.update(b"]")
            digests[position] = closed.hexdigest()
            remaining.discard(position)
            if not remaining:
                break
    return tuple(
        describe_checkpoint(
            record,
            records,
            transcript=transcript,
            prefix_digest=digests.get(length),
        )
        for length, record in marked
    )


def lineage_of(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Where this session says it came from, read from its own ``session_start`` record.

    The loop writes the inheritance as a nested ``resumed_from`` block rather than as loose
    keys, so that a reader cannot mistake a parent-less run for a run whose parent was
    forgotten. Both shapes are accepted here - the nested one is what a current transcript
    holds, and the flat one is what ``--resume-parent`` (extend-the-same-file) used to write -
    and an absent parent is reported as ``{}`` rather than as a zero-length inheritance.
    """
    for record in records:
        if record.get("type") != "session_start":
            continue
        data = record.get("data") or {}
        origin = data.get("resumed_from") or (data if data.get("parent_session") else {})
        parent = origin.get("parent_session")
        if not parent:
            return {}
        return {
            "parent_session": str(parent),
            "checkpoint_record": origin.get("checkpoint_record"),
            "turns_inherited": origin.get("turns_inherited"),
            "tool_calls_inherited": origin.get("tool_calls_inherited"),
            "cost_usd_inherited": origin.get("cost_usd_inherited"),
            "transcript_len": origin.get("transcript_len"),
            "digest_prefix": origin.get("transcript_digest"),
            "forked": bool(origin.get("forked", True)),
        }
    return {}


def build_replay(
    records: Sequence[Mapping[str, Any]],
    *,
    session_id: str = "",
    dropped_trailing_lines: int = 0,
    upto: int | None = None,
) -> Replay:
    """Fold transcript records into frames.

    ``upto`` is the fork-point preview: only the first ``upto`` records are folded, which is
    what a run resuming from a boundary actually starts with. The replay then shows the state
    the child inherits and nothing that came after it - the difference between "the transcript
    is long" and "this is what a resume would see".
    """
    visible = list(records if upto is None else records[:upto])
    reports = {report.record_index: report for report in checkpoint_reports(visible)}
    frames: list[Frame] = []
    result: dict[str, Any] = {}
    sealed = False
    turn_number = 0
    current: _Turn | None = None

    def emit(frame: Frame) -> None:
        frames.append(frame)

    def close_turn() -> None:
        nonlocal current
        if current is not None:
            emit(current.frame(len(frames) + 1))
            current = None

    for record in visible:
        index = int(record.get("index", 0) or 0)
        kind = str(record.get("type", "unknown"))
        agent = str(record.get("agent", "main") or "main")
        if kind == "session_start":
            data = record.get("data") or {}
            limits = data.get("limits") or {}
            budget = limits.get("max_budget_usd")
            emit(
                Frame(
                    index=len(frames) + 1,
                    kind="start",
                    records=(index,),
                    label=(
                        f"{data.get('provider', '?')}/{data.get('model', '?')} mode={data.get('permission_mode', '?')} "
                        f"max_turns={limits.get('max_turns')} budget={'unlimited' if budget is None else f'${float(budget):.2f}'} "
                        f"checkpoint_turns={data.get('checkpoint_turns', 0)}"
                    ),
                    agent=agent,
                )
            )
            continue
        if kind == "user_prompt":
            close_turn()
            _calls, errors, text = _content_blocks(record.get("content"))
            emit(
                Frame(
                    index=len(frames) + 1,
                    kind="prompt",
                    records=(index,),
                    label="prompt: " + (_preview(" ".join(text)) if text else "(empty)"),
                    tool_errors=errors,
                )
            )
            continue
        if kind == "assistant":
            close_turn()
            turn_number += 1
            current = _Turn(started_at=index, number=turn_number, agent=agent)
            calls, errors, text = _content_blocks(record.get("content"))
            current.tools.extend(calls)
            current.text.extend(text)
            current.tool_errors += errors
            current.input_tokens, current.output_tokens = _usage_tokens(record)
            continue
        if current is not None and kind in _TURN_ATTACHMENTS:
            current.absorb(record)
            continue
        if kind == "checkpoint":
            close_turn()
            report = reports.get(index)
            emit(
                Frame(
                    index=len(frames) + 1,
                    kind="checkpoint",
                    records=(index,),
                    label=(
                        f"boundary {record.get('boundary', '?')} at {record.get('transcript_len', '?')} message(s) "
                        f"({record.get('turns', '?')} turn(s), {record.get('tool_calls', '?')} call(s) consumed)"
                    ),
                    agent=agent,
                    cost_usd=float(record.get("cost_usd", 0.0) or 0.0),
                    checkpoint=report,
                )
            )
            continue
        if kind == "governance_drift":
            # Its own frame rather than a turn attachment: the record is about the gate, not
            # about the work, and closing the turn puts it next to the boundary checkpoint that
            # follows it - the pair a reader wants to see side by side.
            close_turn()
            emit(
                Frame(
                    index=len(frames) + 1,
                    kind="governance_drift",
                    records=(index,),
                    label=_preview(record.get("content") or "the governance tree changed during this run"),
                    agent=agent,
                    governance_drift=1,
                )
            )
            continue
        if kind == "compact_boundary":
            close_turn()
            emit(
                Frame(
                    index=len(frames) + 1,
                    kind="compaction",
                    records=(index,),
                    label=_preview(record.get("content") or "context compacted"),
                    agent=agent,
                )
            )
            continue
        if kind == "result":
            close_turn()
            denials = list(record.get("permission_denials") or ())
            result = {
                "subtype": str(record.get("subtype", "")),
                "num_turns": record.get("num_turns"),
                "total_cost_usd": record.get("total_cost_usd"),
                "duration_ms": record.get("duration_ms"),
                "errors": [str(item) for item in (record.get("errors") or ())],
                "denials": len(denials),
                "is_error": bool(record.get("is_error")),
            }
            input_tokens, output_tokens = _usage_tokens(record)
            emit(
                Frame(
                    index=len(frames) + 1,
                    kind="result",
                    records=(index,),
                    label=f"{result['subtype']} after {result['num_turns']} turn(s)",
                    cost_usd=float(record.get("total_cost_usd") or 0.0),
                    denials=len(denials),
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                )
            )
            continue
        if kind == "session_end":
            close_turn()
            sealed = True
            continue
        close_turn()
        payload = {key: value for key, value in record.items() if key not in _NOTE_HIDDEN_KEYS}
        emit(
            Frame(
                index=len(frames) + 1,
                kind="note",
                records=(index,),
                label=f"{kind}: {_preview(payload)}",
                agent=agent,
            )
        )
    close_turn()
    from sessions import transcript_from_records

    return Replay(
        session_id=session_id,
        frames=tuple(frames),
        checkpoints=tuple(reports.values()),
        result=result,
        lineage=lineage_of(records),
        sealed=sealed,
        truncated_at=upto,
        dropped_trailing_lines=dropped_trailing_lines,
        # Counted through the reader's own filter rather than a list of record types kept here:
        # "what the child inherits" has to mean exactly what the transcript contains, and this
        # module is not the owner of that definition.
        inherited_messages=len(transcript_from_records(visible)),
    )


def load_replay(directory: str | Path, session_id: str, *, upto: int | None = None) -> tuple[Replay | None, str]:
    """Read one transcript and replay it, as ``(replay, error)`` with exactly one set.

    Living here rather than in the CLI keeps the reader and the folding together, so
    ``sessions replay``, ``sessions checkpoints`` and an embedder all see the same
    verification semantics - and so a caller that wants the objects never has to parse text.
    """
    from sessions import SESSION_FILE_SUFFIX, load_jsonl

    path = Path(directory) / f"{session_id}{SESSION_FILE_SUFFIX}"
    if not path.is_file():
        return None, f"no transcript for session {session_id!r} in {directory}"
    records, dropped = load_jsonl(path)
    return build_replay(records, session_id=session_id, dropped_trailing_lines=dropped, upto=upto), ""


def budget_headroom(records: Sequence[Mapping[str, Any]], report: CheckpointReport) -> tuple[float | None, str]:
    """What a run resumed from ``report`` would still be allowed to spend, and the catch.

    ``run --resume-from`` refuses a fork whose checkpoint had already spent the ceiling - that
    is the hole checkpoints exist to close - and this says so from the transcript alone, using
    the ceiling the parent recorded in its own ``session_start``. ``None`` means the session had
    no budget ceiling, which is not the same as "unlimited headroom": it is "nothing to check".
    """
    ceiling: float | None = None
    for record in records:
        if record.get("type") != "session_start":
            continue
        limits = (record.get("data") or {}).get("limits") or {}
        value = limits.get("max_budget_usd")
        ceiling = None if value is None else float(value)
        break
    if ceiling is None:
        return None, ""
    remaining = ceiling - report.cost_usd
    if remaining <= 0:
        return remaining, (
            f"a run resumed here would be refused: this boundary had spent ${report.cost_usd:.6f} "
            f"of the ${ceiling:.6f} ceiling"
        )
    return remaining, f"a run resumed here inherits ${report.cost_usd:.6f} spent and may still use ${remaining:.6f}"


def fork_preview(
    records: Sequence[Mapping[str, Any]],
    *,
    record_index: int,
    session_id: str = "",
    dropped_trailing_lines: int = 0,
) -> tuple[Replay | None, CheckpointReport | None, str]:
    """What a run resumed from the checkpoint at ``record_index`` would start with.

    Returns ``(replay, boundary_report, error)``. The replay is cut at the boundary's own
    ``transcript_len`` - the exact prefix the child sees - and the report says whether that cut
    still digests to what was recorded. One function serves ``sessions replay
    --from-checkpoint`` and any embedder that wants the same answer without parsing text,
    because a preview that disagreed with the real resume would be worse than no preview.
    """
    from checkpoints import CheckpointError, select

    try:
        checkpoint = select(records, record_index=record_index)
    except CheckpointError as error:
        return None, None, str(error)
    # The cut is the boundary record itself, so the replay ends on the frame that *is* the
    # fork point rather than stopping one line short of it. `transcript_len` still describes
    # what the child inherits, and says so in the replay's note.
    boundary = next((record for record in records if int(record.get("index", -1) or -1) == record_index), None)
    replay = build_replay(
        records, session_id=session_id, upto=record_index + 1, dropped_trailing_lines=dropped_trailing_lines
    )
    report = describe_checkpoint(boundary, list(records)) if boundary is not None else None
    return replay, report, ""
