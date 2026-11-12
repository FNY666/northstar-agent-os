"""Shutdown unwind: a killed turn leaves tool_use blocks with no tool_result.

What was missing
----------------
A run that is killed mid-turn leaves a transcript whose last assistant message
asks for tools that never answered. Two things were true before this module
existed, and both were wrong:

1. **The next provider request would be rejected.** A ``tool_use`` with no
   matching ``tool_result`` is not a legal request, so the resumed run failed at
   the API boundary with an opaque 400 instead of a fact about the history.
2. **Nobody could tell an interrupted turn from a clean one.** The transcript
   looked like a normal turn that happened to end early, so a resume inherited
   the parent's history as if every call in it had completed.

The fix is the same shape as the one the shutdown path in a hosted agent loop
takes: on resume, find every ``tool_use`` that never got a result and *synthesise*
one, marked as interrupted. The synthesised result is not a fact about the work
product - it is the record of a call that did not happen. So it is:

- marked ``synthetic=True`` and ``tool_denial_kind="interrupted"``,
- always ``is_error=True``,
- **never counted as a success** anywhere, and
- never turned into a ``ToolCallReport`` (a call that never ran is not a call).

A resume is then classified: ``interrupted_turn`` when the unwind synthesised
anything, ``clean`` when the parent turn finished. The classification is recorded
in the resumed run's init record so an auditor can tell the two apart without
re-deriving it.

Two rules this module does not bend
------------------------------------
* **A synthetic result never counts as success.** A counter that summed tool
  results by ``is_error`` would have to know about ``synthetic``; a counter that
  counted results by presence would count an interrupted call as a completed
  one. Both are wrong, so the exclusion is structural: the success counter takes
  only non-synthetic results, and the module exposes that filter itself.
* **A store that refuses the resume raises.** Silently continuing as if the
  session were clean would turn a broken lineage into a successful one, which is
  exactly the failure this module exists to prevent. ``ResumeRefusedError`` is
  the explicit name for that refusal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

#: The denial kind recorded on a synthesised result: the turn was cut short, so
#: the call never ran. Matches the vocabulary a hosted agent loop uses for a
#: turn aborted by shutdown or timeout.
INTERRUPTED_DENIAL_KIND = "interrupted"

#: The two resume classifications. A resume is exactly one of them.
RESUME_CLEAN = "clean"
RESUME_INTERRUPTED = "interrupted_turn"
RESUME_CLASSIFICATIONS: tuple[str, ...] = (RESUME_INTERRUPTED, RESUME_CLEAN)

#: The text a synthesised result carries to the model. It says what happened and
#: nothing more: a synthetic result is not evidence that a tool did or did not
#: do anything, so it must not read like one.
INTERRUPTED_RESULT_TEXT = (
    "[interrupted] this call did not run: the turn was cut short before it produced a result."
)


def __getattr__(name: str) -> Any:
    """Resolve ``ResumeRefusedError`` lazily.

    The canonical class lives in :mod:`sessions` (it is a ``SessionIntegrityError``,
    so a caller that already catches that still catches this one), and ``sessions``
    imports this module - so the reference cannot be resolved at import time
    without a cycle.
    """
    if name == "ResumeRefusedError":
        from sessions import ResumeRefusedError as _Canonical

        return _Canonical
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@dataclass(frozen=True)
class UnwindRecord:
    """One synthesised result: the call that never got an answer."""

    tool_use_id: str = ""
    tool_name: str = ""
    denial_kind: str = INTERRUPTED_DENIAL_KIND
    synthetic: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_use_id": self.tool_use_id,
            "tool_name": self.tool_name,
            "tool_denial_kind": self.denial_kind,
            "synthetic": self.synthetic,
        }


@dataclass(frozen=True)
class UnwindOutcome:
    """What the unwind pass did to one transcript."""

    #: ``clean`` or ``interrupted_turn``.
    classification: str = RESUME_CLEAN
    #: One entry per synthesised result, in the order the calls were asked.
    synthesised: tuple[UnwindRecord, ...] = ()

    @property
    def interrupted(self) -> bool:
        return self.classification == RESUME_INTERRUPTED

    @property
    def count(self) -> int:
        return len(self.synthesised)

    def as_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "synthesised_count": self.count,
            "synthesised": [record.as_dict() for record in self.synthesised],
        }


def _is_assistant(message: Any) -> bool:
    from providers.base import AssistantMessage

    return isinstance(message, AssistantMessage)


def _is_user(message: Any) -> bool:
    from providers.base import UserMessage

    return isinstance(message, UserMessage)


def pending_tool_uses(transcript: Sequence[Any]) -> tuple[tuple[str, str], ...]:
    """``(tool_use_id, tool_name)`` for every call that never got a result.

    A call is pending when no ``tool_result`` in the transcript names it. The
    scan is order-preserving so the synthesised results land in the order the
    calls were asked - the order a reader expects.
    """
    from providers.base import ToolUseBlock

    asked: list[tuple[str, str]] = []
    answered: set[str] = set()
    for message in transcript:
        if _is_assistant(message):
            for block in message.content:
                if isinstance(block, ToolUseBlock):
                    asked.append((block.id, block.name))
        elif _is_user(message):
            for block in message.content:
                tool_use_id = getattr(block, "tool_use_id", "")
                if tool_use_id:
                    answered.add(tool_use_id)
    return tuple((call_id, name) for call_id, name in asked if call_id and call_id not in answered)


def synthetic_result_blocks(transcript: Sequence[Any]) -> tuple[Any, ...]:
    """The synthesised results in a transcript, identified by their own marker."""
    from providers.base import ToolResultBlock

    found: list[Any] = []
    for message in transcript:
        if not _is_user(message):
            continue
        for block in message.content:
            if isinstance(block, ToolResultBlock) and block.synthetic:
                found.append(block)
    return tuple(found)


def successful_tool_results(transcript: Sequence[Any]) -> tuple[Any, ...]:
    """The tool results that count as successes.

    A synthetic result is excluded, always. It says a call did not run, so it is
    not a success of anything - and it is not an error of a tool either, which is
    why ``is_error`` alone cannot decide this.
    """
    from providers.base import ToolResultBlock

    found: list[Any] = []
    for message in transcript:
        if not _is_user(message):
            continue
        for block in message.content:
            if isinstance(block, ToolResultBlock) and not block.synthetic and not block.is_error:
                found.append(block)
    return tuple(found)


def _synthetic_block(tool_use_id: str, tool_name: str) -> Any:
    from providers.base import ToolResultBlock

    return ToolResultBlock(
        tool_use_id=tool_use_id,
        content=INTERRUPTED_RESULT_TEXT,
        is_error=True,
        tool_denial_kind=INTERRUPTED_DENIAL_KIND,
        synthetic=True,
    )


def unwind(transcript: Sequence[Any]) -> tuple[list[Any], UnwindOutcome]:
    """Return ``(unwound_transcript, outcome)`` for a resumed transcript.

    The input is not mutated. When every call has a result, the transcript is
    returned unchanged and the outcome is ``clean`` - a clean session must look
    exactly as it did before this module existed.

    The pass is **idempotent**. A resume may be unwound twice - once where the
    history is read, once where the run starts - and the second pass must not
    forget what the first one found. So a transcript that already carries
    synthetic results keeps its ``interrupted_turn`` classification and gains no
    second copy of them. Without this, the classification of a killed parent
    would depend on which layer looked first, and the run's own init record
    would disagree with the store's.
    """
    from providers.base import UserMessage

    pending = pending_tool_uses(transcript)
    existing = synthetic_result_blocks(transcript)
    if not pending:
        if existing:
            # Already unwound: the calls are answered, and the answer says the
            # turn was interrupted. That is the classification, not "clean".
            records = tuple(
                UnwindRecord(
                    tool_use_id=str(getattr(block, "tool_use_id", "") or ""),
                    tool_name="",
                    denial_kind=block.tool_denial_kind or INTERRUPTED_DENIAL_KIND,
                    synthetic=True,
                )
                for block in existing
            )
            return list(transcript), UnwindOutcome(classification=RESUME_INTERRUPTED, synthesised=records)
        return list(transcript), UnwindOutcome(classification=RESUME_CLEAN, synthesised=())

    blocks = tuple(_synthetic_block(call_id, name) for call_id, name in pending)
    records = tuple(
        UnwindRecord(tool_use_id=call_id, tool_name=name, denial_kind=INTERRUPTED_DENIAL_KIND, synthetic=True)
        for call_id, name in pending
    )
    # The synthesised results go at the end, as their own user turn: that is
    # where the provider expects a tool_result to live, and it keeps the
    # parent's own messages byte-for-byte unchanged.
    unwound = list(transcript)
    unwound.append(UserMessage(content=blocks, is_meta=True, meta_reason="shutdown unwind"))
    return unwound, UnwindOutcome(classification=RESUME_INTERRUPTED, synthesised=records)


def classify(transcript: Sequence[Any]) -> str:
    """``interrupted_turn`` when a call has no result, ``clean`` otherwise.

    A transcript that already carries synthetic results counts as interrupted:
    the calls *were* answered, but by the unwind rather than by a tool.
    """
    if pending_tool_uses(transcript) or synthetic_result_blocks(transcript):
        return RESUME_INTERRUPTED
    return RESUME_CLEAN


def require_resumable(transcript: Sequence[Any], *, source: str = "session") -> None:
    """Raise ``ResumeRefusedError`` when the transcript cannot be resumed.

    A transcript whose last assistant turn asked for tools that never answered
    is resumable *only* through the unwind pass. A caller that reaches this
    function has declined to unwind, so continuing would present an
    incomplete history to the provider as if it were complete.
    """
    from sessions import ResumeRefusedError

    pending = pending_tool_uses(transcript)
    if not pending:
        return
    names = ", ".join(f"{name or '(unnamed)'}[{call_id}]" for call_id, name in pending[:8])
    raise ResumeRefusedError(
        f"resume refused: {source} ends with {len(pending)} tool call(s) that never produced a result "
        f"({names}); unwind them first (see shutdown_unwind.unwind)"
    )


__all__ = [
    "INTERRUPTED_DENIAL_KIND",
    "INTERRUPTED_RESULT_TEXT",
    "RESUME_CLASSIFICATIONS",
    "RESUME_CLEAN",
    "RESUME_INTERRUPTED",
    "ResumeRefusedError",
    "UnwindOutcome",
    "UnwindRecord",
    "classify",
    "pending_tool_uses",
    "require_resumable",
    "successful_tool_results",
    "synthetic_result_blocks",
    "unwind",
]
