"""Context-engineering thresholds for Northstar's own context path.

The numbers here are not ours: they are the measured defaults of production
harnesses, collected from the frontier report "Context engineering inside the
harness" (MarkTechPost, 2026-09-12; GitHub mirror
``ntlx/agentic-work-atlas/20260912-context-engineering-inside-the-harness.md``):

* Deep Agents writes a tool response above **20,000 tokens** to disk and keeps
  a path plus the **first 10 lines** in context.
* At **85%** of the model window, older ``write``/``edit`` calls are reduced to
  a pointer.  Summarisation is the fallback *after* offloading, never before.
* After a compaction, a re-read of a file above **5,000 tokens** returns a path
  reference instead of content; the compaction re-reads at most **5** of the
  most recently modified files; a re-injected skill body is capped at
  **5,000 tokens** per skill and **25,000 tokens** in total.
* Auto-memory is capped at the **first 200 lines or 25KB**.
* A research subagent reads ~**6,100 tokens** and returns ~**420 tokens** to
  its parent; a general subagent returns a distilled **1,000-2,000 tokens**.
* The summary trigger defaults to 85% but may be moved to 10-20% of the window
  for evaluation (what LangChain does when comparing prompt variants).

What this module adds on top of the report is *ordering* and *measurability*:

* **offload before summarize** is an explicit sequence, not a preference;
* every pointer this module produces is recoverable - the bytes are on disk and
  the pointer names where;
* the cost of persistent memory is *bookkept*, so a run can report how much of
  its context is memory tax rather than work.

Everything is configurable through one frozen record (:class:`ContextThresholds`)
so a host can move a number without editing a rule.
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

# -- the measured defaults (source: the frontier report cited above) --------

DEFAULT_TOOL_RESULT_OFFLOAD_TOKENS = 20_000
DEFAULT_OFFLOAD_PREVIEW_LINES = 10
#: The preview is the first 10 lines *and* at most this many bytes.  The
#: report counts lines; a line count alone is not a bound on a single
#: enormous line (a minified file, a base64 blob, a JSON array on one
#: line), and an unbounded preview would put the whole result back into
#: the context -- undoing the offload it was meant to make visible.
DEFAULT_OFFLOAD_PREVIEW_MAX_BYTES = 4_000
DEFAULT_WINDOW_PRESSURE_FRACTION = 0.85
DEFAULT_SUMMARY_TRIGGER_FRACTION = 0.85
DEFAULT_REREAD_PATH_ONLY_TOKENS = 5_000
DEFAULT_REREAD_MAX_FILES = 5
DEFAULT_SKILL_BODY_MAX_TOKENS = 5_000
DEFAULT_SKILL_BODY_TOTAL_MAX_TOKENS = 25_000
DEFAULT_AUTO_MEMORY_MAX_LINES = 200
DEFAULT_AUTO_MEMORY_MAX_BYTES = 25 * 1024
DEFAULT_SUBAGENT_READ_BUDGET_TOKENS = 6_100
DEFAULT_SUBAGENT_RESULT_BUDGET_TOKENS = 420
DEFAULT_SUBAGENT_SUMMARY_MIN_TOKENS = 1_000
DEFAULT_SUBAGENT_SUMMARY_MAX_TOKENS = 2_000
DEFAULT_CONTEXT_WINDOW_TOKENS = 200_000

#: The token rule used everywhere in this module: four UTF-8 bytes per token.
#: It is the same rule the runtime's transcript estimator uses
#: (``providers.base.estimate_transcript_tokens``), so a number measured here
#: means the same thing as a number measured there.
BYTES_PER_TOKEN = 4


def estimate_text_tokens(text: str) -> int:
    """Deterministic token estimate for a piece of text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / BYTES_PER_TOKEN))


def _check_positive_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _check_fraction(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not 0 < float(value) <= 1:
        raise ValueError(f"{name} must be in (0, 1]")
    return float(value)


@dataclass(frozen=True)
class ContextThresholds:
    """Every context-engineering number Northstar enforces, in one place.

    The defaults are the measured harness values.  A host lowers or raises them
    here; no rule in this module hard-codes a number of its own.
    """

    tool_result_offload_tokens: int = DEFAULT_TOOL_RESULT_OFFLOAD_TOKENS
    offload_preview_lines: int = DEFAULT_OFFLOAD_PREVIEW_LINES
    offload_preview_max_bytes: int = DEFAULT_OFFLOAD_PREVIEW_MAX_BYTES
    window_pressure_fraction: float = DEFAULT_WINDOW_PRESSURE_FRACTION
    summary_trigger_fraction: float = DEFAULT_SUMMARY_TRIGGER_FRACTION
    reread_path_only_tokens: int = DEFAULT_REREAD_PATH_ONLY_TOKENS
    reread_max_files: int = DEFAULT_REREAD_MAX_FILES
    skill_body_max_tokens: int = DEFAULT_SKILL_BODY_MAX_TOKENS
    skill_body_total_max_tokens: int = DEFAULT_SKILL_BODY_TOTAL_MAX_TOKENS
    auto_memory_max_lines: int = DEFAULT_AUTO_MEMORY_MAX_LINES
    auto_memory_max_bytes: int = DEFAULT_AUTO_MEMORY_MAX_BYTES
    subagent_read_budget_tokens: int = DEFAULT_SUBAGENT_READ_BUDGET_TOKENS
    subagent_result_budget_tokens: int = DEFAULT_SUBAGENT_RESULT_BUDGET_TOKENS
    subagent_summary_min_tokens: int = DEFAULT_SUBAGENT_SUMMARY_MIN_TOKENS
    subagent_summary_max_tokens: int = DEFAULT_SUBAGENT_SUMMARY_MAX_TOKENS
    context_window_tokens: int = DEFAULT_CONTEXT_WINDOW_TOKENS
    #: Todo-state recitation is off by default.  Deep Agents v0.7 (2026-07)
    #: made ``TodoListMiddleware`` opt-in after three task categories showed
    #: slightly better reward and lower cost with it disabled.  Northstar has
    #: no todo recitation yet; the switch exists so the first one is opt-in.
    todo_state_enabled: bool = False

    def __post_init__(self) -> None:
        _check_positive_int("tool_result_offload_tokens", self.tool_result_offload_tokens)
        _check_positive_int("offload_preview_lines", self.offload_preview_lines)
        _check_positive_int("offload_preview_max_bytes", self.offload_preview_max_bytes)
        _check_fraction("window_pressure_fraction", self.window_pressure_fraction)
        _check_fraction("summary_trigger_fraction", self.summary_trigger_fraction)
        _check_positive_int("reread_path_only_tokens", self.reread_path_only_tokens)
        _check_positive_int("reread_max_files", self.reread_max_files)
        _check_positive_int("skill_body_max_tokens", self.skill_body_max_tokens)
        _check_positive_int("skill_body_total_max_tokens", self.skill_body_total_max_tokens)
        _check_positive_int("auto_memory_max_lines", self.auto_memory_max_lines)
        _check_positive_int("auto_memory_max_bytes", self.auto_memory_max_bytes)
        _check_positive_int("subagent_read_budget_tokens", self.subagent_read_budget_tokens)
        _check_positive_int("subagent_result_budget_tokens", self.subagent_result_budget_tokens)
        _check_positive_int("subagent_summary_min_tokens", self.subagent_summary_min_tokens)
        _check_positive_int("subagent_summary_max_tokens", self.subagent_summary_max_tokens)
        _check_positive_int("context_window_tokens", self.context_window_tokens)
        if self.subagent_summary_min_tokens > self.subagent_summary_max_tokens:
            raise ValueError("subagent_summary_min_tokens must not exceed subagent_summary_max_tokens")
        if not isinstance(self.todo_state_enabled, bool):
            raise ValueError("todo_state_enabled must be a boolean")

    # -- derived numbers ------------------------------------------------

    def window_pressure_tokens(self) -> int:
        """Input size at which old write/edit calls become pointers."""
        return int(self.context_window_tokens * self.window_pressure_fraction)

    def summary_trigger_tokens(self) -> int:
        """Input size at which a summary is produced.

        The default is 85% of the window.  A host evaluating prompt variants
        lowers it to 10-20% (the LangChain eval practice) without touching
        the offload rules, which is the whole point of separating the two.
        """
        return int(self.context_window_tokens * self.summary_trigger_fraction)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_result_offload_tokens": self.tool_result_offload_tokens,
            "offload_preview_lines": self.offload_preview_lines,
            "offload_preview_max_bytes": self.offload_preview_max_bytes,
            "window_pressure_fraction": self.window_pressure_fraction,
            "summary_trigger_fraction": self.summary_trigger_fraction,
            "reread_path_only_tokens": self.reread_path_only_tokens,
            "reread_max_files": self.reread_max_files,
            "skill_body_max_tokens": self.skill_body_max_tokens,
            "skill_body_total_max_tokens": self.skill_body_total_max_tokens,
            "auto_memory_max_lines": self.auto_memory_max_lines,
            "auto_memory_max_bytes": self.auto_memory_max_bytes,
            "subagent_read_budget_tokens": self.subagent_read_budget_tokens,
            "subagent_result_budget_tokens": self.subagent_result_budget_tokens,
            "subagent_summary_min_tokens": self.subagent_summary_min_tokens,
            "subagent_summary_max_tokens": self.subagent_summary_max_tokens,
            "context_window_tokens": self.context_window_tokens,
            "todo_state_enabled": self.todo_state_enabled,
        }


# ---------------------------------------------------------------------------
# Offload before summarize
# ---------------------------------------------------------------------------


class OffloadError(RuntimeError):
    """The offload store could not take the bytes."""


@dataclass(frozen=True)
class OffloadPointer:
    """A recoverable reference to bytes that live on disk.

    The pointer is the *only* thing that stays in the context once a tool
    result was offloaded.  It names the file, so the original content can be
    read back; nothing is ever dropped silently.
    """

    path: str
    original_tokens: int
    preview_lines: int
    sha256: str
    bytes_written: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "original_tokens": self.original_tokens,
            "preview_lines": self.preview_lines,
            "sha256": self.sha256,
            "bytes_written": self.bytes_written,
        }

    def render(self, *, preview: str = "") -> str:
        """The context-facing text: a path, a preview, and the way back."""
        lines = [
            f"[offloaded tool result: {self.original_tokens} tokens written to {self.path}]",
            f"[recover the full content with: Read {self.path}]",
        ]
        if preview:
            lines.append(f"[first {self.preview_lines} line(s) of {self.path}]")
            lines.append(preview)
        return "\n".join(lines)


class OffloadStore:
    """Where offloaded tool results go.

    The store is deliberately a plain directory of files: the pointer's whole
    promise is "the bytes are still there, at this path".  A run that hands a
    pointer to a model has handed it a recovery route, not a truncation.
    """

    def __init__(self, root: str | os.PathLike[str], *, limits: ContextThresholds | None = None) -> None:
        self.root = Path(root).expanduser()
        self.limits = limits or ContextThresholds()
        self._counter = 0

    def path_for(self, *, name: str = "tool-result") -> Path:
        self._counter += 1
        safe = "".join(character if character.isalnum() or character in "-_." else "_" for character in name)
        safe = safe.strip("._") or "tool-result"
        return self.root / f"{safe}-{self._counter:06d}.txt"

    def offload(self, text: str, *, name: str = "tool-result") -> tuple[OffloadPointer, str]:
        """Write ``text`` to disk; return the pointer and the preview text."""
        import hashlib

        if not isinstance(text, str):
            raise OffloadError("only text can be offloaded")
        directory = self.root
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise OffloadError(f"offload directory could not be created: {error}") from error
        target = self.path_for(name=name)
        try:
            target.write_text(text, encoding="utf-8")
        except OSError as error:
            raise OffloadError(f"offload write failed: {error}") from error
        lines = text.splitlines()
        preview_lines = lines[: self.limits.offload_preview_lines]
        preview = "\n".join(preview_lines)
        # A preview is a *preview*: the first N lines, but never more than
        # the preview budget in bytes.  One 120,000-character line is one
        # line, so a line-count alone would put the whole result back into
        # the context and undo the offload.
        preview = _truncate_to_bytes(preview, self.limits.offload_preview_max_bytes)
        pointer = OffloadPointer(
            path=str(target),
            original_tokens=estimate_text_tokens(text),
            preview_lines=len(preview_lines),
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            bytes_written=len(text.encode("utf-8")),
        )
        return pointer, preview


def should_offload_tool_result(text: str, limits: ContextThresholds) -> bool:
    """True when a single tool result is too big to keep in context.

    The rule is per tool result, not per transcript: a transcript may hold
    many small results forever, but one 20k-token result is what overflows a
    window that the model is reading linearly.
    """
    return estimate_text_tokens(text) > limits.tool_result_offload_tokens


def offload_tool_result(
    text: str,
    store: OffloadStore,
    *,
    name: str = "tool-result",
    force: bool = False,
) -> tuple[str, OffloadPointer]:
    """Replace an oversized tool result with a recoverable pointer.

    Under the threshold nothing happens: the text is returned unchanged and
    the pointer is empty (``path == ""``).  ``force=True`` offloads regardless
    of size, for a host that wants every result on disk.
    """
    if not force and not should_offload_tool_result(text, store.limits):
        return text, OffloadPointer(
            path="",
            original_tokens=estimate_text_tokens(text),
            preview_lines=0,
            sha256="",
            bytes_written=0,
        )
    pointer, preview = store.offload(text, name=name)
    return pointer.render(preview=preview), pointer


# ---------------------------------------------------------------------------
# Window pressure: old write/edit calls become pointers
# ---------------------------------------------------------------------------

#: The tools whose *arguments* carry a file's content.  Their input is
#: reproducible from disk, so it is the one thing a window-pressure rule may
#: reduce to a pointer without losing information.
WRITE_LIKE_TOOLS = ("Write", "Edit", "MultiEdit", "WriteFile", "EditFile")


def is_write_like(tool_name: str) -> bool:
    return tool_name in WRITE_LIKE_TOOLS


def window_pressure_reached(input_tokens: int, limits: ContextThresholds) -> bool:
    """True when the input has reached the configured fraction of the window."""
    return input_tokens >= limits.window_pressure_tokens()


@dataclass(frozen=True)
class TruncatedCall:
    """One write/edit call reduced to a pointer."""

    tool_use_id: str
    tool_name: str
    path: str
    original_tokens: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_use_id": self.tool_use_id,
            "tool_name": self.tool_name,
            "path": self.path,
            "original_tokens": self.original_tokens,
        }

    def render(self) -> str:
        return (
            f"[{self.tool_name} call {self.tool_use_id} reduced to a pointer at window pressure: "
            f"{self.original_tokens} tokens of file content; the file itself is unchanged on disk. "
            f"Recover it with: Read {self.path}]"
        )


def truncate_write_like_calls(
    calls: Sequence[Any],
    *,
    input_tokens: int,
    limits: ContextThresholds,
) -> tuple[list[Any], list[TruncatedCall]]:
    """Reduce old write/edit calls to pointers when the window is under pressure.

    ``calls`` are :class:`providers.base.ToolUseBlock` objects.  The returned
    list has the same length; a truncated call carries an input whose
    ``content`` is the pointer text instead of the file body, and keeps its
    path in ``pointer_path`` so the original is recoverable.

    Only write-like calls are touched: an ordinary read call has no
    reproducible form, and dropping its arguments would drop the request.
    """
    if not window_pressure_reached(input_tokens, limits):
        return list(calls), []
    reduced: list[Any] = []
    changed: list[TruncatedCall] = []
    for call in calls:
        name = getattr(call, "name", "")
        payload = getattr(call, "input", None)
        if not is_write_like(name) or not isinstance(payload, dict):
            reduced.append(call)
            continue
        content = payload.get("content")
        if not isinstance(content, str) or not content:
            reduced.append(call)
            continue
        original_tokens = estimate_text_tokens(content)
        path = str(payload.get("path") or payload.get("file_path") or "(unknown path)")
        record = TruncatedCall(
            tool_use_id=str(getattr(call, "id", "")),
            tool_name=name,
            path=path,
            original_tokens=original_tokens,
        )
        new_payload = dict(payload)
        new_payload["content"] = record.render()
        # The path is kept so a reader (or a later re-read) can find the file
        # the pointer refers to.
        new_payload["pointer_path"] = path
        reduced.append(_replace_call_input(call, new_payload))
        changed.append(record)
    return reduced, changed


def _replace_call_input(call: Any, payload: dict[str, Any]) -> Any:
    """Return a copy of ``call`` with a new input mapping."""
    try:
        return dataclasses_replace(call, input=payload)
    except Exception:  # noqa: BLE001 - fall back to a shallow copy
        import copy as _copy

        clone = _copy.copy(call)
        try:
            object.__setattr__(clone, "input", payload)
        except Exception:  # noqa: BLE001 - frozen dataclass without that field
            return call
        return clone


def dataclasses_replace(obj: Any, **changes: Any) -> Any:
    import dataclasses

    return dataclasses.replace(obj, **changes)


# ---------------------------------------------------------------------------
# Re-reads after a compaction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RereadDecision:
    """What a re-read of one file may put in the context."""

    path: str
    tokens: int
    #: True when the content is withheld and only the path is returned.
    path_only: bool

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "tokens": self.tokens, "path_only": self.path_only}

    def render(self) -> str:
        if not self.path_only:
            return ""
        return (
            f"[{self.path} was re-read after compaction: {self.tokens} tokens withheld; "
            f"read it explicitly with: Read {self.path}]"
        )


def plan_rereads(
    files: Sequence[tuple[str, str]],
    *,
    limits: ContextThresholds,
) -> tuple[list[RereadDecision], list[str]]:
    """Decide what a post-compaction re-read may keep.

    ``files`` is ``(path, content)`` pairs, most recently modified first.  The
    rules, from the source report:

    * at most ``reread_max_files`` files are re-read at all;
    * a file above ``reread_path_only_tokens`` returns a **path reference**,
      not its content - the model is told the file exists and how to read it,
      and the bytes are not paid for twice;
    * a file at or below the threshold returns its content.

    Returns the decisions and the list of paths that were *not* re-read.
    """
    decisions: list[RereadDecision] = []
    skipped: list[str] = []
    for index, (path, content) in enumerate(files):
        if index >= limits.reread_max_files:
            skipped.append(path)
            continue
        tokens = estimate_text_tokens(content)
        decisions.append(
            RereadDecision(
                path=path,
                tokens=tokens,
                path_only=tokens > limits.reread_path_only_tokens,
            )
        )
    return decisions, skipped


def apply_reread_decisions(
    files: Sequence[tuple[str, str]],
    decisions: Sequence[RereadDecision],
) -> list[tuple[str, str]]:
    """Apply the decisions: a path-only file yields its pointer text."""
    by_path = {decision.path: decision for decision in decisions}
    applied: list[tuple[str, str]] = []
    for path, content in files:
        decision = by_path.get(path)
        if decision is None:
            continue
        applied.append((path, decision.render() if decision.path_only else content))
    return applied


# ---------------------------------------------------------------------------
# Skill bodies
# ---------------------------------------------------------------------------


def cap_skill_bodies(
    bodies: Sequence[tuple[str, str]],
    *,
    limits: ContextThresholds,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Cap re-injected skill bodies per skill and in total.

    A skill body above ``skill_body_max_tokens`` is truncated, and the total
    across all skills is capped at ``skill_body_total_max_tokens``.  The
    returned list is the truncated bodies; the second value lists the skills
    that were dropped for want of total budget.
    """
    kept: list[tuple[str, str]] = []
    dropped: list[str] = []
    spent = 0
    for name, body in bodies:
        tokens = estimate_text_tokens(body)
        if tokens > limits.skill_body_max_tokens:
            body = _truncate_to_tokens(body, limits.skill_body_max_tokens)
            tokens = estimate_text_tokens(body)
        if spent + tokens > limits.skill_body_total_max_tokens:
            dropped.append(name)
            continue
        spent += tokens
        kept.append((name, body))
    return kept, dropped


def _truncate_to_bytes(text: str, max_bytes: int) -> str:
    """Clip ``text`` to at most ``max_bytes`` UTF-8 bytes.

    No marker is appended: this clips a *preview*, and the pointer already
    says where the full content is.
    """
    raw = text.encode("utf-8")[:max_bytes]
    return raw.decode("utf-8", errors="ignore")


def _truncate_to_tokens(text: str, max_tokens: int) -> str:
    limit = max_tokens * BYTES_PER_TOKEN
    raw = text.encode("utf-8")[:limit]
    clipped = raw.decode("utf-8", errors="ignore")
    return clipped + f"\n[skill body truncated to {max_tokens} tokens]"


# ---------------------------------------------------------------------------
# Auto-memory
# ---------------------------------------------------------------------------


def cap_auto_memory(text: str, *, limits: ContextThresholds) -> tuple[str, dict[str, Any]]:
    """Cap auto-memory at the first N lines or M bytes, whichever comes first.

    The source rule ("the first 200 lines or 25KB") is an *either* cap: the
    memory is cut at whichever limit is reached first.  A memory that is
    longer than both is cut at the earlier one, so the cap is never looser
    than the report's.

    Returns the capped text and a record of what was cut.
    """
    raw_lines = text.splitlines()
    bytes_total = len(text.encode("utf-8"))
    lines_kept = min(len(raw_lines), limits.auto_memory_max_lines)
    body = "\n".join(raw_lines[:lines_kept])
    body_bytes = len(body.encode("utf-8"))
    bytes_kept = min(body_bytes, limits.auto_memory_max_bytes)
    if bytes_kept < body_bytes:
        body = body.encode("utf-8")[:bytes_kept].decode("utf-8", errors="ignore")
        body_bytes = bytes_kept
    truncated = lines_kept < len(raw_lines) or bytes_kept < bytes_total
    record = {
        "original_lines": len(raw_lines),
        "original_bytes": bytes_total,
        "kept_lines": len(body.splitlines()),
        "kept_bytes": body_bytes,
        "truncated": truncated,
        "limit_lines": limits.auto_memory_max_lines,
        "limit_bytes": limits.auto_memory_max_bytes,
    }
    return body, record


# ---------------------------------------------------------------------------
# Subagent budgets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubagentBudget:
    """What a subagent may read, and what it may hand back.

    Two shapes, both from the source report: a *research* subagent reads about
    6,100 tokens and returns about 420; a general subagent may explore far
    more but returns a distilled 1,000-2,000 token summary.
    """

    read_budget_tokens: int = DEFAULT_SUBAGENT_READ_BUDGET_TOKENS
    result_budget_tokens: int = DEFAULT_SUBAGENT_RESULT_BUDGET_TOKENS
    summary_min_tokens: int = DEFAULT_SUBAGENT_SUMMARY_MIN_TOKENS
    summary_max_tokens: int = DEFAULT_SUBAGENT_SUMMARY_MAX_TOKENS
    research: bool = False

    @staticmethod
    def research_variant(limits: ContextThresholds) -> "SubagentBudget":
        return SubagentBudget(
            read_budget_tokens=limits.subagent_read_budget_tokens,
            result_budget_tokens=limits.subagent_result_budget_tokens,
            summary_min_tokens=limits.subagent_summary_min_tokens,
            summary_max_tokens=limits.subagent_summary_max_tokens,
            research=True,
        )

    @staticmethod
    def general_variant(limits: ContextThresholds) -> "SubagentBudget":
        return SubagentBudget(
            read_budget_tokens=limits.subagent_read_budget_tokens,
            result_budget_tokens=limits.subagent_summary_max_tokens,
            summary_min_tokens=limits.subagent_summary_min_tokens,
            summary_max_tokens=limits.subagent_summary_max_tokens,
            research=False,
        )

    def budget_for_result(self) -> int:
        """The ceiling on what this subagent hands back to its parent."""
        if self.research:
            return self.result_budget_tokens
        return self.summary_max_tokens


def cap_subagent_result(text: str, budget: SubagentBudget) -> tuple[str, bool]:
    """Cap a subagent's return value; report whether it was cut.

    A cut result is *marked*.  Silently dropping the tail would tell the
    parent a false story about what the child found, which is worse than
    saying "this was truncated".
    """
    limit = budget.budget_for_result()
    if estimate_text_tokens(text) <= limit:
        return text, False
    clipped = _truncate_to_tokens(text, limit)
    return clipped, True


def read_budget_exceeded(tokens: int, budget: SubagentBudget) -> bool:
    """True when a subagent has read more than its read budget allows."""
    return tokens > budget.read_budget_tokens


# ---------------------------------------------------------------------------
# Memory tax
# ---------------------------------------------------------------------------


@dataclass
class MemoryTaxLedger:
    """What persistent memory costs this run, measured rather than guessed.

    The ETH Zurich study the report cites found that LLM-generated context
    files raised inference cost by 20% and 23% on two benchmarks (developer
    files up to 19%).  Those are *their* numbers on *their* benchmarks; they
    are not Northstar's.  This ledger measures Northstar's own: every time a
    memory, note, or other persistent context file is injected into a
    request, the injected token count is booked here, and the run can report
    the share of its input that was tax rather than work.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, *, source: str, tokens: int, kind: str = "memory") -> int:
        if not isinstance(source, str) or not source:
            raise ValueError("source must be a non-empty string")
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ValueError("tokens must be a non-negative int")
        self.entries.append({"source": source, "tokens": tokens, "kind": kind})
        return tokens

    @property
    def injected_tokens(self) -> int:
        """Total tokens injected by persistent context files."""
        return sum(entry["tokens"] for entry in self.entries)

    def tax_ratio(self, total_input_tokens: int) -> float:
        """The share of a run's input that was memory tax.

        ``0.0`` when the run had no input to compare against: an unknown
        denominator is not a zero tax.
        """
        if total_input_tokens <= 0:
            return 0.0
        return self.injected_tokens / float(total_input_tokens)

    def as_dict(self, *, total_input_tokens: int = 0) -> dict[str, Any]:
        return {
            "entries": list(self.entries),
            "injected_tokens": self.injected_tokens,
            "total_input_tokens": total_input_tokens,
            "tax_ratio": self.tax_ratio(total_input_tokens),
        }


# ---------------------------------------------------------------------------
# Todo state
# ---------------------------------------------------------------------------


def todo_state_enabled(limits: ContextThresholds) -> bool:
    """Whether todo-state recitation is on.

    Off by default.  Deep Agents v0.7 (2026-07) made ``TodoListMiddleware``
    opt-in after three task categories showed slightly better reward and
    lower cost with todos disabled; Northstar has to make its own
    measurement before turning one on, so the default is off and the switch
    is explicit.
    """
    return bool(limits.todo_state_enabled)


__all__ = [
    "BYTES_PER_TOKEN",
    "MemoryTaxLedger",
    "SubagentBudget",
    "cap_auto_memory",
    "cap_subagent_result",
    "read_budget_exceeded",
    "RereadDecision",
    "apply_reread_decisions",
    "cap_skill_bodies",
    "plan_rereads",
    "ContextThresholds",
    "OffloadError",
    "OffloadPointer",
    "OffloadStore",
    "offload_tool_result",
    "should_offload_tool_result",
    "DEFAULT_AUTO_MEMORY_BYTES",
    "DEFAULT_AUTO_MEMORY_MAX_BYTES",
    "DEFAULT_AUTO_MEMORY_MAX_LINES",
    "DEFAULT_CONTEXT_WINDOW_TOKENS",
    "DEFAULT_OFFLOAD_PREVIEW_LINES",
    "DEFAULT_REREAD_MAX_FILES",
    "DEFAULT_REREAD_PATH_ONLY_TOKENS",
    "DEFAULT_SKILL_BODY_MAX_TOKENS",
    "DEFAULT_SKILL_BODY_TOTAL_MAX_TOKENS",
    "DEFAULT_SUBAGENT_READ_BUDGET_TOKENS",
    "DEFAULT_SUBAGENT_RESULT_BUDGET_TOKENS",
    "DEFAULT_SUBAGENT_SUMMARY_MAX_TOKENS",
    "DEFAULT_SUBAGENT_SUMMARY_MIN_TOKENS",
    "DEFAULT_SUMMARY_TRIGGER_FRACTION",
    "DEFAULT_TOOL_RESULT_OFFLOAD_TOKENS",
    "DEFAULT_WINDOW_PRESSURE_FRACTION",
    "estimate_text_tokens",
]
