"""The stateful half of the context-engineering rules.

:mod:`context_budget` holds the numbers and the pure rules.  This module holds
the *state* a run needs while the rules act: where offloaded bytes go, whether
a compaction has happened, what the memory tax is so far.

The ordering it enforces is the report's own logic made mechanical:

1. **offload** a tool result that is too big to read linearly;
2. **truncate** old write/edit calls to pointers once the window is under
   pressure;
3. **summarize** only what offloading and truncation could not free.

A summary is the last resort, not the first.  Summarising a result that could
have been offloaded throws away recoverable bytes for nothing: the bytes were
still on disk and the model could have read the part it needed.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from context_budget import (
    ContextThresholds,
    MemoryTaxLedger,
    OffloadPointer,
    OffloadStore,
    RereadDecision,
    TruncatedCall,
    cap_auto_memory,
    cap_skill_bodies,
    cap_subagent_result,
    estimate_text_tokens,
    is_write_like,
    offload_tool_result,
    plan_rereads,
    should_offload_tool_result,
    truncate_write_like_calls,
)


def _block_text(content: Any) -> str:
    """The text a provider tool-result block carries."""
    if isinstance(content, str):
        return content
    if isinstance(content, (list, tuple)):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text") or ""))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return ""

#: How many workspace entries the recent-file scan will look at before it
#: gives up.  A context rule must never become the reason a run walks a
#: million-file tree.
MAX_SCAN_ENTRIES = 2_000


@dataclass(frozen=True)
class InjectedContext:
    """One block of model-visible context the runtime put back after a cut."""

    kind: str
    path: str
    tokens: int
    path_only: bool = False
    text: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "tokens": self.tokens,
            "path_only": self.path_only,
        }


class ContextController:
    """The runtime's context policy, with the state the rules need.

    Every rule is off unless the host configures ``ContextThresholds``: these
    rules change what the model sees, and Northstar does not change observable
    behaviour without a host asking for it.  The *numbers* default to the
    measured harness values (see :mod:`context_budget`).
    """

    def __init__(
        self,
        thresholds: ContextThresholds,
        *,
        offload_dir: str | os.PathLike[str] | None = None,
        workspace: str | os.PathLike[str] | None = None,
    ) -> None:
        if not isinstance(thresholds, ContextThresholds):
            raise ValueError("thresholds must be a ContextThresholds")
        self.thresholds = thresholds
        self.workspace = Path(workspace).expanduser() if workspace else None
        directory = offload_dir
        if directory is None and self.workspace is not None:
            directory = self.workspace / ".northstar" / "offload"
        self.offload_dir = Path(directory).expanduser() if directory else None
        self.store = OffloadStore(self.offload_dir, limits=thresholds) if self.offload_dir else None
        #: True once a compaction has happened in this run.  Post-compaction
        #: re-read rules key off this.
        self.compacted = False
        self.compactions = 0
        #: Every offload this run performed, so a report can name the files.
        self.offloads: list[OffloadPointer] = []
        #: Every write/edit call this run reduced to a pointer.
        self.truncations: list[TruncatedCall] = []
        #: The context the runtime put back after a compaction.
        self.injected: list[InjectedContext] = []
        #: The files already re-read in this run.  The re-read budget is a
        #: *run* budget, not a per-compaction one: a run that compacts twice
        #: must not pay for the same file twice, and a file that has not
        #: changed since the last re-read has nothing new to say.
        self.reread_files: set[str] = set()
        #: The cost of persistent context files, measured.
        self.memory_tax = MemoryTaxLedger()

    # -- the post-compaction re-read -------------------------------------

    def reinject_after_compaction(
        self,
        *,
        workspace: str | os.PathLike[str] | None = None,
        skill_bodies: Sequence[tuple[str, str]] = (),
        memory_text: str = "",
    ) -> list[InjectedContext]:
        """Put the workspace back into the context after a compaction.

        This is the seam the source report describes: after a compaction the
        harness re-reads the most recently modified files and reloads the
        rules that match them.  Northstar's version keeps the *budgets*:

        * at most ``reread_max_files`` files are re-read, and the budget is
          a **run** budget: a file already re-read in this run is not
          re-read again, because it has not changed and the model already
          has the pointer;
        * a file over ``reread_path_only_tokens`` comes back as a **path**,
          not its content -- the model is told the file exists and how to
          read it, and the bytes are not paid for twice;
        * a re-injected skill body is capped at ``skill_body_max_tokens``
          each and ``skill_body_total_max_tokens`` in total.

        Every injected block is booked in the memory tax: this is the cost of
        persistent context, and a run must be able to name it.
        """
        records: list[InjectedContext] = []
        candidates = self.plan_recent_files(workspace)
        budget = self.thresholds.reread_max_files
        for path in candidates:
            if len(self.reread_files) >= budget:
                break
            if path in self.reread_files:
                continue
            try:
                content = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self.reread_files.add(path)
            records.append(self.inject(path, content, kind="reread"))
        kept, dropped = self.cap_skills(skill_bodies)
        for name, body in kept:
            records.append(self.inject(name, body, kind="skill", path_only=False))
        for name in dropped:
            self.memory_tax.record(source=name, tokens=0, kind="skill_dropped")
        if memory_text:
            # Auto-memory is persistent context like any other: the cap is
            # the first 200 lines or 25KB, whichever comes first.
            capped, record = self.cap_memory(memory_text)
            records.append(self.inject("auto-memory", capped, kind="memory", path_only=False))
        return records

    # -- the provider-facing rules ---------------------------------------

    def apply_provider_rules(
        self, messages: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Apply the offload and window-pressure rules to a provider payload.

        This is the seam where the model-visible context is formed, and it is
        deliberately *after* the durable record: the transcript keeps the full
        tool result and the full call arguments, and only what the provider
        reads is reduced.  A pointer is therefore always recoverable - from
        the disk (offload) or from the session record (truncation).

        The order is the point: **offload first, then window pressure**.
        Offloading a 20k-token result frees the space that a pointer would
        only have pretended to free.
        """
        import copy as _copy

        payload = [_copy.deepcopy(dict(message)) for message in messages]
        payload = self._offload_tool_results(payload)
        payload = self._truncate_write_calls(payload)
        return payload

    def _offload_tool_results(
        self, messages: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Replace oversized tool-result content with a recoverable pointer."""
        if self.store is None:
            return [dict(message) for message in messages]
        out: list[dict[str, Any]] = []
        for message in messages:
            content = message.get("content")
            if not isinstance(content, list):
                out.append(dict(message))
                continue
            blocks: list[Any] = []
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    blocks.append(block)
                    continue
                text = _block_text(block.get("content"))
                if not text or not should_offload_tool_result(text, self.thresholds):
                    blocks.append(block)
                    continue
                # Screen the bytes before they reach the disk: an offload
                # moves a body out of the model's context, not out of the
                # process's rules.
                safe = self._screen(text)
                pointer_text, pointer = offload_tool_result(
                    safe, self.store, name=f"tool-result-{block.get('tool_use_id', 'unknown')}"
                )
                self.offloads.append(pointer)
                new_block = dict(block)
                new_block["content"] = pointer_text
                blocks.append(new_block)
            new_message = dict(message)
            new_message["content"] = blocks
            out.append(new_message)
        return out

    def _truncate_write_calls(
        self, messages: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Reduce old write/edit call arguments to recoverable pointers."""
        import copy as _copy

        total = 0
        for message in messages:
            total += estimate_text_tokens(json.dumps(message, ensure_ascii=False, default=str))
        if total < self.thresholds.window_pressure_tokens():
            return [dict(message) for message in messages]
        out: list[dict[str, Any]] = []
        for message in messages:
            content = message.get("content")
            if not isinstance(content, list):
                out.append(dict(message))
                continue
            blocks: list[Any] = []
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    blocks.append(block)
                    continue
                name = str(block.get("name") or "")
                payload = block.get("input")
                if not is_write_like(name) or not isinstance(payload, dict):
                    blocks.append(block)
                    continue
                body = payload.get("content")
                if not isinstance(body, str) or not body:
                    blocks.append(block)
                    continue
                path = str(payload.get("path") or payload.get("file_path") or "(unknown path)")
                record = TruncatedCall(
                    tool_use_id=str(block.get("id") or ""),
                    tool_name=name,
                    path=path,
                    original_tokens=estimate_text_tokens(body),
                )
                new_payload = dict(payload)
                new_payload["content"] = record.render()
                new_payload["pointer_path"] = path
                new_block = dict(block)
                new_block["input"] = new_payload
                blocks.append(new_block)
                self.truncations.append(record)
            new_message = dict(message)
            new_message["content"] = blocks
            out.append(new_message)
        return out

    # -- offload --------------------------------------------------------

    def offload_transcript(self, transcript: Sequence[Any]) -> list[Any]:
        """Offload oversized tool results *in a copy of* the transcript.

        This is the "offload before summarize" seam.  The durable transcript
        keeps the full bytes; the copy handed to the compactor carries
        pointers, so a summary is only written over content that could not be
        offloaded.  Summarising first would throw away recoverable bytes --
        bytes that were on disk and that the model could have read the part
        of it needed.
        """
        if self.store is None:
            return list(transcript)
        from providers.base import ToolResultBlock, UserMessage

        out: list[Any] = []
        for message in transcript:
            results = getattr(message, "tool_results", None)
            if not results:
                out.append(message)
                continue
            blocks: list[Any] = []
            changed = False
            for result in results:
                text = result.text() if hasattr(result, "text") else ""
                if not text or not should_offload_tool_result(text, self.thresholds):
                    blocks.append(result)
                    continue
                pointer_text, pointer = offload_tool_result(
                    text, self.store, name=f"tool-result-{result.tool_use_id}"
                )
                self.offloads.append(pointer)
                blocks.append(
                    ToolResultBlock(
                        tool_use_id=result.tool_use_id,
                        content=pointer_text,
                        is_error=result.is_error,
                        provenance=result.provenance,
                        tool_denial_kind=result.tool_denial_kind,
                        synthetic=result.synthetic,
                    )
                )
                changed = True
            if not changed:
                out.append(message)
                continue
            out.append(UserMessage(content=tuple(blocks)))
        return out

    def offload_result(self, text: str, *, name: str = "tool-result") -> str:
        """Offload an oversized tool result; return the pointer text.

        Under the threshold the text is returned unchanged and nothing is
        written to disk.

        The bytes are screened *before* they are written.  Offloading moves a
        body out of the model's context, but it moves it into a file on disk,
        and a file on disk is still something a later read can bring back.
        Screening at the offload boundary keeps the invariant that the raw
        bytes never leave the process unscreened -- including when the
        context rules run before the provider-payload screening checkpoint.
        """
        if self.store is None:
            return text
        if not should_offload_tool_result(text, self.thresholds):
            return text
        safe = self._screen(text)
        pointer_text, pointer = offload_tool_result(safe, self.store, name=name)
        self.offloads.append(pointer)
        return pointer_text

    @staticmethod
    def _screen(text: str) -> str:
        """Screen a body that is about to leave the model's context.

        Import is local so that a host that never enables the context rules
        does not pay for the defensive stack, and so that the module has no
        import-time dependency on it.
        """
        from defensive_agent import sanitize_for_model

        return sanitize_for_model(text)[0]

    # -- window pressure -------------------------------------------------

    def apply_window_pressure(self, transcript: Sequence[Any]) -> tuple[list[Any], list[TruncatedCall]]:
        """Reduce old write/edit calls to pointers when the window is tight.

        The transcript is copied, never mutated in place: the session record
        keeps the full call, and only the *context* the model reads is
        reduced.  The pointer names the file, so the original is recoverable.
        """
        from providers.base import estimate_transcript_tokens

        input_tokens = estimate_transcript_tokens(transcript)
        if input_tokens < self.thresholds.window_pressure_tokens():
            return list(transcript), []
        reduced: list[Any] = []
        changed: list[TruncatedCall] = []
        for message in transcript:
            calls = getattr(message, "tool_uses", None)
            if not calls:
                reduced.append(message)
                continue
            new_calls, cut = truncate_write_like_calls(
                calls, input_tokens=input_tokens, limits=self.thresholds
            )
            if not cut:
                reduced.append(message)
                continue
            changed.extend(cut)
            reduced.append(_replace_tool_uses(message, new_calls))
        self.truncations.extend(changed)
        return reduced, changed

    # -- post-compaction re-reads ---------------------------------------

    def note_compaction(self) -> None:
        """Record that a compaction happened, so the re-read rules apply."""
        self.compacted = True
        self.compactions += 1

    def plan_recent_files(self, workspace: str | os.PathLike[str] | None = None) -> list[str]:
        """The most recently modified workspace files, at most ``reread_max_files``.

        The scan is bounded: a context rule must not become the reason a run
        walks an unbounded tree.
        """
        root = Path(workspace).expanduser() if workspace else self.workspace
        if root is None or not root.is_dir():
            return []
        entries: list[tuple[float, str]] = []
        scanned = 0
        for dirpath, dirnames, filenames in os.walk(root):
            # ``.northstar`` holds Northstar's own scratch -- the offload
            # files in particular.  Re-reading an offload file would put
            # the very bytes the offload removed back into the context, and
            # would spend the re-read budget on the runtime's own state
            # instead of on the workspace.
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {".git", "__pycache__", ".northstar"}
            ]
            for filename in filenames:
                scanned += 1
                if scanned > MAX_SCAN_ENTRIES:
                    break
                candidate = Path(dirpath) / filename
                try:
                    stat = candidate.stat()
                except OSError:
                    continue
                entries.append((stat.st_mtime, str(candidate)))
            if scanned > MAX_SCAN_ENTRIES:
                break
        entries.sort(reverse=True)
        return [path for _mtime, path in entries[: self.thresholds.reread_max_files]]

    def reread_decision(self, path: str, content: str) -> RereadDecision:
        """Whether a re-read of one file keeps its content or returns a path."""
        decisions, _skipped = plan_rereads([(path, content)], limits=self.thresholds)
        return decisions[0]

    def reread_text(self, path: str, content: str) -> tuple[str, bool]:
        """The context text a re-read may contribute, and whether it is path-only."""
        decision = self.reread_decision(path, content)
        return (decision.render() if decision.path_only else content), decision.path_only

    def inject(
        self,
        path: str,
        content: str,
        *,
        kind: str = "reread",
        path_only: bool | None = None,
    ) -> InjectedContext:
        """Book one injected context block, and the memory tax it carries.

        ``path_only`` overrides the re-read rule: a memory body or a skill
        body is already capped by its own budget, so the re-read's
        "path instead of content" rule does not apply to it.
        """
        if path_only is None:
            text, path_only = self.reread_text(path, content)
        else:
            text = content
        tokens = estimate_text_tokens(text)
        record = InjectedContext(
            kind=kind, path=path, tokens=tokens, path_only=path_only, text=text
        )
        self.injected.append(record)
        # A persistent context file is a tax on every request that carries it.
        # Book it here so a run can report the share of its input that was
        # memory rather than work.
        self.memory_tax.record(source=path, tokens=tokens, kind=kind)
        return record

    # -- memory / skills -------------------------------------------------

    def cap_memory(self, text: str) -> tuple[str, dict[str, Any]]:
        """Cap auto-memory at the first N lines or M bytes."""
        return cap_auto_memory(text, limits=self.thresholds)

    def cap_skills(self, bodies: Sequence[tuple[str, str]]) -> tuple[list[tuple[str, str]], list[str]]:
        """Cap re-injected skill bodies per skill and in total."""
        return cap_skill_bodies(bodies, limits=self.thresholds)

    def cap_subagent(self, text: str, *, research: bool = False) -> tuple[str, bool]:
        """Cap what a subagent hands back to its parent."""
        from context_budget import SubagentBudget

        budget = (
            SubagentBudget.research_variant(self.thresholds)
            if research
            else SubagentBudget.general_variant(self.thresholds)
        )
        return cap_subagent_result(text, budget)

    # -- reporting -------------------------------------------------------

    def as_dict(self, *, total_input_tokens: int = 0) -> dict[str, Any]:
        """Everything this run's context policy did, for the run report."""
        return {
            "thresholds": self.thresholds.as_dict(),
            "offloads": [pointer.as_dict() for pointer in self.offloads],
            "truncations": [record.as_dict() for record in self.truncations],
            "injected": [record.as_dict() for record in self.injected],
            "compactions": self.compactions,
            "memory_tax": self.memory_tax.as_dict(total_input_tokens=total_input_tokens),
        }


def _replace_tool_uses(message: Any, calls: Sequence[Any]) -> Any:
    """Return a copy of an assistant message with new tool_use blocks."""
    import dataclasses

    content = getattr(message, "content", ())
    if not isinstance(content, tuple):
        return message
    new_content = tuple(
        call if getattr(block, "kind", "") == "tool_use" else block
        for block, call in zip(content, calls)
    )
    if new_content == content:
        return message
    try:
        return dataclasses.replace(message, content=new_content)
    except Exception:  # noqa: BLE001 - keep the original if it cannot be replaced
        return message


__all__ = [
    "MAX_SCAN_ENTRIES",
    "ContextController",
    "InjectedContext",
]
