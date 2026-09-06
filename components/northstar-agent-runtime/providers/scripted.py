"""Deterministic offline provider for tests and local development.

A ``ScriptedProvider`` replays a fixed list of steps, one per model call, so
every test run is reproducible with no API key and no network.

Step shapes (JSON-friendly, so a ``--script`` file works with the CLI):

    # final assistant text
    {"text": "Done."}
    "Done."

    # assistant text plus tool calls
    {"text": "Reading now.", "tools": [{"name": "Read", "input": {"path": "a.txt"}}]}

    # per-step usage override (all fields optional)
    {"text": "hi", "usage": {"input_tokens": 100, "output_tokens": 20,
                             "cache_read_input_tokens": 5, "cache_creation_input_tokens": 3}}

    # simulate a provider failure
    {"error": "boom"}
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .base import (
    Provider,
    ProviderError,
    ProviderRequest,
    ProviderResponse,
    TextBlock,
    ToolUseBlock,
    Usage,
)

DEFAULT_USAGE = Usage(input_tokens=10, output_tokens=5)


def normalize_step(step: Any) -> dict[str, Any]:
    if isinstance(step, str):
        return {"text": step}
    if isinstance(step, Mapping):
        value = dict(step)
        if value.get("error") is None and not value.get("text") and not value.get("tools"):
            raise ProviderError("scripted step must contain text, tools, or error")
        tools = value.get("tools")
        if tools is not None and not isinstance(tools, (list, tuple)):
            raise ProviderError("scripted step 'tools' must be a list")
        for tool in tools or []:
            if not isinstance(tool, Mapping) or not tool.get("name"):
                raise ProviderError("each scripted tool step needs a 'name'")
        return value
    raise ProviderError(f"unsupported scripted step: {type(step).__name__}")


class ScriptedProvider(Provider):
    """Replays a script deterministically. Records every request it receives."""

    def __init__(self, script: Sequence[Any]):
        self._script: list[dict[str, Any]] = [normalize_step(s) for s in script]
        self.calls: list[ProviderRequest] = []
        self._tool_seq = 0

    def create_message(self, request: ProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        if not self._script:
            raise ProviderError("scripted provider: script exhausted")
        step = self._script.pop(0)
        if step.get("error") is not None:
            raise ProviderError(str(step["error"]))

        content: list = []
        if step.get("text"):
            content.append(TextBlock(step["text"]))
        for tool in step.get("tools", []) or []:
            self._tool_seq += 1
            content.append(
                ToolUseBlock(
                    id=f"toolu_script_{self._tool_seq}",
                    name=str(tool["name"]),
                    input=dict(tool.get("input", {})),
                )
            )
        usage_spec = step.get("usage") or {}
        usage = Usage(
            input_tokens=int(usage_spec.get("input_tokens", DEFAULT_USAGE.input_tokens)),
            output_tokens=int(usage_spec.get("output_tokens", DEFAULT_USAGE.output_tokens)),
            cache_read_input_tokens=int(usage_spec.get("cache_read_input_tokens", 0)),
            cache_creation_input_tokens=int(usage_spec.get("cache_creation_input_tokens", 0)),
        )
        stop_reason = step.get("stop_reason") or ("tool_use" if step.get("tools") else "end_turn")
        return ProviderResponse(content=content, usage=usage, stop_reason=stop_reason)
