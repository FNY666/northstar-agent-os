"""Shared helpers for the runtime test suite (offline, deterministic)."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Sequence

from loop import AgentRuntime, RunConfig, ResultMessage
from providers.scripted import ScriptedProvider


def make_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="nsrt-"))


def make_runtime(script: Sequence[Any], **config_kwargs: Any):
    """Return (runtime, provider) with a fresh temporary workspace."""
    workspace = config_kwargs.pop("workspace", None) or make_workspace()
    provider = ScriptedProvider(script)
    config = RunConfig(workspace=workspace, **config_kwargs)
    return AgentRuntime(provider, config), provider


def tool_results_of(provider_call) -> list[dict[str, Any]]:
    """All tool_result blocks recorded in one provider request."""
    results = []
    for message in provider_call.messages:
        if message.get("role") != "user" or not isinstance(message.get("content"), list):
            continue
        for block in message["content"]:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                results.append(block)
    return results


def results_of(report) -> list[ResultMessage]:
    return [e for e in report.events if isinstance(e, ResultMessage)]
