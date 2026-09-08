"""Shared, offline fixtures for the Northstar agent-runtime tests.

Nothing here touches the network. The scripted provider is the only model, so the
whole suite runs without an API key and produces the same result on every host.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SIDECAR_DIR = ROOT.parent / "northstar-codex-sidecar"
CONTRACT_DIR = ROOT.parent / "northstar-run-contract"


def load_sidecar(name: str):
    """Import a module from the sibling sidecar component.

    The path is appended, never prepended: if a name ever collided the runtime's
    own module wins, so the component under test cannot be shadowed by its peer.
    """
    import importlib

    text = str(SIDECAR_DIR)
    if text not in sys.path:
        sys.path.append(text)
    return importlib.import_module(name)

def load_contract(name: str):
    """Import a module from the sibling run-contract component (same rule as above)."""
    import importlib

    text = str(CONTRACT_DIR)
    if text not in sys.path:
        sys.path.append(text)
    return importlib.import_module(name)


from agents import AgentRegistry, builtin_registry  # noqa: E402
from hooks import HookRegistry  # noqa: E402
from loop import AgentRuntime, RunReport, RuntimeConfig  # noqa: E402
from permissions import PermissionConfig, PermissionEngine  # noqa: E402
from providers.base import AssistantMessage, ResultMessage, SystemMessage, Usage, UserMessage  # noqa: E402
from providers.scripted import ScriptedProvider  # noqa: E402
from sessions import SessionStore  # noqa: E402
from tools import (  # noqa: E402
    ToolContext,
    ToolLimits,
    ToolRegistry,
    ToolResult,
    ToolSandbox,
    build_default_registry,
)
from tracing import Tracer  # noqa: E402


def write_files(root: Path, files: dict[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


class RuntimeTestCase(unittest.TestCase):
    """Base class with temp workspaces, a scripted provider, and span capture."""

    def setUp(self) -> None:
        self._temp_dirs: list[str] = []
        self.tracer = Tracer(collect=True)

    def tearDown(self) -> None:
        for directory in self._temp_dirs:
            shutil.rmtree(directory, ignore_errors=True)
        self._temp_dirs.clear()

    # -- fixtures ---------------------------------------------------------
    def temp_dir(self) -> Path:
        created = tempfile.mkdtemp(prefix="nsar-test-")
        self._temp_dirs.append(created)
        return Path(created)

    def workspace(self, files: dict[str, str] | None = None) -> Path:
        root = self.temp_dir()
        if files:
            write_files(root, files)
        return root

    def sandbox(self, files: dict[str, str] | None = None, *, limits: ToolLimits | None = None) -> tuple[Path, ToolSandbox, ToolContext]:
        root = self.workspace(files)
        sandbox = ToolSandbox(root, limits=limits or ToolLimits())
        registry = build_default_registry()
        context = ToolContext(session_id="test", sandbox=sandbox, limits=limits or ToolLimits(), services={"registry": registry})
        return root, sandbox, context

    def session_store(self, session_id: str | None = None) -> SessionStore:
        return SessionStore(self.workspace(), session_id=session_id)

    def provider(self, turns: Iterable[Any] = (), **kwargs: Any) -> ScriptedProvider:
        # Pinned to a priced model so cost assertions are exact; the scripted
        # provider's own default would fall back to conservative pricing.
        kwargs.setdefault("model", "claude-sonnet-4-5")
        return ScriptedProvider(list(turns), **kwargs)

    def runtime(
        self,
        turns: Sequence[Any] = (),
        *,
        workspace: Path | str | None = None,
        config: RuntimeConfig | None = None,
        hooks: HookRegistry | None = None,
        agents: AgentRegistry | None = None,
        tools: ToolRegistry | None = None,
        sessions: SessionStore | None = None,
        providers: dict[str, Any] | None = None,
        can_use_tool: Any = None,
        provider: Any = None,
        tracer: Tracer | None = None,
        budget: Any = None,
        **config_kwargs: Any,
    ) -> AgentRuntime:
        if provider is None:
            provider = self.provider(turns)
        if workspace is None:
            workspace = self.workspace()
        if config is None:
            config = RuntimeConfig(workspace=str(workspace), **config_kwargs)
        return AgentRuntime(
            provider=provider,
            config=config,
            tools=tools,
            hooks=hooks or HookRegistry(),
            agents=agents or builtin_registry(),
            providers=providers,
            sessions=sessions,
            can_use_tool=can_use_tool,
            tracer=tracer if tracer is not None else self.tracer,
            budget=budget,
        )

    def drive(self, runtime: AgentRuntime, prompt: str = "go") -> RunReport:
        return runtime.run_collect(prompt)

    # -- assertions -------------------------------------------------------
    def assertExactlyOneResult(self, report: RunReport) -> ResultMessage:
        results = [event for event in report.events if isinstance(event, ResultMessage)]
        self.assertEqual(len(results), 1, f"expected exactly one ResultMessage, saw {len(results)}")
        self.assertIsNotNone(report.result)
        assert report.result is not None
        self.assertIs(results[0], report.result)
        return report.result

    def assertEventKinds(self, report: RunReport, expected: Sequence[str]) -> None:
        kinds = [type(event).__name__ for event in report.events]
        self.assertEqual(kinds, list(expected))

    def subtypes(self, report: RunReport) -> list[str]:
        return [event.subtype for event in report.events if isinstance(event, SystemMessage) and event.subtype == "init"]


def tool_call(name: str, payload: dict[str, Any] | None = None, *, call_id: str = "") -> dict[str, Any]:
    block: dict[str, Any] = {"type": "tool_use", "name": name, "input": dict(payload or {})}
    if call_id:
        block["id"] = call_id
    return block


def text_turn(text: str, **kwargs: Any) -> dict[str, Any]:
    turn: dict[str, Any] = {"text": text}
    turn.update(kwargs)
    return turn


def tool_turn(
    name: str,
    payload: dict[str, Any] | None = None,
    *,
    id: str | None = None,
    usage: dict[str, Any] | None = None,
    also_text: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    """One scripted turn that asks for a tool call.

    ``id`` belongs *inside* the tool dict; a top-level key there would be silently
    ignored, which reads like the provider dropping call ids.
    """
    tool: dict[str, Any] = {"name": name, "input": dict(payload or {})}
    if id:
        tool["id"] = id
    turn: dict[str, Any] = {"tool": tool, **kwargs}
    if usage is not None:
        turn["usage"] = usage
    if also_text:
        turn["also_text"] = also_text
    return turn


__all__ = [
    "AgentRegistry",
    "AssistantMessage",
    "HookRegistry",
    "PermissionConfig",
    "PermissionEngine",
    "ResultMessage",
    "RunReport",
    "RuntimeConfig",
    "RuntimeTestCase",
    "SIDECAR_DIR",
    "CONTRACT_DIR",
    "load_contract",
    "load_sidecar",
    "ScriptedProvider",
    "SessionStore",
    "SystemMessage",
    "ToolContext",
    "ToolLimits",
    "ToolRegistry",
    "ToolResult",
    "ToolSandbox",
    "Tracer",
    "Usage",
    "UserMessage",
    "build_default_registry",
    "builtin_registry",
    "text_turn",
    "tool_call",
    "tool_turn",
    "write_files",
]
