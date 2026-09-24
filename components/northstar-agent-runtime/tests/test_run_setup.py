"""``run_setup.resolve_ceilings()``, one row per combination of sources.

A run's ceilings come from four places - the operator's flags, the agent definition it
runs as, the workspace policy file and installed plugins - and every source other than the
flags may only tighten. The table below is the whole contract: each row names its inputs
and the ``Ceilings`` it must produce, so a change to one source's precedence shows up as a
named row failing rather than as a behaviour nobody wrote down.

The flags are parsed by the real ``run`` parser so the defaults under test are the ones an
operator actually gets, and the policy file and plugin set are the real dataclasses, so a
renamed field fails here instead of in production.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from unittest import mock
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import support  # noqa: F401
from support import RuntimeTestCase

from agents import AgentDefinition, general_agent, planner_agent
from cli import build_parser
from plugin_load import PluginContributions
from policy_file import PolicyFile
from run_setup import Ceilings, agent_permission_mode, resolve_ceilings

# The ``run`` parser's own defaults, restated so a row that relies on one says so.
FLAG_TURNS = 25
FLAG_TOOL_CALLS = 50
FLAG_COMPACTION = 60_000

# A repository agent with ceilings of its own, distinct from every built-in's.
REVIEWER = AgentDefinition(name="reviewer", tools=("Read",), max_turns=4, max_tool_calls=9)


def run_args(*flags: str) -> Any:
    return build_parser().parse_args(["run", "--prompt", "x", *flags])


def policy(**fields: Any) -> PolicyFile:
    return PolicyFile(source=Path(".northstar/config.toml"), **fields)


def plugins(**ceilings: Any) -> PluginContributions:
    return PluginContributions(policy=dict(ceilings))


@dataclass(frozen=True)
class Row:
    name: str
    expected: Ceilings
    flags: tuple[str, ...] = ()
    definition: AgentDefinition | None = None
    policy: PolicyFile | None = None
    plugins: PluginContributions | None = None


def ceilings(
    turns: int = FLAG_TURNS,
    tool_calls: int | None = FLAG_TOOL_CALLS,
    budget: float | None = None,
    compaction: int | None = FLAG_COMPACTION,
    halt: bool = False,
) -> Ceilings:
    return Ceilings(
        max_turns=turns,
        max_tool_calls=tool_calls,
        max_budget_usd=budget,
        compaction_threshold=compaction,
        halt_on_denial=halt,
    )


ROWS: tuple[Row, ...] = (
    # -- flags alone ---------------------------------------------------------------------
    Row("flag defaults", ceilings()),
    Row(
        "every flag set",
        ceilings(turns=7, tool_calls=11, budget=2.5, compaction=4_000, halt=True),
        flags=("--max-turns", "7", "--max-tool-calls", "11", "--max-budget-usd", "2.5",
               "--compaction-threshold-tokens", "4000", "--halt-on-denial"),
    ),
    Row("flags may exceed the policy defaults when nothing else speaks", ceilings(turns=40, tool_calls=90),
        flags=("--max-turns", "40", "--max-tool-calls", "90")),
    Row("compaction 0 (off) passes through as 0", ceilings(compaction=0), flags=("--compaction-threshold-tokens", "0")),
    # -- policy file ---------------------------------------------------------------------
    Row("empty policy file changes nothing", ceilings(), policy=policy()),
    Row(
        "policy lower than the flags wins",
        ceilings(turns=3, tool_calls=5, budget=1.0, compaction=8_000),
        policy=policy(max_turns=3, max_tool_calls=5, max_budget_usd=1.0, compaction_threshold_tokens=8_000),
    ),
    Row(
        "policy higher than the flags loses",
        ceilings(turns=2, tool_calls=3, budget=0.5, compaction=1_000),
        flags=("--max-turns", "2", "--max-tool-calls", "3", "--max-budget-usd", "0.5",
               "--compaction-threshold-tokens", "1000"),
        policy=policy(max_turns=20, max_tool_calls=40, max_budget_usd=9.0, compaction_threshold_tokens=50_000),
    ),
    Row("policy budget binds a run with no budget flag", ceilings(budget=0.25), policy=policy(max_budget_usd=0.25)),
    Row("policy compaction 0 turns compaction off", ceilings(compaction=0), policy=policy(compaction_threshold_tokens=0)),
    Row("policy halt_on_denial switches it on", ceilings(halt=True), policy=policy(halt_on_denial=True)),
    Row("policy halt_on_denial=False cannot switch the flag off", ceilings(halt=True),
        flags=("--halt-on-denial",), policy=policy(halt_on_denial=False)),
    # -- plugins -------------------------------------------------------------------------
    Row("empty plugin policy changes nothing", ceilings(), plugins=plugins()),
    Row(
        "plugin lower than the flags wins",
        ceilings(turns=6, tool_calls=8, budget=0.75),
        plugins=plugins(max_turns=6, max_tool_calls=8, max_budget_usd=0.75),
    ),
    Row(
        "plugin higher than the flags loses",
        ceilings(turns=4, tool_calls=6, budget=0.1),
        flags=("--max-turns", "4", "--max-tool-calls", "6", "--max-budget-usd", "0.1"),
        plugins=plugins(max_turns=10, max_tool_calls=20, max_budget_usd=3.0),
    ),
    Row("plugin halt_on_denial switches it on", ceilings(halt=True), plugins=plugins(halt_on_denial=True)),
    Row("plugins have no say over compaction", ceilings(), plugins=plugins(compaction_threshold_tokens=1_000)),
    # -- policy file and plugins together: the lowest of all three -----------------------
    Row(
        "policy lowest",
        ceilings(turns=2, tool_calls=4, budget=0.2),
        flags=("--max-budget-usd", "5"),
        policy=policy(max_turns=2, max_tool_calls=4, max_budget_usd=0.2),
        plugins=plugins(max_turns=9, max_tool_calls=9, max_budget_usd=0.9),
    ),
    Row(
        "plugin lowest",
        ceilings(turns=3, tool_calls=2, budget=0.1),
        flags=("--max-budget-usd", "5"),
        policy=policy(max_turns=8, max_tool_calls=8, max_budget_usd=0.8),
        plugins=plugins(max_turns=3, max_tool_calls=2, max_budget_usd=0.1),
    ),
    Row(
        "mixed: each ceiling takes its own minimum",
        ceilings(turns=5, tool_calls=7, budget=0.3),
        flags=("--max-turns", "5", "--max-budget-usd", "0.3"),
        policy=policy(max_turns=9, max_tool_calls=7),
        plugins=plugins(max_turns=12, max_budget_usd=2.0),
    ),
    Row("either halt_on_denial source is enough", ceilings(halt=True),
        policy=policy(halt_on_denial=False), plugins=plugins(halt_on_denial=True)),
    # -- running as an agent definition --------------------------------------------------
    Row("definition supplies turns and tool calls", ceilings(turns=4, tool_calls=9), definition=REVIEWER),
    Row("built-in general definition", ceilings(turns=12, tool_calls=40), definition=general_agent()),
    Row("built-in planner definition", ceilings(turns=6, tool_calls=20), definition=planner_agent()),
    Row(
        "definition does not touch budget, compaction or halt_on_denial",
        ceilings(turns=4, tool_calls=9, budget=1.5, compaction=2_000, halt=True),
        flags=("--max-budget-usd", "1.5", "--compaction-threshold-tokens", "2000", "--halt-on-denial"),
        definition=REVIEWER,
    ),
    Row(
        "policy tightens the definition",
        ceilings(turns=2, tool_calls=3),
        definition=REVIEWER,
        policy=policy(max_turns=2, max_tool_calls=3),
    ),
    Row(
        "policy looser than the definition loses",
        ceilings(turns=4, tool_calls=9),
        definition=REVIEWER,
        policy=policy(max_turns=20, max_tool_calls=40),
    ),
    Row(
        "plugin tightens the definition",
        ceilings(turns=1, tool_calls=2),
        definition=REVIEWER,
        plugins=plugins(max_turns=1, max_tool_calls=2),
    ),
    Row(
        "definition, policy and plugin: lowest of each",
        ceilings(turns=3, tool_calls=5),
        definition=REVIEWER,
        policy=policy(max_turns=3, max_tool_calls=12),
        plugins=plugins(max_turns=10, max_tool_calls=5),
    ),
)


class ResolveCeilingsTableTests(unittest.TestCase):
    def test_every_row(self):
        self.assertEqual(len({row.name for row in ROWS}), len(ROWS), "row names must be unique")
        for row in ROWS:
            with self.subTest(row.name):
                got = resolve_ceilings(run_args(*row.flags), row.definition, row.policy, row.plugins)
                self.assertEqual(got, row.expected)

    def test_no_source_can_raise_a_ceiling_above_the_flags(self):
        # The tighten-only rule as a property over the table: without an agent definition,
        # no policy file or plugin row may end above what the flags alone produce.
        for row in ROWS:
            if row.definition is not None:
                continue
            with self.subTest(row.name):
                flags_only = resolve_ceilings(run_args(*row.flags), None, None, None)
                got = resolve_ceilings(run_args(*row.flags), None, row.policy, row.plugins)
                self.assertLessEqual(got.max_turns, flags_only.max_turns)
                for name in ("max_tool_calls", "max_budget_usd", "compaction_threshold"):
                    ceiling, bound = getattr(got, name), getattr(flags_only, name)
                    if bound is not None:
                        self.assertIsNotNone(ceiling, name)
                        self.assertLessEqual(ceiling, bound, name)
                self.assertGreaterEqual(got.halt_on_denial, flags_only.halt_on_denial)

    def test_max_turns_is_always_an_integer(self):
        # ``resolve_session()`` computes ``max(ceilings.max_turns, checkpoint.turns)``; a
        # None here would be a TypeError at resume time, not a configuration error.
        for row in ROWS:
            with self.subTest(row.name):
                got = resolve_ceilings(run_args(*row.flags), row.definition, row.policy, row.plugins)
                self.assertIsInstance(got.max_turns, int)


class ResolveCeilingsKnownDefectTests(unittest.TestCase):
    """Known defect, pinned so that fixing it flips these tests (an unexpected success fails).

    An agent definition *replaces* the operator's --max-turns / --max-tool-calls instead of
    tightening them: `--max-turns 3 --agent general` runs with 12 turns. Every definition's
    ceilings are at or below the flag defaults, so taking the lower of the two keeps every
    run that does not pass the flags exactly as it is today.
    """

    @unittest.expectedFailure
    def test_an_agent_definition_cannot_raise_the_operators_turn_flag(self):
        got = resolve_ceilings(run_args("--max-turns", "3"), general_agent(), None, None)
        self.assertEqual(got.max_turns, 3)

    @unittest.expectedFailure
    def test_an_agent_definition_cannot_raise_the_operators_tool_call_flag(self):
        got = resolve_ceilings(run_args("--max-tool-calls", "2"), general_agent(), None, None)
        self.assertEqual(got.max_tool_calls, 2)


class AgentPermissionModeTableTests(unittest.TestCase):
    # (resolved mode, definition mode or None, mode the run uses)
    ROWS = (
        ("default", None, "default"),
        ("plan", None, "plan"),
        ("acceptEdits", None, "acceptEdits"),
        ("bypassPermissions", None, "bypassPermissions"),
        ("default", "default", "default"),
        ("plan", "default", "plan"),
        ("acceptEdits", "default", "default"),
        ("bypassPermissions", "default", "default"),
        ("default", "plan", "plan"),
        ("plan", "plan", "plan"),
        ("acceptEdits", "plan", "plan"),
        ("bypassPermissions", "plan", "plan"),
    )

    def test_every_row(self):
        for resolved, own, expected in self.ROWS:
            with self.subTest(resolved=resolved, definition=own):
                definition = None if own is None else AgentDefinition(name="a", tools=("Read",), permission_mode=own)
                self.assertEqual(agent_permission_mode(resolved, definition), expected)

    def test_a_definition_never_loosens_and_never_exceeds_its_own_mode(self):
        order = ("plan", "default", "acceptEdits", "bypassPermissions")
        for resolved, own, expected in self.ROWS:
            if own is None:
                continue
            with self.subTest(resolved=resolved, definition=own):
                self.assertLessEqual(order.index(expected), order.index(resolved))
                self.assertLessEqual(order.index(expected), order.index(own))


class _CliCase(RuntimeTestCase):
    """``cli.main()`` in-process, with stdout/stderr captured and no stdin."""

    _PLAN_POLICY = 'schema_version = "northstar.policy.v1"\npermission_mode = "plan"\n'

    def invoke(self, *argv: str) -> tuple[int, str, str]:
        from cli import main

        out, err = io.StringIO(), io.StringIO()
        saved, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(list(argv))
        finally:
            sys.stdin = saved
        return code, out.getvalue(), err.getvalue()

    def dry_run(self, root: Path, *flags: str) -> tuple[int, str, str]:
        return self.invoke("run", "--workspace", str(root), "--prompt", "x", "--scripted-text", "y", "--dry-run", *flags)


class CliGovernanceKnownDefectTests(_CliCase):
    """Known defects found next to the ceilings, pinned the same way as above.

    The T02 shape: a value is resolved in one place and a later step reads a different
    source, so the check that was made is not the one enforced.
    """

    @unittest.expectedFailure
    def test_mcp_roots_offer_the_workspace_not_the_current_directory(self):
        # --mcp-allow-roots promises "exactly one root, the workspace itself", but
        # _connect_mcp_clients() passes Path.cwd(), so running from a parent directory
        # hands the server that directory instead.
        import mcp_client
        from cli import _connect_mcp_clients
        from tools import build_default_registry

        workspace = self.workspace()
        seen: dict[str, object] = {}

        class FakeClient:
            negotiation = None

            def __init__(self, name, command, **options):
                seen.update(options)

            def connect(self):
                pass

            def close(self):
                pass

        args = build_parser().parse_args(["run", "--prompt", "x", "--workspace", str(workspace), "--mcp-allow-roots"])
        with mock.patch.object(mcp_client, "McpStdioClient", FakeClient), \
                mock.patch.object(mcp_client, "mcp_tool_specs", lambda client: ()):
            _connect_mcp_clients([("fs", ["python3"])], 1000, build_default_registry(), args)
        self.assertTrue(seen["allow_roots"])
        self.assertEqual(Path(seen["workspace_root"]).resolve(), workspace.resolve())


class AgentRunTightenOnlyTests(_CliCase):
    """Running *as* an agent definition may only tighten what the run already resolved.

    ``resolve_permission_mode()`` pins the policy file's (or a plugin's) ``plan`` and honours
    an operator's ``--plan``; the definition may add ``plan`` on top, but it may not hand the
    run a looser mode than the one resolved. Likewise the MCP guard for agent runs must cover
    every way a server list reaches the run, not only ``--mcp-server``.
    """

    _WRITE_SCRIPT = [{"tool": {"name": "Write", "input": {"path": "b.txt", "content": "made"}, "id": "t1"}}, {"text": "ok"}]

    def run_script(self, root: Path, *flags: str) -> tuple[int, str, str]:
        script = self.temp_dir() / "script.json"
        script.write_text(json.dumps(self._WRITE_SCRIPT), encoding="utf-8")
        return self.invoke("run", "--workspace", str(root), "--prompt", "x", "--script", str(script), *flags)

    def test_the_policy_files_plan_mode_binds_without_an_agent(self):
        # Control: without an agent the policy file's plan has always bound.
        code, out, err = self.dry_run(self.workspace({".northstar/config.toml": self._PLAN_POLICY}))
        self.assertEqual(code, 0, err)
        self.assertIn("permission_mode=plan\n", out)

    def test_the_policy_files_plan_mode_survives_running_as_an_agent(self):
        # resolve_permission_mode() pins 'plan'; the definition's own 'default' must not
        # replace it (it did before agent_permission_mode()).
        code, out, err = self.dry_run(self.workspace({".northstar/config.toml": self._PLAN_POLICY}), "--agent", "general")
        self.assertEqual(code, 0, err)
        self.assertIn("permission_mode=plan\n", out)

    def test_the_operators_plan_flag_survives_running_as_an_agent(self):
        code, out, err = self.dry_run(self.workspace(), "--plan", "--agent", "general")
        self.assertEqual(code, 0, err)
        self.assertIn("permission_mode=plan\n", out)

    def test_an_mcp_server_flag_is_refused_on_an_agent_run(self):
        code, _out, err = self.dry_run(self.workspace(), "--agent", "explorer", "--mcp-server", "fs=python3")
        self.assertEqual(code, 64)
        self.assertIn("cannot be combined with an agent-definition run", err)

    def test_an_mcp_config_file_is_refused_on_an_agent_run(self):
        # The guard in _resolve_mcp_servers() once checked only --mcp-server and plugin
        # servers, so the same server declared in .mcp.json joined the agent's fixed subset.
        root = self.workspace({".mcp.json": '{"mcpServers": {"fs": {"command": "python3", "args": ["-c", "pass"]}}}'})
        code, _out, _err = self.dry_run(root, "--agent", "explorer", "--mcp-config", "auto")
        self.assertEqual(code, 64)

    def test_a_policy_plan_refuses_a_write_under_plan_when_running_as_an_agent(self):
        # Without a host approval callback the CLI refuses an unapproved Write in 'default'
        # too, so what differs is the mode the refusal - and the run's record - is made
        # under. An explicit --allow-tool still wins over plan, with or without an agent
        # (the gate's documented layer order), so this call is deliberately not approved.
        root = self.workspace({".northstar/config.toml": self._PLAN_POLICY})
        code, out, err = self.run_script(root, "--agent", "general")
        self.assertFalse((root / "b.txt").exists())
        self.assertIn("permission_mode=plan sidecar=off", out)
        self.assertIn("plan mode is read-only; Write would change state", out)
        self.assertIn("refused: Write", err)

    def test_an_agent_run_never_widens_the_operators_mode(self):
        # The fix must tighten only: a definition in 'default' keeps a bypass flag at
        # 'default', exactly as before, rather than inheriting the wider mode.
        code, out, err = self.dry_run(self.workspace(), "--permission-mode", "bypassPermissions", "--agent", "general")
        self.assertEqual(code, 0, err)
        self.assertIn("permission_mode=default\n", out)

    def test_a_plan_definition_still_pins_plan(self):
        code, out, err = self.dry_run(self.workspace(), "--permission-mode", "acceptEdits", "--agent", "planner")
        self.assertEqual(code, 0, err)
        self.assertIn("permission_mode=plan\n", out)

    def test_an_mcp_config_refusal_names_the_flag(self):
        root = self.workspace({".mcp.json": '{"mcpServers": {"fs": {"command": "python3", "args": ["-c", "pass"]}}}'})
        code, _out, err = self.dry_run(root, "--agent", "explorer", "--mcp-config", "auto")
        self.assertEqual(code, 64, err)
        self.assertIn("--mcp-config cannot be combined with an agent-definition run", err)

    def test_mcp_config_off_is_fine_on_an_agent_run(self):
        root = self.workspace({".mcp.json": '{"mcpServers": {"fs": {"command": "python3", "args": ["-c", "pass"]}}}'})
        code, out, err = self.dry_run(root, "--agent", "explorer", "--mcp-config", "off")
        self.assertEqual(code, 0, err)
        self.assertIn("mcp_servers=off", out)


if __name__ == "__main__":
    unittest.main()
