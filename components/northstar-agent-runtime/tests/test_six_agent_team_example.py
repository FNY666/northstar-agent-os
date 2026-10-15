"""Smoke test the checked-in six-agent example against the runtime loader."""
from __future__ import annotations

import contextlib
import io
import unittest
from pathlib import Path

from agent_files import discover_agent_files
from cli import main
from tools import build_default_registry


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
TEAM_WORKSPACE = REPOSITORY_ROOT / "examples" / "six-agent-team"
EXPECTED_ROLES = {
    "team_lead",
    "team_researcher",
    "team_architect",
    "team_implementer",
    "team_qa",
    "team_safety_reviewer",
}
EXPECTED_ROLE_BUDGETS = {
    "team_researcher": 0.03,
    "team_architect": 0.02,
    "team_implementer": 0.08,
    "team_qa": 0.03,
    "team_safety_reviewer": 0.02,
}


@unittest.skipUnless(
    TEAM_WORKSPACE.is_dir(),
    "repository example fixtures are absent from the component-only guard copy",
)
class SixAgentTeamExampleTests(unittest.TestCase):
    def test_all_profiles_compile_with_known_tools_and_narrow_grants(self):
        profiles = discover_agent_files(
            TEAM_WORKSPACE,
            known_tools=build_default_registry().names(),
        )
        by_name = {profile.name: profile for profile in profiles}

        self.assertEqual(set(by_name), EXPECTED_ROLES)
        lead = by_name["team_lead"]
        self.assertTrue(lead.allow_delegation)
        self.assertNotIn("Task", lead.tools)

        for name in EXPECTED_ROLES - {"team_lead"}:
            profile = by_name[name]
            self.assertFalse(profile.allow_delegation)
            self.assertLessEqual(set(profile.tools), set(lead.tools))

        for name in ("team_researcher", "team_architect", "team_safety_reviewer"):
            self.assertTrue(by_name[name].read_only_enforced, name)

        for name, budget in EXPECTED_ROLE_BUDGETS.items():
            self.assertAlmostEqual(by_name[name].max_budget_usd, budget)

    def test_cli_adds_the_virtual_task_tool_for_the_lead(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [
                    "run",
                    "--workspace",
                    str(TEAM_WORKSPACE),
                    "--agent",
                    "team_lead",
                    "--provider",
                    "scripted",
                    "--scripted-text",
                    "ready",
                    "--prompt",
                    "inspect one bounded issue",
                    "--dry-run",
                ]
            )

        self.assertEqual(code, 0, err.getvalue())
        tool_line = next(
            (line for line in out.getvalue().splitlines() if line.startswith("tools=")),
            "",
        )
        self.assertIn("Task", tool_line)


    def test_direct_run_uses_the_workspace_agent_budget_cap(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(
                [
                    "agent",
                    "--workspace",
                    str(TEAM_WORKSPACE),
                    "--agent",
                    "team_researcher",
                    "--provider",
                    "scripted",
                    "--scripted-text",
                    "ok",
                    "--max-budget-usd",
                    "0.20",
                    "--prompt",
                    "inspect one bounded issue",
                    "--dry-run",
                ]
            )

        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("max_budget_usd=0.03", out.getvalue())


if __name__ == "__main__":
    unittest.main()
