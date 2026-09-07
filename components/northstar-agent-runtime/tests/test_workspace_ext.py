"""Workspace extension content: skills (``.northstar/skills``) and agent files
(``.northstar/agents``) plus their shared strict frontmatter reader.

Governance contract under test: repository extension files may only *tighten*.
Unknown keys, unparseable frontmatter, unknown tool names, loosening modes or
ceilings, and symlinks escaping the workspace are configuration errors (the CLI
exits 64) - never silently ignored. Skills are knowledge packages: only the
name/description listing enters the prompt and the full file stays readable
through the ordinary sandboxed ``Read`` tool.
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

import agent_files
import skills
from agent_files import AgentFileError, discover_agent_files, register_workspace_agents
from agents import builtin_registry, READ_ONLY_TOOLS
from cli import USAGE_ERROR, main
from frontmatter import FrontmatterError, parse_frontmatter
from skills import SkillError, discover_skills, skill_listing
from tools import build_default_registry

KNOWN_TOOLS = build_default_registry().names()


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    saved_stdin, sys.stdin = sys.stdin, io.StringIO("")
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


class FrontmatterTests(unittest.TestCase):
    def test_no_frontmatter_returns_none_fields(self):
        fields, body = parse_frontmatter("just a body\n")
        self.assertIsNone(fields)
        self.assertIn("just a body", body)

    def test_scalars_are_typed(self):
        fields, body = parse_frontmatter(
            "---\nname: demo\ndescription: 'A skill'\ncount: 3\nratio: 1.5\nenabled: true\n---\nbody text\n"
        )
        self.assertEqual(fields["name"], "demo")
        self.assertEqual(fields["description"], "A skill")
        self.assertEqual(fields["count"], 3)
        self.assertEqual(fields["ratio"], 1.5)
        self.assertIs(fields["enabled"], True)
        self.assertEqual(body, "body text")

    def test_inline_and_block_arrays(self):
        fields, _ = parse_frontmatter("---\ntools: [Read, Grep]\ndeny:\n  - Write\n  - Edit\n---\n")
        self.assertEqual(fields["tools"], ["Read", "Grep"])
        self.assertEqual(fields["deny"], ["Write", "Edit"])

    def test_malformed_input_is_an_error(self):
        with self.assertRaises(FrontmatterError):
            parse_frontmatter("---\nname: demo\nnever closed\n")
        with self.assertRaises(FrontmatterError):
            parse_frontmatter("---\nname demo\n---\n")
        with self.assertRaises(FrontmatterError):
            parse_frontmatter("---\nname: a\nname: b\n---\n")
        with self.assertRaises(FrontmatterError):
            parse_frontmatter("---\nbad key!: x\n---\n")

    def test_comments_and_blank_lines_are_skipped(self):
        fields, _ = parse_frontmatter("---\n# a comment\n\nname: demo\n---\n")
        self.assertEqual(fields["name"], "demo")


class SkillTests(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-skills-"))
        self.skills_dir = self.ws / ".northstar" / "skills"

    def write_skill(self, name: str, text: str) -> Path:
        folder = self.skills_dir / name
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "SKILL.md"
        path.write_text(text, encoding="utf-8")
        return path

    def test_a_skill_is_discovered_with_name_and_description(self):
        self.write_skill(
            "demo",
            "---\nname: demo\ndescription: Does demo things.\n---\nThe body is read via Read.\n",
        )
        found = discover_skills(self.ws)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "demo")
        self.assertEqual(found[0].description, "Does demo things.")

    def test_absent_directory_means_no_skills(self):
        self.assertEqual(discover_skills(self.ws), ())

    def test_missing_frontmatter_or_unknown_key_is_an_error(self):
        path = self.write_skill("bad1", "no frontmatter here\n")
        with self.assertRaises(SkillError):
            discover_skills(self.ws)
        path.write_text("---\nname: bad2\ndescription: x\nbogus: 1\n---\nbody\n", encoding="utf-8")
        with self.assertRaises(SkillError) as caught:
            discover_skills(self.ws)
        self.assertIn("bogus", str(caught.exception))

    def test_missing_required_fields_is_an_error(self):
        self.write_skill("bad", "---\nname: x\n---\nbody\n")
        with self.assertRaises(SkillError):
            discover_skills(self.ws)
        self.write_skill("bad2", "---\ndescription: x\n---\nbody\n")
        with self.assertRaises(SkillError):
            discover_skills(self.ws)

    def test_a_symlinked_skill_folder_escaping_the_workspace_is_refused(self):
        outside = Path(tempfile.mkdtemp(prefix="nsar-outside-"))
        (outside / "SKILL.md").write_text("---\nname: evil\ndescription: x\n---\nbody\n", encoding="utf-8")
        folder = self.skills_dir / "evil"
        folder.mkdir(parents=True)
        (folder / "SKILL.md").symlink_to(outside / "SKILL.md")
        with self.assertRaises(SkillError) as caught:
            discover_skills(self.ws)
        self.assertIn("outside the workspace", str(caught.exception))

    def test_listing_is_bounded_and_contains_paths(self):
        self.write_skill(
            "demo",
            "---\nname: demo\ndescription: Does demo things.\n---\nbody\n",
        )
        listing = skill_listing(discover_skills(self.ws), self.ws)
        self.assertIn("== Workspace skills ==", listing)
        self.assertIn("- demo: Does demo things.", listing)
        self.assertIn(".northstar/skills/demo/SKILL.md", listing)
        self.assertIn("== End of workspace skills ==", listing)

    def test_no_frontmatter_key_typos_in_a_skill(self):
        self.write_skill("demo", "---\nname: demo\ndescription: x\n---\n")
        # case sensitivity: an uppercase key is an unknown key
        path = self.skills_dir / "demo" / "SKILL.md"
        path.write_text("---\nName: demo\ndescription: x\n---\n", encoding="utf-8")
        with self.assertRaises(SkillError):
            discover_skills(self.ws)


class AgentFileTests(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-agents-"))
        self.agents_dir = self.ws / ".northstar" / "agents"

    def write_agent(self, name: str, text: str) -> Path:
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        path = self.agents_dir / f"{name}.md"
        path.write_text(text, encoding="utf-8")
        return path

    def test_an_agent_file_compiles_to_a_definition(self):
        self.write_agent(
            "summariser",
            "---\nname: summariser\ndescription: Summarises.\ntools: [Read, Grep, LS]\nmax_turns: 4\n---\nSummarise the workspace.\n",
        )
        found = discover_agent_files(self.ws, known_tools=KNOWN_TOOLS)
        self.assertEqual(len(found), 1)
        agent = found[0]
        self.assertEqual(agent.name, "summariser")
        self.assertEqual(agent.tools, ("Read", "Grep", "LS"))
        self.assertEqual(agent.max_turns, 4)
        self.assertIn("Summarise the workspace.", agent.prompt)
        self.assertTrue(agent.is_read_only)

    def test_registry_registration_and_collisions(self):
        self.write_agent(
            "helper",
            "---\nname: helper\ndescription: H.\ntools: [Read]\n---\nHelp.\n",
        )
        registry = builtin_registry()
        discovered = register_workspace_agents(registry, self.ws, known_tools=KNOWN_TOOLS)
        self.assertIn("helper", registry.names())
        self.assertEqual(discovered[0].name, "helper")
        # A second file with the same name collides.
        self.write_agent("helper2", "---\nname: helper\ndescription: H2.\ntools: [Read]\n---\nHelp2.\n")
        with self.assertRaises(AgentFileError):
            register_workspace_agents(registry, self.ws, known_tools=KNOWN_TOOLS)

    def test_shadowing_a_builtin_is_refused(self):
        self.write_agent(
            "explorer",
            "---\nname: explorer\ndescription: H.\ntools: [Read]\n---\nHi.\n",
        )
        registry = builtin_registry()
        with self.assertRaises(AgentFileError):
            register_workspace_agents(registry, self.ws, known_tools=KNOWN_TOOLS)

    def test_loosening_or_unknown_input_is_an_error(self):
        cases = {
            "bypass.md": '---\nname: bypass\ndescription: x\ntools: [Read]\npermission_mode: "bypassPermissions"\n---\n',
            "badkey.md": '---\nname: badkey\ndescription: x\ntools: [Read]\nallow_edit: true\n---\n',
            "unknown-tool.md": '---\nname: ut\ndescription: x\ntools: [Read, NoSuchTool]\n---\n',
            "toohigh.md": '---\nname: toohigh\ndescription: x\ntools: [Read]\nmax_turns: 99\n---\n',
            "notools.md": "---\nname: none\ndescription: x\ntools: []\n---\n",
            "emptybody.md": "---\nname: empty\ndescription: x\ntools: [Read]\n---\n",
        }
        for filename, text in cases.items():
            self.write_agent(filename, text)
            with self.assertRaises(AgentFileError, msg=filename):
                discover_agent_files(self.ws, known_tools=KNOWN_TOOLS)

    def test_read_only_filters_mutating_tools_out(self):
        self.write_agent(
            "r",
            "---\nname: ro\ndescription: x\ntools: [Read, Write]\nread_only: true\n---\nBody.\n",
        )
        found = discover_agent_files(self.ws, known_tools=KNOWN_TOOLS)
        self.assertEqual(found[0].tools, ("Read",))
        self.assertTrue(found[0].read_only_enforced)

    def test_a_symlinked_agent_file_escaping_the_workspace_is_refused(self):
        outside = Path(tempfile.mkdtemp(prefix="nsar-outside-")) / "a.md"
        outside.write_text("---\nname: evil\ndescription: x\ntools: [Read]\n---\n", encoding="utf-8")
        self.agents_dir.mkdir(parents=True)
        (self.agents_dir / "evil.md").symlink_to(outside)
        with self.assertRaises(AgentFileError) as caught:
            discover_agent_files(self.ws, known_tools=KNOWN_TOOLS)
        self.assertIn("outside the workspace", str(caught.exception))


class WorkspaceExtensionCliTests(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-cliext-"))
        (self.ws / ".northstar").mkdir(exist_ok=True)
        (self.ws / ".northstar" / "agents").mkdir()
        (self.ws / ".northstar" / "agents" / "summariser.md").write_text(
            "---\nname: summariser\ndescription: Summarises.\ntools: [Read, Grep, LS]\nmax_turns: 3\n---\n"
            "Summarise the workspace.\n",
            encoding="utf-8",
        )
        (self.ws / "f.txt").write_text("hello\n", encoding="utf-8")

    def dry(self, *extra: str):
        return run_cli("run", "--workspace", str(self.ws), "--prompt", "hi",
                       "--scripted-text", "reply", "--dry-run", *extra)

    def test_dry_run_reports_repository_agents_and_skills(self):
        (self.ws / ".northstar" / "skills").mkdir()
        skill_dir = self.ws / ".northstar" / "skills" / "guide"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: guide\ndescription: Navigates.\n---\nBody.\n", encoding="utf-8"
        )
        code, out, _ = self.dry()
        self.assertEqual(code, 0)
        self.assertIn("workspace_agents=summariser", out)
        self.assertIn("skills=1 package(s): guide", out)

    def test_the_file_agent_runs_as_agent(self):
        code, out, err = run_cli("run", "--workspace", str(self.ws), "--prompt", "summarise",
                                 "--scripted-text", "done", "--agent", "summariser", "--quiet")
        self.assertEqual(code, 0, err)
        self.assertIn("[success]", out)

    def test_agents_subcommand_lists_the_file_agent(self):
        code, out, _ = run_cli("agents", "--workspace", str(self.ws))
        self.assertEqual(code, 0)
        self.assertIn("summariser", out)

    def test_an_invalid_agent_file_is_a_configuration_error(self):
        (self.ws / ".northstar" / "agents" / "bad.md").write_text(
            "---\nname: bad\ndescription: x\ntools: [Read]\nallow_edit: true\n---\n", encoding="utf-8"
        )
        code, _, err = self.dry()
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("configuration error", err)

    def test_no_workspace_agents_flag_skips_discovery(self):
        code, out, _ = self.dry("--no-workspace-agents")
        self.assertEqual(code, 0)
        self.assertIn("workspace_agents=none", out)

    def test_a_loosening_agent_file_never_reaches_the_registry(self):
        (self.ws / ".northstar" / "agents" / "bad.md").write_text(
            "---\nname: bad\ndescription: x\ntools: [Read]\nmax_turns: 99\n---\n", encoding="utf-8"
        )
        code, _, err = self.dry()
        self.assertEqual(code, USAGE_ERROR)
        self.assertIn("may only tighten", err)


if __name__ == "__main__":
    unittest.main()
