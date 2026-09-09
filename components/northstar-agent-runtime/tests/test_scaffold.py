"""The project scaffold (`cli new`): generated files load clean under the
runtime's own validators, so a new governed project starts correct."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import cli
import policy_file
from scaffold import AGENTS_MD, scaffold_project


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


KNOWN_TOOLS = ("Read", "Grep", "LS", "Write", "Edit", "DescribeTools", "Task")


class ScaffoldTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.project = self.root / "my-project"

    def tearDown(self):
        self._tmp.cleanup()

    def scaffold(self, directory: Path | None = None) -> list[Path]:
        return scaffold_project(directory or self.project)

    # -- generated structure -------------------------------------------------

    def test_scaffold_creates_the_expected_files(self):
        created = self.scaffold()
        relative = {path.relative_to(self.project) for path in created}
        self.assertEqual(
            relative,
            {
                Path(".northstar/config.toml"),
                Path(".northstar/agents/reviewer.md"),
                Path(".northstar/hooks/README.md"),
                Path(".northstar/skills/README.md"),
                Path(".github/workflows/northstar-review.yml"),
                Path("AGENTS.md"),
                Path("README.md"),
            },
        )

    def test_refuses_a_non_empty_directory_without_force(self):
        self.scaffold()
        with self.assertRaises(ValueError) as caught:
            scaffold_project(self.project)
        self.assertIn("not empty", str(caught.exception))

    def test_force_writes_into_a_non_empty_directory_without_deleting(self):
        self.project.mkdir(parents=True)
        (self.project / "keep.txt").write_text("mine", encoding="utf-8")
        scaffold_project(self.project, force=True)
        self.assertEqual((self.project / "keep.txt").read_text(encoding="utf-8"), "mine")
        self.assertTrue((self.project / AGENTS_MD).is_file())

    def test_scaffold_into_an_empty_existing_directory_is_allowed(self):
        self.project.mkdir(parents=True)
        created = self.scaffold()
        self.assertEqual(len(created), 7)

    # -- generated files are valid under the runtime's own loaders -------------

    def test_policy_file_loads_with_v1_schema_and_a_revision(self):
        self.scaffold()
        policy = policy_file.load_policy_file(
            self.project,
            known_tools=KNOWN_TOOLS,
            known_agents=("reviewer",),
        )
        self.assertIsNotNone(policy)
        assert policy is not None
        self.assertEqual(policy.schema_version, "northstar.policy.v1")
        self.assertIsNotNone(policy.revision)
        self.assertEqual(policy.agent, "reviewer")  # governance default baked in
        self.assertEqual(policy.project_context_setting, "AGENTS.md")

    def test_reviewer_agent_registers_as_read_only_plan(self):
        self.scaffold()
        from agent_files import AgentFileError, register_workspace_agents
        from agents import builtin_registry

        agents = builtin_registry()
        register_workspace_agents(agents, self.project, known_tools=KNOWN_TOOLS)
        reviewer = agents.get("reviewer")
        self.assertIsNotNone(reviewer)
        assert reviewer is not None
        self.assertTrue(reviewer.is_read_only)
        self.assertEqual(reviewer.permission_mode, "plan")
        self.assertEqual(set(reviewer.tools), {"Read", "Grep", "LS", "DescribeTools"})
        self.assertFalse({"Write", "Edit"} & set(reviewer.tools))

    def test_ag_md_is_discovered_as_project_context(self):
        self.scaffold()
        context = policy_file.discover_project_context(
            self.project, configured="AGENTS.md", explicit=None
        )
        self.assertIsNotNone(context)
        assert context is not None
        self.assertEqual(context.name, "AGENTS.md")
        self.assertIn("my-project", context.text)

    def test_workflow_template_is_a_yaml_looking_recipe_with_todos(self):
        self.scaffold()
        workflow = (self.project / ".github/workflows/northstar-review.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request", workflow)
        self.assertIn("northstar-agent-runtime run --workspace . --agent reviewer", workflow)
        self.assertIn("TODO", workflow)

    # -- CLI end to end ---------------------------------------------------------

    def test_cli_new_scaffolds_and_lists_created_files(self):
        code, out, err = run_cli("new", str(self.project))
        self.assertEqual(code, 0, err)
        self.assertIn("created", out)
        self.assertIn(".northstar/config.toml", out)
        self.assertTrue((self.project / AGENTS_MD).is_file())

    def test_cli_new_refuses_a_non_empty_directory_with_64(self):
        self.project.mkdir(parents=True)
        (self.project / "x.txt").write_text("x", encoding="utf-8")
        code, out, err = run_cli("new", str(self.project))
        self.assertEqual(code, cli.USAGE_ERROR)
        self.assertIn("not empty", err)

    def test_cli_new_force_overwrites_the_template(self):
        self.project.mkdir(parents=True)
        (self.project / AGENTS_MD).write_text("stale", encoding="utf-8")
        code, _, _ = run_cli("new", str(self.project), "--force")
        self.assertEqual(code, 0)
        self.assertIn("project instructions", (self.project / AGENTS_MD).read_text(encoding="utf-8").lower())

    def test_scaffolded_project_passes_doctor(self):
        self.scaffold()
        code, out, _ = run_cli("doctor", "--workspace", str(self.project))
        self.assertEqual(code, 0)
        self.assertIn("ready to run", out)

    def test_scaffolded_project_dry_run_reports_policy_identity_and_agent(self):
        self.scaffold()
        code, out, _ = run_cli(
            "run", "--workspace", str(self.project), "--prompt", "hi",
            "--scripted-text", "ok", "--dry-run",
        )
        self.assertEqual(code, 0)
        self.assertIn("schema=northstar.policy.v1", out)
        self.assertIn("revision=", out)
        self.assertIn("workspace_agents=reviewer", out)

    def test_scaffolded_project_runs_one_scripted_turn_as_reviewer(self):
        self.scaffold()
        code, out, err = run_cli(
            "run", "--workspace", str(self.project), "--prompt", "hi",
            "--scripted-text", "all good",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("[success]", out)


if __name__ == "__main__":
    unittest.main()
