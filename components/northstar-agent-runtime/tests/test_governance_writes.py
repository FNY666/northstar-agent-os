"""The agent must not be able to rewrite the governance that gates it.

``.northstar`` holds the policy file, the repository subagent definitions, and the
skill packages that reach the system prompt. Before this rule a run with workspace
edit rights could replace its own policy - not to *loosen* it past the built-in
floor (a policy file may only tighten, and a loosened value fails closed), but to
silently drop tightenings for every later run, plant poisoned instructions, or
corrupt the file so the workspace refuses to run at all.
"""
from __future__ import annotations

from pathlib import Path

from support import RuntimeTestCase, tool_turn  # noqa: F401 - bootstraps sys.path first
from providers.base import SystemMessage

from tools import ToolAccessError, ToolLimits, ToolSandbox, build_default_registry


def _model_visible_error(report) -> str:
    """Every errored tool_result the model was shown, concatenated."""
    from providers.base import ToolResultBlock, UserMessage, flatten_result_content

    seen = []
    for event in report.events_of(UserMessage):
        for block in event.content:
            if isinstance(block, ToolResultBlock) and block.is_error:
                seen.append(flatten_result_content([block]))
    return "\n".join(seen)


def _init_data(report) -> dict:
    """The ``init`` event payload, which is where attribution has to be visible."""
    for event in report.events_of(SystemMessage):
        if event.subtype == "init":
            return dict(event.data)
    raise AssertionError("the run produced no init event")

POLICY = "schema_version = \"northstar.policy.v1\"\nrevision = \"rev-1\"\n"
GOVERNANCE_PATHS = (
    ".northstar/config.toml",
    ".northstar/agents/reviewer.md",
    ".northstar/skills/quiet/SKILL.md",
)


class DefaultLimitsTests(RuntimeTestCase):
    def test_northstar_is_protected_by_default(self):
        self.assertIn(".northstar", ToolLimits().protected_prefixes)
        self.assertIn(".git", ToolLimits().protected_prefixes)

    def test_every_governance_path_is_refused_for_writes(self):
        root = self.workspace({path: "original\n" for path in GOVERNANCE_PATHS})
        sandbox = ToolSandbox(root, limits=ToolLimits())
        for relative in GOVERNANCE_PATHS:
            with self.subTest(path=relative):
                with self.assertRaises(ToolAccessError) as caught:
                    sandbox.resolve(relative, for_write=True)
                self.assertIn("must not rewrite the rules that gate it", str(caught.exception))
                self.assertIn("--allow-policy-writes", str(caught.exception))

    def test_reads_are_unaffected(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        sandbox = ToolSandbox(root, limits=ToolLimits())
        resolved = sandbox.resolve(".northstar/config.toml", for_write=False, must_exist=True)
        self.assertEqual(resolved.read_text(encoding="utf-8"), POLICY)

    def test_a_new_governance_file_is_also_refused(self):
        # The directory exists but the file does not: containment runs on the
        # nearest existing ancestor, so a fresh file cannot slip past.
        root = self.workspace({".northstar/config.toml": POLICY})
        sandbox = ToolSandbox(root, limits=ToolLimits())
        with self.assertRaises(ToolAccessError):
            sandbox.resolve(".northstar/agents/evil.md", for_write=True)

    def test_indirection_cannot_reach_the_governance_tree(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        outside = self.workspace({"elsewhere/config.toml": "x\n"})
        link = root / "escape.toml"
        try:
            link.symlink_to(outside / "elsewhere" / "config.toml")
        except (OSError, NotImplementedError):  # pragma: no cover - host policy
            self.skipTest("symlinks are unavailable here")
        sandbox = ToolSandbox(root, limits=ToolLimits())
        # A link out of the workspace is refused on containment, before any write.
        with self.assertRaises(ToolAccessError):
            sandbox.resolve("escape.toml", for_write=True)

    def test_host_can_still_widen_explicitly(self):
        root = self.workspace({".northstar/config.toml": POLICY})
        sandbox = ToolSandbox(root, limits=ToolLimits(protected_prefixes=(".git",)))
        self.assertTrue(sandbox.resolve(".northstar/config.toml", for_write=True).exists())


class RegistryHandlerTests(RuntimeTestCase):
    """The refusal must come from the sandbox, not from a model-visible string check."""

    def _write(self, root: Path, *, limits: ToolLimits, path: str, content: str):
        from tools import ToolContext

        registry = build_default_registry()
        sandbox = ToolSandbox(root, limits=limits)
        context = ToolContext(session_id="t", sandbox=sandbox, limits=limits, services={"registry": registry})
        spec = registry.get("Write")
        return spec.handler({"path": path, "content": content}, context)

    def test_write_handler_refuses_at_the_sandbox_layer(self):
        # The handler raises; the loop converts a ToolAccessError into an errored
        # tool_result (asserted end to end in ThroughTheLoopTests). Testing the
        # raise here keeps the guarantee independent of the loop's error mapping.
        root = self.workspace({".northstar/config.toml": POLICY})
        with self.assertRaises(ToolAccessError):
            self._write(root, limits=ToolLimits(), path=".northstar/config.toml", content="pwned\n")
        self.assertEqual((root / ".northstar" / "config.toml").read_text(encoding="utf-8"), POLICY)

    def test_edit_handler_refuses_to_patch_the_policy_file(self):
        from tools import ToolContext

        root = self.workspace({".northstar/config.toml": POLICY})
        registry = build_default_registry()
        limits = ToolLimits()
        context = ToolContext(session_id="t", sandbox=ToolSandbox(root, limits=limits), limits=limits, services={"registry": registry})
        with self.assertRaises(ToolAccessError):
            registry.get("Edit").handler(
                {"path": ".northstar/config.toml", "old_string": "rev-1", "new_string": "rev-2"}, context
            )
        self.assertIn("rev-1", (root / ".northstar" / "config.toml").read_text(encoding="utf-8"))

    def test_writes_outside_the_governance_tree_still_work(self):
        root = self.workspace({".northstar/config.toml": POLICY, "notes.txt": "hi\n"})
        result = self._write(root, limits=ToolLimits(), path="notes.txt", content="updated\n")
        self.assertFalse(result.is_error)
        self.assertEqual((root / "notes.txt").read_text(encoding="utf-8"), "updated\n")


class ThroughTheLoopTests(RuntimeTestCase):
    """End to end: a scripted agent with edit rights cannot rewrite its own policy."""

    def _run(self, *, extra_config: dict | None = None):
        root = self.workspace({".northstar/config.toml": POLICY})
        runtime = self.runtime(
            [
                tool_turn("Write", {"path": ".northstar/config.toml", "content": "revision = \"evil\"\n"}),
                {"text": "done"},
            ],
            workspace=root,
            permission_mode="acceptEdits",
            **(extra_config or {}),
        )
        return root, self.drive(runtime)

    def test_accept_edits_does_not_open_the_governance_tree(self):
        root, report = self._run()
        self.assertEqual(report.subtype, "success")
        self.assertTrue(report.tool_calls[0].is_error)
        self.assertIn("rev-1", (root / ".northstar" / "config.toml").read_text(encoding="utf-8"))
        self.assertIn(".northstar", _init_data(report)["protected_prefixes"])
        self.assertIn("governance", _model_visible_error(report))

    def test_the_opt_out_is_auditable(self):
        root, report = self._run(extra_config={"tool_limits": ToolLimits(protected_prefixes=(".git",))})
        self.assertFalse(report.tool_calls[0].is_error)
        self.assertEqual(_init_data(report)["protected_prefixes"], [".git"])
        self.assertIn("evil", (root / ".northstar" / "config.toml").read_text(encoding="utf-8"))


class RunConfigurationTests(RuntimeTestCase):
    def test_correlation_keys_are_validated(self):
        from loop import RuntimeConfigurationError, RuntimeConfig

        for bad in ("", "  ", "has space", "a/b", "a\\b", "x" * 129):
            with self.subTest(value=bad):
                with self.assertRaises(RuntimeConfigurationError):
                    RuntimeConfig(model="claude-sonnet-4-5", run_id=bad)
        with self.assertRaises(RuntimeConfigurationError):
            RuntimeConfig(model="claude-sonnet-4-5", policy_revision="no\\slash")
        config = RuntimeConfig(model="claude-sonnet-4-5", run_id="run-7", policy_revision="rev-3")
        self.assertEqual((config.run_id, config.policy_revision), ("run-7", "rev-3"))
