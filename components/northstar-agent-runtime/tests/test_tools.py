"""Tool sandbox, caps, and the uniform handler signature.
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path

import support  # noqa: F401
from support import RuntimeTestCase, tool_turn

from tools import (
    MAX_GREP_MATCHES,
    MAX_LIST_ENTRIES,
    MAX_READ_BYTES,
    ToolAccessError,
    ToolContext,
    ToolInputError,
    ToolLimits,
    ToolRegistry,
    ToolResult,
    ToolSandbox,
    ToolSpec,
    build_default_registry,
    codex_tool_spec,
)


def context_for(root: Path, *, limits: ToolLimits | None = None, registry: ToolRegistry | None = None) -> ToolContext:
    return ToolContext(
        session_id="test",
        sandbox=ToolSandbox(root, limits=limits or ToolLimits()),
        limits=limits or ToolLimits(),
        services={"registry": registry or build_default_registry()},
    )


class ContainmentTests(RuntimeTestCase):
    def test_relative_traversal_outside_the_workspace_is_refused(self):
        root = self.workspace({"keep.txt": "mine"})
        ctx = context_for(root)
        with self.assertRaises(ToolAccessError):
            ctx.resolve("../keep.txt")
        with self.assertRaises(ToolAccessError):
            ctx.resolve("a/../../b/../../../etc/passwd")

    def test_absolute_paths_outside_are_refused(self):
        ctx = context_for(self.workspace())
        with self.assertRaises(ToolAccessError):
            ctx.resolve("/etc/passwd")

    def test_a_symlink_pointing_outside_is_followed_before_the_check(self):
        root = self.workspace({"real.txt": "secret"})
        outside = self.workspace()
        leaked = outside / "leak.txt"
        leaked.write_text("secret", encoding="utf-8")
        os.symlink(str(leaked), root / "link.txt")
        ctx = context_for(root)
        with self.assertRaises(ToolAccessError) as caught:
            ctx.resolve("link.txt")
        self.assertIn("symlink", str(caught.exception))

    def test_a_symlinked_directory_cannot_smuggle_a_write_out(self):
        root = self.workspace()
        outside = self.workspace()
        (root / "escape").symlink_to(outside, target_is_directory=True)
        ctx = context_for(root)
        with self.assertRaises(ToolAccessError):
            ctx.resolve("escape/new-file.txt", for_write=True)
        self.assertFalse((outside / "new-file.txt").exists())

    def test_a_not_yet_created_path_is_still_checked_through_existing_parents(self):
        root = self.workspace()
        outside = self.workspace()
        (root / "sub").mkdir()
        (root / "sub" / "out").symlink_to(outside, target_is_directory=True)
        ctx = context_for(root)
        for candidate in ("sub/out/deep/nested.txt", "sub/ok.txt"):
            with self.subTest(candidate=candidate):
                if candidate.startswith("sub/out"):
                    with self.assertRaises(ToolAccessError):
                        ctx.resolve(candidate, for_write=True)
                else:
                    self.assertTrue(ctx.resolve(candidate, for_write=True))

    def test_paths_inside_the_workspace_resolve_normally(self):
        root = self.workspace({"dir/file.txt": "x"})
        ctx = context_for(root)
        resolved = ctx.resolve("dir/file.txt")
        self.assertEqual(resolved, Path(os.path.realpath(str(root))) / "dir" / "file.txt")
        self.assertEqual(ctx.relative(resolved), os.path.join("dir", "file.txt"))

    def test_the_workspace_root_itself_is_a_valid_target(self):
        root = self.workspace()
        ctx = context_for(root)
        self.assertEqual(ctx.resolve("."), Path(os.path.realpath(str(root))))

    def test_repository_metadata_is_not_writable(self):
        root = self.workspace({".git/HEAD": "ref: refs/heads/main"})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        with self.assertRaises(ToolAccessError):
            registry.require("Write").handler({"path": ".git/HEAD", "content": "hijacked"}, ctx)
        self.assertEqual((root / ".git" / "HEAD").read_text(), "ref: refs/heads/main")
        # Reading repository metadata is still allowed: it is not a mutation.
        self.assertIn("ref:", registry.require("Read").handler({"path": ".git/HEAD"}, ctx).text())

    def test_malformed_path_input_is_a_tool_error_not_a_crash(self):
        ctx = context_for(self.workspace())
        for bad in ("", "   ", "\x00", None, 5):
            with self.subTest(value=str(bad)):
                with self.assertRaises((ToolInputError, ToolAccessError)):
                    ctx.resolve(bad)

    def test_protected_prefixes_are_configurable(self):
        root = self.workspace({".git/HEAD": "x", "secrets/api.txt": "y"})
        limits = ToolLimits(protected_prefixes=(".git", "secrets"))
        registry = build_default_registry()
        ctx = context_for(root, limits=limits, registry=registry)
        with self.assertRaises(ToolAccessError):
            ctx.resolve("secrets/api.txt", for_write=True)


class CapTests(RuntimeTestCase):
    def test_read_is_capped_at_256kb_and_says_so(self):
        root = self.workspace({"big.txt": "a" * (MAX_READ_BYTES + 5000)})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        result = registry.require("Read").handler({"path": "big.txt"}, ctx)
        self.assertTrue(result.truncated)
        text = result.text()
        self.assertIn("[first 262144 of 267144 bytes", text)
        self.assertIn("truncated at 262144 of 267144 bytes", text)
        self.assertGreaterEqual(len(text), MAX_READ_BYTES)
        self.assertEqual(result.data["bytes"], MAX_READ_BYTES)
        self.assertEqual(result.data["size"], MAX_READ_BYTES + 5000)

    def test_an_explicit_max_bytes_may_only_shrink_the_cap(self):
        root = self.workspace({"big.txt": "b" * 10_000})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        small = registry.require("Read").handler({"path": "big.txt", "max_bytes": 100}, ctx)
        self.assertEqual(small.data["bytes"], 100)
        greedy = registry.require("Read").handler({"path": "big.txt", "max_bytes": 10_000_000}, ctx)
        self.assertLessEqual(len(greedy.text()), MAX_READ_BYTES + 200)

    def test_grep_caps_at_200_matches_and_reports_the_cap(self):
        root = self.workspace({"many.txt": "hit\n" * (MAX_GREP_MATCHES + 60)})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        result = registry.require("Grep").handler({"pattern": "hit"}, ctx)
        self.assertEqual(result.data["matches"], MAX_GREP_MATCHES)
        self.assertTrue(result.truncated)
        self.assertEqual(result.text().count("many.txt:"), MAX_GREP_MATCHES)
        self.assertIn("truncated at 200 matches", result.text())

    def test_listing_caps_at_500_entries(self):
        root = self.temp_dir()
        for index in range(MAX_LIST_ENTRIES + 40):
            (root / f"file{index:04d}.txt").write_text("x", encoding="utf-8")
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        result = registry.require("LS").handler({"path": "."}, ctx)
        self.assertEqual(result.data["entries"], MAX_LIST_ENTRIES)
        self.assertTrue(result.truncated)
        self.assertIn("truncated at 500 entries", result.text())

    def test_grep_skips_binary_and_oversized_files(self):
        root = self.workspace({"bin.txt": "hit\x00hit\n", "note.txt": "hit here\n"})
        limits = ToolLimits(max_grep_file_bytes=64)
        registry = build_default_registry()
        ctx = context_for(root, limits=limits, registry=registry)
        result = registry.require("Grep").handler({"pattern": "hit"}, ctx)
        self.assertEqual(result.data["matches"], 1)
        self.assertIn("note.txt", result.text())

    def test_grep_glob_filters_by_relative_path(self):
        root = self.workspace({"a/keep.py": "target\n", "a/skip.txt": "target\n"})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        result = registry.require("Grep").handler({"pattern": "target", "glob": "**/*.py"}, ctx)
        self.assertEqual(result.data["matches"], 1)
        self.assertIn("keep.py", result.text())

    def test_edit_refuses_an_ambiguous_match_instead_of_guessing(self):
        root = self.workspace({"dup.txt": "x x x\n"})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        refused = registry.require("Edit").handler({"path": "dup.txt", "old_string": "x", "new_string": "y"}, ctx)
        self.assertTrue(refused.is_error)
        self.assertIn("matches 3 places", refused.text())
        self.assertEqual((root / "dup.txt").read_text(), "x x x\n")
        all_of_them = registry.require("Edit").handler({"path": "dup.txt", "old_string": "x", "new_string": "y", "replace_all": True}, ctx)
        self.assertFalse(all_of_them.is_error)
        self.assertEqual((root / "dup.txt").read_text(), "y y y\n")

    def test_read_of_a_directory_reports_an_error(self):
        root = self.workspace({"d/f.txt": "x"})
        registry = build_default_registry()
        ctx = context_for(root, registry=registry)
        result = registry.require("Read").handler({"path": "d"}, ctx)
        self.assertTrue(result.is_error)

    def test_missing_paths_report_as_tool_errors(self):
        registry = build_default_registry()
        ctx = context_for(self.workspace(), registry=registry)
        for name, payload in (("Read", {"path": "nope"}), ("LS", {"path": "nope"}), ("Edit", {"path": "nope", "old_string": "a", "new_string": "b"})):
            with self.subTest(tool=name):
                with self.assertRaises(ToolInputError):
                    registry.require(name).handler(payload, ctx)


class SignatureTests(unittest.TestCase):
    def test_a_reversed_handler_signature_is_refused_at_registration(self):
        with self.assertRaises(TypeError) as caught:
            ToolSpec(name="Swapped", description="", input_schema={}, handler=lambda ctx, payload: None, kind="read")
        self.assertIn("(payload, ctx)", str(caught.exception))

    def test_a_handler_that_cannot_take_the_context_is_refused(self):
        with self.assertRaises(TypeError):
            ToolSpec(name="TooFew", description="", input_schema={}, handler=lambda payload: None, kind="read")

    def test_positional_only_and_varargs_shapes_are_accepted(self):
        def positional(payload, ctx, /):  # noqa: ANN001
            return ToolResult.ok("fine")

        def starred(payload, ctx, *rest):  # noqa: ANN001
            return ToolResult.ok("fine")

        for handler in (positional, starred):
            ToolSpec(name=handler.__name__, description="", input_schema={}, handler=handler, kind="read")

    def test_every_built_in_handler_uses_the_same_two_argument_shape(self):
        for spec in build_default_registry().specs():
            with self.subTest(tool=spec.name):
                import inspect

                parameters = [
                    parameter
                    for parameter in inspect.signature(spec.handler).parameters.values()
                    if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
                ]
                self.assertGreaterEqual(len(parameters), 2)
                self.assertEqual(parameters[0].name, "payload")
                self.assertEqual(parameters[1].name, "ctx")

    def test_non_callables_and_non_specs_are_refused(self):
        registry = ToolRegistry()
        with self.assertRaises(TypeError):
            registry.register("Read")
        with self.assertRaises(TypeError):
            ToolSpec(name="Bad", description="", input_schema={}, handler="not callable")

    def test_limits_must_be_positive(self):
        with self.assertRaises(ValueError):
            ToolLimits(max_read_bytes=0)
        with self.assertRaises(ValueError):
            ToolLimits(max_grep_matches=-1)


class RegistryTests(unittest.TestCase):
    def test_duplicate_registration_needs_an_explicit_override(self):
        registry = build_default_registry()
        spec = registry.require("Read")
        with self.assertRaises(ValueError):
            registry.register(spec)
        registry.register(spec, replace_existing=True)

    def test_subset_and_missing_support_subagent_tool_sets(self):
        registry = build_default_registry()
        subset = registry.subset(["Read", "Grep", "Ghost"])
        self.assertEqual(subset.names(), ("Grep", "Read"))
        self.assertEqual(registry.missing(["Read", "Ghost"]), ("Ghost",))
        with self.assertRaises(KeyError):
            registry.subset(["Ghost"], missing_ok=False)

    def test_api_payload_and_kind_map(self):
        registry = build_default_registry()
        api = registry.to_api()
        self.assertEqual(len(api), len(registry))
        self.assertEqual(api[0]["input_schema"]["type"], "object")
        self.assertEqual(registry.kinds()["Write"], "edit")
        self.assertEqual(registry.kinds()["Read"], "read")

    def test_tool_spec_derives_mutating_from_its_kind(self):
        for kind, expected in (("read", False), ("edit", True), ("exec", True), ("task", False), ("other", True)):
            with self.subTest(kind=kind):
                spec = ToolSpec(name=f"T{kind}", description="", input_schema={}, handler=lambda payload, ctx: None, kind=kind)
                self.assertEqual(spec.is_mutating, expected)

    def test_decorator_registration_reads_the_docstring(self):
        registry = ToolRegistry()

        @registry.tool("CountLines", kind="read", input_schema={"type": "object", "properties": {}})
        def count_lines(payload: dict, ctx: ToolContext) -> ToolResult:
            """Count the lines of a workspace file."""
            return ToolResult.ok("42")

        self.assertEqual(count_lines.description, "Count the lines of a workspace file.")
        self.assertFalse(count_lines.is_mutating)
        self.assertEqual(registry.require("CountLines").handler({}, ctx=None).text(), "42")  # type: ignore[arg-type]

    def test_result_blocks_are_capped_for_the_transcript(self):
        result = ToolResult(content="z" * 1000)
        block = result.as_block("call-1", max_chars=100)
        self.assertIn("truncated 900 chars", block.text())
        self.assertEqual(block.tool_use_id, "call-1")
        self.assertFalse(block.is_error)

    def test_error_results_are_flagged_for_the_api(self):
        block = ToolResult.error("nope").as_block("call-2")
        self.assertTrue(block.is_error)
        api = block.to_api()
        self.assertEqual(api["type"], "tool_result")
        self.assertTrue(api["is_error"])


class SidecarToolShapeTests(unittest.TestCase):
    def test_codex_tool_is_read_only_and_named_for_the_sidecar(self):
        spec = codex_tool_spec()
        self.assertEqual(spec.name, "CodexReadOnly")
        self.assertFalse(spec.is_mutating)
        self.assertEqual(spec.kind, "read")
        self.assertIn("read-only", spec.description)
        self.assertEqual(spec.input_schema["required"], ["prompt"])

    def test_codex_tool_without_a_client_reports_instead_of_hanging(self):
        spec = codex_tool_spec()
        ctx = ToolContext(sandbox=None, services={})
        result = spec.handler({"prompt": "hello"}, ctx)
        self.assertTrue(result.is_error)
        self.assertIn("no sidecar client", result.text())


if __name__ == "__main__":
    unittest.main()
