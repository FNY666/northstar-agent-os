import os
import unittest

from helpers import make_runtime, make_workspace, tool_results_of
from tools import (
    GREP_LIMIT,
    LIST_LIMIT,
    READ_LIMIT_BYTES,
    ToolContext,
    handle_edit,
    handle_grep,
    handle_list,
    handle_read,
    handle_write,
    resolve_within_workspace,
)


def direct_ctx(workspace):
    return ToolContext(workspace=workspace)


class ContainmentTests(unittest.TestCase):
    """Invariant: paths are resolved (symlinks followed) BEFORE the containment check."""

    def test_read_absolute_path_outside_denied(self):
        runtime, _ = make_runtime(["ok"])
        result = handle_read({"path": "/etc/hostname"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("escapes workspace", result.output)

    def test_read_dotdot_traversal_denied(self):
        runtime, _ = make_runtime(["ok"])
        result = handle_read({"path": "../../etc/passwd"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("escapes workspace", result.output)

    def test_read_via_symlink_pointing_outside_denied(self):
        # The classic pitfall: a symlink inside the workspace that resolves outside.
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "sneaky.txt").symlink_to("/etc/hostname")
        result = handle_read({"path": "sneaky.txt"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("escapes workspace", result.output)

    def test_read_via_symlink_pointing_inside_allowed(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "real.txt").write_text("inner content")
        (runtime.workspace / "alias.txt").symlink_to("real.txt")
        result = handle_read({"path": "alias.txt"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertEqual(result.output, "inner content")

    def test_write_outside_denied(self):
        runtime, _ = make_runtime(["ok"])
        result = handle_write({"path": "/tmp/should-not-exist-nsrt", "content": "x"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("escapes workspace", result.output)

    def test_write_through_symlinked_parent_pointing_outside_denied(self):
        outside_dir = make_workspace()
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "escaped").symlink_to(str(outside_dir))
        result = handle_write({"path": "escaped/evil.txt", "content": "x"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("escapes workspace", result.output)
        self.assertFalse((outside_dir / "evil.txt").exists())

    def test_grep_and_list_outside_denied(self):
        runtime, _ = make_runtime(["ok"])
        self.assertTrue(handle_grep({"pattern": "x", "path": "/etc"}, direct_ctx(runtime.workspace)).is_error)
        self.assertTrue(handle_list({"path": "/etc"}, direct_ctx(runtime.workspace)).is_error)

    def test_resolve_within_workspace_root_itself_is_allowed(self):
        runtime, _ = make_runtime(["ok"])
        self.assertEqual(resolve_within_workspace(runtime.workspace, "."), runtime.workspace)

    def test_resolve_rejects_empty_and_non_string(self):
        runtime, _ = make_runtime(["ok"])
        self.assertIsNone(resolve_within_workspace(runtime.workspace, ""))
        self.assertIsNone(resolve_within_workspace(runtime.workspace, None))


class ReadCapTests(unittest.TestCase):
    def test_read_returns_full_small_file(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "a.txt").write_text("hello world")
        result = handle_read({"path": "a.txt"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertEqual(result.output, "hello world")

    def test_read_truncates_at_256_kb_with_note(self):
        runtime, _ = make_runtime(["ok"])
        big = "z" * (READ_LIMIT_BYTES + 10_000)
        (runtime.workspace / "big.txt").write_text(big)
        result = handle_read({"path": "big.txt"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertEqual(len(result.output.encode("utf-8")), READ_LIMIT_BYTES + len("\n[truncated: first 256 KiB of %d bytes]" % (READ_LIMIT_BYTES + 10_000)))
        self.assertIn("truncated", result.output)

    def test_missing_file_is_a_tool_error_not_exception(self):
        runtime, _ = make_runtime(["ok"])
        result = handle_read({"path": "ghost.txt"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("no such file", result.output)


class GrepCapTests(unittest.TestCase):
    def test_grep_match_format(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "code.txt").write_text("alpha\nbeta matches here\ngamma\n")
        result = handle_grep({"pattern": "matches"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertEqual(result.output, "code.txt:2: beta matches here")

    def test_grep_stops_at_200_matches_with_note(self):
        runtime, _ = make_runtime(["ok"])
        lines = "\n".join(f"hit number {i}" for i in range(300))
        (runtime.workspace / "many.txt").write_text(lines)
        result = handle_grep({"pattern": "hit number"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        count = len([l for l in result.output.splitlines() if l.startswith("many.txt:")])
        self.assertEqual(count, GREP_LIMIT)
        self.assertIn(f"stopped at {GREP_LIMIT} matches", result.output)

    def test_grep_max_matches_override_is_clamped(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "many.txt").write_text("\n".join(f"hit {i}" for i in range(50)))
        result = handle_grep({"pattern": "hit", "max_matches": 5}, direct_ctx(runtime.workspace))
        match_lines = [l for l in result.output.splitlines() if l.startswith("many.txt:")]
        self.assertEqual(len(match_lines), 5)
        result_big = handle_grep({"pattern": "hit", "max_matches": 10_000}, direct_ctx(runtime.workspace))
        match_lines_big = [l for l in result_big.output.splitlines() if l.startswith("many.txt:")]
        self.assertEqual(len(match_lines_big), 50)

    def test_grep_skips_binary_files(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "bin.dat").write_bytes(b"\x00\xffhit\x00")
        (runtime.workspace / "ok.txt").write_text("hit")
        result = handle_grep({"pattern": "hit"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertNotIn("bin.dat", result.output)
        self.assertIn("ok.txt", result.output)


class ListCapTests(unittest.TestCase):
    def test_list_stops_at_500_entries(self):
        runtime, _ = make_runtime(["ok"])
        for i in range(600):
            (runtime.workspace / f"f{i:04d}.txt").write_text("x")
        result = handle_list({}, direct_ctx(runtime.workspace))
        entries = [l for l in result.output.splitlines() if l.startswith("f")]
        self.assertEqual(len(entries), LIST_LIMIT)
        self.assertIn(f"stopped at {LIST_LIMIT} entries", result.output)

    def test_list_does_not_traverse_symlinked_directories(self):
        outside = make_workspace()
        (outside / "secret.txt").write_text("x")
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "link").symlink_to(str(outside))
        (runtime.workspace / "real.txt").write_text("x")
        result = handle_list({}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertNotIn("secret.txt", result.output)
        self.assertIn("real.txt", result.output)


class WriteEditFlowTests(unittest.TestCase):
    def test_write_creates_nested_paths_inside_workspace(self):
        runtime, _ = make_runtime(["ok"])
        result = handle_write({"path": "a/b/c.txt", "content": "nested"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertEqual((runtime.workspace / "a" / "b" / "c.txt").read_text(), "nested")

    def test_write_to_directory_fails(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "d").mkdir()
        result = handle_write({"path": "d", "content": "x"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)

    def test_edit_replaces_unique_string(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "f.txt").write_text("one two three")
        result = handle_edit({"path": "f.txt", "old_string": "two", "new_string": "TWO"}, direct_ctx(runtime.workspace))
        self.assertFalse(result.is_error)
        self.assertEqual((runtime.workspace / "f.txt").read_text(), "one TWO three")

    def test_edit_not_found_and_ambiguous_are_errors(self):
        runtime, _ = make_runtime(["ok"])
        (runtime.workspace / "f.txt").write_text("x x")
        self.assertTrue(handle_edit({"path": "f.txt", "old_string": "nope", "new_string": "y"}, direct_ctx(runtime.workspace)).is_error)
        result = handle_edit({"path": "f.txt", "old_string": "x", "new_string": "y"}, direct_ctx(runtime.workspace))
        self.assertTrue(result.is_error)
        self.assertIn("2", result.output)


class UnifiedSignatureTests(unittest.TestCase):
    def test_every_builtin_handler_takes_payload_then_ctx(self):
        import inspect

        import tools as tools_module

        for handler in (tools_module.handle_read, tools_module.handle_grep, tools_module.handle_list,
                        tools_module.handle_write, tools_module.handle_edit, tools_module.handle_task,
                        tools_module.handle_codex):
            params = list(inspect.signature(handler).parameters)
            self.assertEqual(params, ["payload", "ctx"], f"{handler.__name__} must be (payload, ctx)")


if __name__ == "__main__":
    unittest.main()
