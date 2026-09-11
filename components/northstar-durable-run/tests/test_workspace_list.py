import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from action_gateway import ToolExecutionFailed, ToolRefused  # noqa: E402
from workspace_list import WorkspaceListResult, WorkspaceListTool  # noqa: E402


class WorkspaceListToolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "workspace"
        self.root.mkdir(mode=0o700)
        (self.root / "README.md").write_text("private content\n", encoding="utf-8")
        (self.root / "data").mkdir()
        (self.root / "data" / "records.csv").write_text("name,score\na,1\n", encoding="utf-8")
        (self.root / "data" / "nested").mkdir()
        (self.root / "data" / "nested" / "notes.txt").write_text("nested\n", encoding="utf-8")
        self.tool = WorkspaceListTool(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def call(self, prefix="", max_depth=2, max_entries=16):
        return self.tool(
            {"prefix": prefix, "max_depth": max_depth, "max_entries": max_entries}
        )

    def test_root_listing_returns_only_sorted_metadata(self):
        result = self.call(max_depth=1)
        self.assertIsInstance(result, WorkspaceListResult)
        self.assertEqual(result.prefix, "")
        self.assertFalse(result.truncated)
        self.assertEqual(
            result.entries,
            (
                {"path": "README.md", "kind": "file", "size_bytes": 16},
                {"path": "data", "kind": "directory", "size_bytes": None},
            ),
        )
        output = result.as_output()
        self.assertEqual(set(output), {"prefix", "entries", "truncated"})
        self.assertNotIn("private content", str(output))

    def test_depth_controls_recursive_entries(self):
        shallow = self.call(max_depth=1)
        deep = self.call(max_depth=3)
        self.assertNotIn("data/records.csv", [item["path"] for item in shallow.entries])
        self.assertEqual(
            [item["path"] for item in deep.entries],
            ["README.md", "data", "data/nested", "data/nested/notes.txt", "data/records.csv"],
        )

    def test_prefix_lists_only_the_requested_subtree(self):
        result = self.call(prefix="data", max_depth=2)
        self.assertEqual(result.prefix, "data")
        self.assertEqual(
            [item["path"] for item in result.entries],
            ["data/nested", "data/nested/notes.txt", "data/records.csv"],
        )

    def test_entry_bound_reports_truncation_without_leaking_more(self):
        result = self.call(max_depth=3, max_entries=2)
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual([item["path"] for item in result.entries], ["README.md", "data"])

    def test_exact_payload_and_bounds_are_required(self):
        invalid = (
            {"prefix": "", "max_depth": 1},
            {"prefix": "", "max_depth": 1, "max_entries": 2, "extra": True},
            {"prefix": "", "max_depth": 0, "max_entries": 2},
            {"prefix": "", "max_depth": 9, "max_entries": 2},
            {"prefix": "", "max_depth": 1, "max_entries": 0},
            {"prefix": "", "max_depth": 1, "max_entries": 513},
            {"prefix": "", "max_depth": True, "max_entries": 2},
            "data",
        )
        for payload in invalid:
            with self.assertRaises(ToolRefused):
                self.tool(payload)

    def test_rejects_absolute_traversal_and_malformed_prefixes(self):
        for prefix in ("/etc", "../outside", "data/../README.md", "data//nested", "data\\nested", "data\x00nested"):
            with self.assertRaises(ToolRefused):
                self.call(prefix=prefix)

    def test_rejects_missing_or_non_directory_prefix(self):
        with self.assertRaises(ToolExecutionFailed):
            self.call(prefix="missing")
        with self.assertRaises(ToolRefused):
            self.call(prefix="README.md")

    def test_does_not_follow_or_return_symlinks(self):
        outside = Path(self.tempdir.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("secret\n", encoding="utf-8")
        try:
            (self.root / "linkdir").symlink_to(outside, target_is_directory=True)
            (self.root / "link.txt").symlink_to(outside / "secret.txt")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        paths = [item["path"] for item in self.call(max_depth=3).entries]
        self.assertNotIn("linkdir", paths)
        self.assertNotIn("linkdir/secret.txt", paths)
        self.assertNotIn("link.txt", paths)
        with self.assertRaises(ToolRefused):
            self.call(prefix="linkdir")

    def test_allowlist_accepts_only_the_authorized_subtree(self):
        tool = WorkspaceListTool(self.root, allowed_prefixes=["data"])
        result = tool({"prefix": "data", "max_depth": 1, "max_entries": 8})
        self.assertEqual([item["path"] for item in result.entries], ["data/nested", "data/records.csv"])
        with self.assertRaises(ToolRefused):
            tool({"prefix": "", "max_depth": 1, "max_entries": 8})
        with self.assertRaises(ToolRefused):
            tool({"prefix": "README.md", "max_depth": 1, "max_entries": 8})

    def test_root_alias_is_resolved_once_but_nested_symlink_is_refused(self):
        alias = Path(self.tempdir.name) / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        alias_tool = WorkspaceListTool(alias)
        result = alias_tool({"prefix": "data", "max_depth": 1, "max_entries": 8})
        self.assertEqual([item["path"] for item in result.entries], ["data/nested", "data/records.csv"])


if __name__ == "__main__":
    unittest.main()
