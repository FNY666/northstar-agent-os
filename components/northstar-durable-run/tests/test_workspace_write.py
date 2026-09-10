import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from workspace_write import WorkspaceWriteResult, WorkspaceWriteTool  # noqa: E402


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class WorkspaceWriteToolTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "workspace"
        self.root.mkdir(mode=0o700)
        self.tool = WorkspaceWriteTool(self.root)

    def tearDown(self):
        self.tempdir.cleanup()

    def _entries(self, relative="."):
        return sorted(os.listdir(self.root / relative))

    def test_writes_file_with_digest_and_metadata(self):
        result = self.tool({"path": "out.txt", "content": "hello\n"})
        self.assertIsInstance(result, WorkspaceWriteResult)
        self.assertEqual(result.path, "out.txt")
        self.assertEqual((self.root / "out.txt").read_text(encoding="utf-8"), "hello\n")
        self.assertEqual(result.size_bytes, 6)
        self.assertEqual(result.digest, digest("hello\n"))
        self.assertTrue(result.created)
        self.assertIsNone(result.previous_digest)

    def test_creates_parent_directories_inside_the_root(self):
        self.tool({"path": "a/b/c.txt", "content": "nested\n"})
        self.assertEqual((self.root / "a" / "b" / "c.txt").read_text(encoding="utf-8"), "nested\n")
        self.assertTrue(stat.S_ISDIR((self.root / "a").stat().st_mode))

    def test_written_file_is_not_group_or_world_readable(self):
        self.tool({"path": "secret.txt", "content": "private\n"})
        mode = stat.S_IMODE((self.root / "secret.txt").stat().st_mode)
        self.assertEqual(mode & 0o077, 0)

    def test_overwrite_reports_previous_and_new_digest(self):
        self.tool({"path": "out.txt", "content": "one"})
        result = self.tool({"path": "out.txt", "content": "two"})
        self.assertFalse(result.created)
        self.assertEqual(result.previous_digest, digest("one"))
        self.assertEqual(result.digest, digest("two"))
        self.assertEqual((self.root / "out.txt").read_text(encoding="utf-8"), "two")

    def test_rejects_absolute_traversal_and_malformed_paths(self):
        for path in ("../outside.txt", "/etc/passwd", "a/../../b", "", "a\\b", "a\x00b", "a//b"):
            with self.assertRaises(ValueError):
                self.tool({"path": path, "content": "x"})
        self.assertEqual(self._entries(), [])

    def test_rejects_malformed_payloads(self):
        for payload in (
            {"path": "a.txt", "content": "x", "extra": True},
            {"path": "a.txt"},
            {"content": "x"},
            {"path": "a.txt", "content": 5},
            {"path": 5, "content": "x"},
            "a.txt",
            None,
        ):
            with self.assertRaises(ValueError):
                self.tool(payload)
        self.assertEqual(self._entries(), [])

    def test_rejects_content_over_the_byte_bound(self):
        (self.root / "keep.txt").write_text("original", encoding="utf-8")
        tool = WorkspaceWriteTool(self.root, max_bytes=4)
        with self.assertRaises(ValueError):
            tool({"path": "keep.txt", "content": "toolong"})
        self.assertEqual((self.root / "keep.txt").read_text(encoding="utf-8"), "original")

    def test_rejects_symlinked_target_without_replacing_or_following_it(self):
        outside = Path(self.tempdir.name) / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            self.tool({"path": "link.txt", "content": "clobber"})
        self.assertEqual(outside.read_text(encoding="utf-8"), "secret")
        self.assertTrue(link.is_symlink())

    def test_rejects_symlinked_intermediate_directory(self):
        outside = Path(self.tempdir.name) / "outside-dir"
        outside.mkdir()
        try:
            (self.root / "linkdir").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            self.tool({"path": "linkdir/escape.txt", "content": "x"})
        self.assertEqual(sorted(os.listdir(outside)), [])

    def test_rejects_directory_target(self):
        (self.root / "dir").mkdir()
        with self.assertRaises(ValueError):
            self.tool({"path": "dir", "content": "x"})

    def test_allowed_paths_allowlist_blocks_other_targets(self):
        tool = WorkspaceWriteTool(self.root, allowed_paths=["reports/out.txt"])
        tool({"path": "reports/out.txt", "content": "ok"})
        with self.assertRaises(ValueError):
            tool({"path": "reports/other.txt", "content": "no"})
        self.assertEqual(self._entries("reports"), ["out.txt"])

    def test_no_temporary_file_survives_a_write(self):
        self.tool({"path": "a/b.txt", "content": "x"})
        self.assertEqual(self._entries("a"), ["b.txt"])

    def test_host_root_may_contain_symlink_prefix_and_is_resolved_once(self):
        alias = Path(self.tempdir.name) / "alias"
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        WorkspaceWriteTool(alias)({"path": "via-alias.txt", "content": "ok\n"})
        self.assertEqual((self.root / "via-alias.txt").read_text(encoding="utf-8"), "ok\n")

    def test_unicode_content_round_trips_with_utf8_digest(self):
        result = self.tool({"path": "cn.txt", "content": "北辰\n"})
        self.assertEqual(result.digest, digest("北辰\n"))
        self.assertEqual(result.size_bytes, len("北辰\n".encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
