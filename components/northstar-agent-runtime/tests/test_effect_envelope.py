"""Tests for the Effect Envelope (unified path containment)."""

import os
import tempfile
import unittest
from pathlib import Path

from tools.effect_envelope import EffectEnvelopeError, contain


class EffectEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "sub").mkdir()
        (self.root / "sub" / "file.txt").write_text("x")

    def tearDown(self):
        self.tmp.cleanup()

    def test_allows_inside(self):
        p = contain("sub/file.txt", self.root)
        self.assertEqual(p, Path(os.path.realpath(self.root / "sub" / "file.txt")))

    def test_rejects_null_byte(self):
        with self.assertRaises(EffectEnvelopeError):
            contain("sub/fi\x00le.txt", self.root)

    def test_rejects_dotdot(self):
        with self.assertRaises(EffectEnvelopeError):
            contain("../outside.txt", self.root)
        with self.assertRaises(EffectEnvelopeError):
            contain("sub/../../outside.txt", self.root)

    def test_rejects_absolute_by_default(self):
        with self.assertRaises(EffectEnvelopeError):
            contain("/etc/passwd", self.root)

    def test_absolute_allowed_inside(self):
        inside = str(self.root / "sub" / "file.txt")
        p = contain(inside, self.root, allow_absolute=True)
        self.assertTrue(str(p).startswith(os.path.realpath(str(self.root))))

    def test_absolute_outside_rejected(self):
        with self.assertRaises(EffectEnvelopeError):
            contain("/etc/passwd", self.root, allow_absolute=True)

    def test_rejects_symlink_escape(self):
        # Symlink inside the workspace pointing outside.
        outside = tempfile.TemporaryDirectory()
        try:
            (self.root / "link").symlink_to(outside.name)
            with self.assertRaises(EffectEnvelopeError):
                contain("link/secret.txt", self.root)
        finally:
            outside.cleanup()

    def test_reject_symlinks_option(self):
        (self.root / "real.txt").write_text("x")
        (self.root / "slink").symlink_to(self.root / "real.txt")
        # By default, a symlink to an inside target is allowed (resolves inside).
        p = contain("slink", self.root)
        self.assertTrue(p.is_file())
        # With reject_symlinks, any symlink is refused.
        with self.assertRaises(EffectEnvelopeError):
            contain("slink", self.root, reject_symlinks=True)

    def test_rejects_empty(self):
        with self.assertRaises(EffectEnvelopeError):
            contain("   ", self.root)

    def test_rejects_non_string(self):
        with self.assertRaises(EffectEnvelopeError):
            contain(None, self.root)  # type: ignore[arg-type]

    def test_root_with_symlink_component(self):
        # If the workspace root itself goes through a symlink, containment
        # is still computed on the real path.
        linkroot = Path(self.tmp.name + "_link")
        try:
            linkroot.symlink_to(self.root)
            p = contain("sub/file.txt", linkroot)
            self.assertTrue(str(p).startswith(os.path.realpath(str(self.root))))
            with self.assertRaises(EffectEnvelopeError):
                contain("../outside.txt", linkroot)
        finally:
            if linkroot.is_symlink():
                linkroot.unlink()


if __name__ == "__main__":
    unittest.main()
