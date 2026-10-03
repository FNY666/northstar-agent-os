"""PATH-shim detection and binary-pin integrity (trustmebro red-team model).

Pure unit tests: temp directories, explicit ``PATH`` strings, no
process-environment mutation, no network, no model.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

import support  # noqa: F401

from tools.path_integrity import (
    BinaryPin,
    digest_bytes,
    digest_output,
    pin_binary,
    scan_path_shadows,
    verify_output_receipt,
    verify_pin,
)


class PathIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.dirs: list[str] = []
        self.real_dir = self._tool_dir(b"real binary bytes v1")
        self.shim_dir = self._tool_dir(b"fabricated shim bytes")

    def tearDown(self):
        for directory in self.dirs:
            shutil.rmtree(directory, ignore_errors=True)

    def _tool_dir(self, content: bytes, name: str = "nstool") -> str:
        directory = tempfile.mkdtemp(prefix="ns-pin-test-")
        self.dirs.append(directory)
        script = os.path.join(directory, name)
        with open(script, "wb") as handle:
            handle.write(content)
        os.chmod(script, 0o755)
        return directory

    # -- digest helpers ----------------------------------------------------
    def test_digest_bytes_format(self):
        digest = digest_bytes(b"abc")
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 64)

    def test_digest_output_is_canonical(self):
        first = digest_output({"b": 1, "a": [1, 2]})
        second = digest_output({"a": [1, 2], "b": 1})
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))

    # -- pin / verify ------------------------------------------------------
    def test_pin_and_verify_roundtrip(self):
        pin = pin_binary("nstool", path=self.real_dir)
        self.assertIsInstance(pin, BinaryPin)
        self.assertEqual(pin.name, "nstool")
        ok, reason = verify_pin(pin, path=self.real_dir)
        self.assertTrue(ok, reason)

    def test_pin_resolves_symlinks(self):
        link_dir = tempfile.mkdtemp(prefix="ns-pin-link-")
        self.dirs.append(link_dir)
        os.symlink(
            os.path.join(self.real_dir, "nstool"),
            os.path.join(link_dir, "nstool"),
        )
        pin = pin_binary("nstool", path=link_dir)
        # realpath at pin time: the symlink target, not the link.
        self.assertEqual(
            pin.path, os.path.realpath(os.path.join(self.real_dir, "nstool"))
        )

    def test_pin_missing_binary_raises(self):
        with self.assertRaises(ValueError):
            pin_binary("no-such-tool-xyz", path=self.real_dir)

    def test_pin_rejects_bad_names(self):
        with self.assertRaises(ValueError):
            pin_binary("../evil", path=self.real_dir)
        with self.assertRaises(ValueError):
            pin_binary("a/b", path=self.real_dir)

    def test_verify_fails_when_shim_shadows_after_pinning(self):
        # The trustmebro install-mode attack: shim dir prepended to PATH
        # *after* the pin was taken at registration time.
        pin = pin_binary("nstool", path=self.real_dir)
        ok, reason = verify_pin(
            pin, path=self.shim_dir + os.pathsep + self.real_dir
        )
        self.assertFalse(ok)
        self.assertIn("nstool", reason)

    def test_verify_fails_when_binary_bytes_change_in_place(self):
        pin = pin_binary("nstool", path=self.real_dir)
        with open(os.path.join(self.real_dir, "nstool"), "wb") as handle:
            handle.write(b"replaced bytes, same path")
        os.chmod(os.path.join(self.real_dir, "nstool"), 0o755)
        ok, reason = verify_pin(pin, path=self.real_dir)
        self.assertFalse(ok)
        self.assertIn("digest", reason)

    def test_verify_fails_when_binary_vanishes(self):
        pin = pin_binary("nstool", path=self.real_dir)
        os.remove(os.path.join(self.real_dir, "nstool"))
        ok, _reason = verify_pin(pin, path=self.real_dir)
        self.assertFalse(ok)

    def test_verify_rejects_non_pin(self):
        ok, _reason = verify_pin("not-a-pin", path=self.real_dir)  # type: ignore[arg-type]
        self.assertFalse(ok)

    # -- shadow scan -------------------------------------------------------
    def test_scan_flags_shadowed_name(self):
        shadows = scan_path_shadows(
            ["nstool"],
            path=self.shim_dir + os.pathsep + self.real_dir,
            trusted_path=self.real_dir,
        )
        self.assertEqual(len(shadows), 1)
        self.assertEqual(shadows[0]["name"], "nstool")
        self.assertNotEqual(
            shadows[0]["path_resolution"], shadows[0]["trusted_resolution"]
        )

    def test_scan_passes_clean_path(self):
        shadows = scan_path_shadows(
            ["nstool"],
            path=self.real_dir,
            trusted_path=self.real_dir,
        )
        self.assertEqual(shadows, [])

    def test_scan_skips_unresolvable_names(self):
        shadows = scan_path_shadows(
            ["no-such-tool-xyz"],
            path=self.shim_dir + os.pathsep + self.real_dir,
            trusted_path=self.real_dir,
        )
        self.assertEqual(shadows, [])

    # -- output receipt ----------------------------------------------------
    def test_output_receipt_roundtrip(self):
        output = {"text": "real answer", "exit": 0}
        receipt = digest_output(output)
        ok, _reason = verify_output_receipt(output, receipt)
        self.assertTrue(ok)

    def test_output_receipt_detects_forgery(self):
        receipt = digest_output({"text": "real answer", "exit": 0})
        ok, reason = verify_output_receipt(
            {"text": "fabricated answer", "exit": 0}, receipt
        )
        self.assertFalse(ok)
        self.assertIn("forged", reason)

    def test_output_receipt_detects_type_confusion(self):
        receipt = digest_output({"text": "real answer"})
        ok, _reason = verify_output_receipt(["not", "a", "dict"], receipt)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
