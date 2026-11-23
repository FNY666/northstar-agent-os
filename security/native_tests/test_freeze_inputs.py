"""Tests for the local-only, fail-closed input freezer.

Every adversarial input in this module is created inside ``TemporaryDirectory``;
no test targets a remote service, runs a candidate project, or reads credentials.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from freeze_inputs import freeze_inputs, validate_requirements  # noqa: E402
from native_contract import EvidenceError, sha, wire  # noqa: E402


class FreezeInputsCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="freeze-inputs-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "src").mkdir()
        (self.source / "src" / "app.py").write_bytes(b"print('fixture only')\n")
        (self.source / "requirements.txt").write_bytes(b"# local fixture\nExample_Pkg==1.2.3\nother-pkg==2!4.0+local\n")

    def assert_rejected_without_output(self, paths: list[str], *, name: str) -> None:
        output = self.root / name
        with self.assertRaises(EvidenceError):
            freeze_inputs(self.source, output, paths)
        self.assertFalse(output.exists(), "a rejected freeze must not publish a partial directory")

    def test_freezes_explicit_nested_files_and_canonical_manifest(self) -> None:
        output = self.root / "frozen"
        result = freeze_inputs(self.source, output, ["requirements.txt", "src/app.py"])

        requirements = (self.source / "requirements.txt").read_bytes()
        expected_files = [
            {"path": "requirements.txt", "sha256": sha(requirements), "bytes": len(requirements)},
            {"path": "src/app.py", "sha256": sha(b"print('fixture only')\n"), "bytes": 22},
        ]
        self.assertEqual(expected_files, result["files"])
        self.assertEqual(sha(wire({"files": expected_files})), result["manifest_sha256"])
        self.assertEqual(str(output), result["output_dir"])
        self.assertEqual(
            {"requirements.txt": requirements, "src/app.py": b"print('fixture only')\n"},
            result["input_bytes"],
        )
        self.assertEqual(result["input_bytes"]["src/app.py"], (output / "src" / "app.py").read_bytes())
        self.assertEqual(result["input_bytes"]["requirements.txt"], (output / "requirements.txt").read_bytes())
        self.assertEqual(0, stat.S_IMODE((output / "src" / "app.py").stat().st_mode) & 0o222)
        self.assertEqual(0, stat.S_IMODE((output / "src").stat().st_mode) & 0o222)

    def test_rejects_dotdot_absolute_credential_and_symlink_paths(self) -> None:
        (self.source / ".env").write_bytes(b"fixture-not-a-real-secret\n")
        (self.source / "link.py").symlink_to(self.source / "src" / "app.py")
        self.assert_rejected_without_output(["src/../src/app.py"], name="reject-dotdot")
        self.assert_rejected_without_output([str(self.source / "src" / "app.py")], name="reject-absolute")
        self.assert_rejected_without_output(["src//app.py"], name="reject-empty-component")
        self.assert_rejected_without_output([".env"], name="reject-credential")
        self.assert_rejected_without_output(["link.py"], name="reject-link")

    def test_rejects_hardlinks_and_special_files_without_blocking(self) -> None:
        os.link(self.source / "src" / "app.py", self.source / "hardlinked.py")
        os.mkfifo(self.source / "fixture.fifo")
        self.assert_rejected_without_output(["hardlinked.py"], name="reject-hardlink")
        self.assert_rejected_without_output(["fixture.fifo"], name="reject-special")

    def test_requirements_allow_only_exact_ordinary_pins(self) -> None:
        allowed = b"# comment\nAlpha_pkg==1.0\nother-pkg==2!4.0+local\n\n"
        self.assertEqual(
            [{"name": "Alpha_pkg", "version": "1.0"}, {"name": "other-pkg", "version": "2!4.0+local"}],
            validate_requirements(allowed),
        )
        for invalid in (
            b"package[extra]==1.0\n",
            b"package>=1.0\n",
            b"package==1.0; python_version<'3.12'\n",
            b"package @ https://fixture.invalid/pkg.whl\n",
            b"-r included.txt\n",
            b"--constraint constraints.txt\n",
            b"package==1.0 # inline comment\n",
            b"one==1\nOne==2\n",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(EvidenceError):
                    validate_requirements(invalid)

    def test_invalid_requirements_fails_before_publication(self) -> None:
        (self.source / "requirements.txt").write_bytes(b"fixture-package>=1.0\n")
        self.assert_rejected_without_output(["requirements.txt", "src/app.py"], name="reject-requirements")
        (self.source / "requirements").mkdir()
        (self.source / "requirements" / "base.txt").write_bytes(b"fixture-package>=1.0\n")
        self.assert_rejected_without_output(["requirements/base.txt"], name="reject-requirements-directory")

    def test_existing_output_is_never_replaced(self) -> None:
        output = self.root / "already-published"
        output.mkdir()
        sentinel = output / "sentinel.txt"
        sentinel.write_bytes(b"preserve-me")
        with self.assertRaises(EvidenceError):
            freeze_inputs(self.source, output, ["src/app.py"])
        self.assertEqual(b"preserve-me", sentinel.read_bytes())
        self.assertFalse((output / "src").exists())

    def test_only_caller_named_files_are_copied_and_project_code_is_not_run(self) -> None:
        marker = self.root / "must-not-exist"
        (self.source / "candidate.py").write_text(
            "from pathlib import Path\nPath(%r).write_text('executed')\n" % str(marker),
            encoding="utf-8",
        )
        output = self.root / "narrow-view"
        result = freeze_inputs(self.source, output, ["src/app.py"])
        self.assertEqual(["src/app.py"], [item["path"] for item in result["files"]])
        self.assertFalse((output / "candidate.py").exists())
        self.assertFalse(marker.exists(), "freezing must copy bytes, not execute candidate code")


if __name__ == "__main__":
    unittest.main()
