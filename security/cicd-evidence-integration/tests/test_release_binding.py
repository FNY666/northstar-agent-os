"""验证 verify_release_files 的 fail-closed 发布绑定合同。"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

_TOOL_DIRECTORY = Path(__file__).resolve().parents[1]
if str(_TOOL_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIRECTORY))
import verify_release_files as verifier  # noqa: E402


RUN_ID = "release.20261017-01"
SOURCE_COMMIT = "a" * 40
WHEEL_NAME = "northstar_example-1.0.0-py3-none-any.whl"
WHEEL_BYTES = b"not-a-real-wheel; fixture bytes only\n"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


class ReleaseBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.dist = self.root / "dist"
        self.binding_path = self.root / "release-binding.json"
        self.gate_path = self.root / "security-gate.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _make_pair(
        self,
        *,
        binding_patch: dict[str, Any] | None = None,
        gate_patch: dict[str, Any] | None = None,
    ) -> dict[str, str | Path]:
        self.dist.mkdir()
        (self.dist / WHEEL_NAME).write_bytes(WHEEL_BYTES)
        gate: dict[str, Any] = {
            "schema": "northstar.security-gate.v1",
            "run_id": RUN_ID,
            "decision": "pass",
            "exit_code": 0,
            "eligible_for_delivery": True,
            "evidence_valid": True,
        }
        if gate_patch:
            gate.update(gate_patch)
        gate_raw = _json_bytes(gate)
        self.gate_path.write_bytes(gate_raw)

        binding: dict[str, Any] = {
            "schema": "northstar.release-binding.v1",
            "run_id": RUN_ID,
            "source_commit": SOURCE_COMMIT,
            "security_gate_sha256": _sha256(gate_raw),
            "files": [
                {
                    "name": WHEEL_NAME,
                    "sha256": _sha256(WHEEL_BYTES),
                    "bytes": len(WHEEL_BYTES),
                }
            ],
        }
        if binding_patch:
            binding.update(binding_patch)
        binding_raw = _json_bytes(binding)
        self.binding_path.write_bytes(binding_raw)
        return {
            "dist_dir": self.dist,
            "binding": self.binding_path,
            "gate": self.gate_path,
            "expected_binding_sha256": _sha256(binding_raw),
            "expected_source_commit": SOURCE_COMMIT,
            "expected_run_id": RUN_ID,
            "expected_gate_sha256": _sha256(gate_raw),
        }

    def _verify(self, pair: dict[str, str | Path], **expected_patch: str) -> dict[str, Any]:
        expected = {
            "expected_binding_sha256": str(pair["expected_binding_sha256"]),
            "expected_source_commit": str(pair["expected_source_commit"]),
            "expected_run_id": str(pair["expected_run_id"]),
            "expected_gate_sha256": str(pair["expected_gate_sha256"]),
        }
        expected.update(expected_patch)
        return verifier.verify_release_files(
            pair["dist_dir"],
            pair["binding"],
            pair["gate"],
            **expected,
        )

    def assertRejected(self, answer: dict[str, Any], code: str) -> None:
        self.assertFalse(answer["eligible_for_publish"])
        self.assertEqual(2, answer["exit_code"])
        self.assertIn(code, answer["reason_codes"])

    def test_matching_pins_gate_and_wheel_are_eligible(self) -> None:
        answer = self._verify(self._make_pair())
        self.assertTrue(answer["eligible_for_publish"])
        self.assertEqual(0, answer["exit_code"])
        self.assertEqual([], answer["reason_codes"])
        self.assertEqual("northstar.release-files-gate.v1", answer["schema"])

    def test_replaced_artifact_is_rejected(self) -> None:
        pair = self._make_pair()
        (self.dist / WHEEL_NAME).write_bytes(b"substituted wheel bytes")
        self.assertRejected(self._verify(pair), "ARTIFACT_INTEGRITY_MISMATCH")

    def test_extra_artifact_is_rejected(self) -> None:
        pair = self._make_pair()
        (self.dist / "unexpected-1.0.0.whl").write_bytes(b"extra")
        self.assertRejected(self._verify(pair), "ARTIFACT_SET_MISMATCH")

    def test_missing_artifact_is_rejected(self) -> None:
        pair = self._make_pair()
        (self.dist / WHEEL_NAME).unlink()
        self.assertRejected(self._verify(pair), "ARTIFACT_SET_MISMATCH")

    def test_manifest_mutation_without_external_pin_update_is_rejected(self) -> None:
        pair = self._make_pair()
        self.binding_path.write_bytes(self.binding_path.read_bytes() + b" \n")
        self.assertRejected(self._verify(pair), "BINDING_PIN_MISMATCH")

    def test_gate_mutation_without_external_pin_update_is_rejected(self) -> None:
        pair = self._make_pair()
        self.gate_path.write_bytes(self.gate_path.read_bytes() + b" \n")
        answer = self._verify(pair)
        self.assertRejected(answer, "GATE_TRUSTED_SHA256_MISMATCH")
        self.assertIn("GATE_BINDING_SHA256_MISMATCH", answer["reason_codes"])

    def test_wrong_trusted_source_commit_is_rejected(self) -> None:
        pair = self._make_pair()
        self.assertRejected(self._verify(pair, expected_source_commit="b" * 40), "SOURCE_COMMIT_MISMATCH")

    def test_wrong_trusted_run_id_is_rejected(self) -> None:
        pair = self._make_pair()
        self.assertRejected(self._verify(pair, expected_run_id="different-run"), "RUN_ID_MISMATCH")

    def test_wrong_trusted_gate_hash_is_rejected(self) -> None:
        pair = self._make_pair()
        self.assertRejected(self._verify(pair, expected_gate_sha256="f" * 64), "BINDING_GATE_SHA256_MISMATCH")

    def test_boolean_file_bytes_is_not_an_integer(self) -> None:
        pair = self._make_pair(
            binding_patch={
                "files": [{"name": WHEEL_NAME, "sha256": _sha256(WHEEL_BYTES), "bytes": True}]
            }
        )
        self.assertRejected(self._verify(pair), "BINDING_CONTRACT_INVALID")

    def test_float_file_bytes_is_not_an_integer(self) -> None:
        pair = self._make_pair(
            binding_patch={
                "files": [{"name": WHEEL_NAME, "sha256": _sha256(WHEEL_BYTES), "bytes": float(len(WHEEL_BYTES))}]
            }
        )
        self.assertRejected(self._verify(pair), "BINDING_CONTRACT_INVALID")

    def test_unsafe_manifest_filename_is_rejected(self) -> None:
        pair = self._make_pair(
            binding_patch={
                "files": [{"name": "../escape.whl", "sha256": _sha256(WHEEL_BYTES), "bytes": len(WHEEL_BYTES)}]
            }
        )
        self.assertRejected(self._verify(pair), "BINDING_CONTRACT_INVALID")

    def test_duplicate_manifest_filename_is_rejected(self) -> None:
        descriptor = {"name": WHEEL_NAME, "sha256": _sha256(WHEEL_BYTES), "bytes": len(WHEEL_BYTES)}
        pair = self._make_pair(binding_patch={"files": [descriptor, dict(descriptor)]})
        self.assertRejected(self._verify(pair), "BINDING_CONTRACT_INVALID")

    def test_non_pass_gate_is_rejected_even_when_it_is_pinned(self) -> None:
        pair = self._make_pair(gate_patch={"decision": "block", "exit_code": 1, "eligible_for_delivery": False})
        self.assertRejected(self._verify(pair), "GATE_DECISION_NOT_PASS")

    def test_artifact_symlink_is_rejected(self) -> None:
        pair = self._make_pair()
        artifact = self.dist / WHEEL_NAME
        artifact.unlink()
        target = self.root / "elsewhere.whl"
        target.write_bytes(WHEEL_BYTES)
        artifact.symlink_to(target)
        self.assertRejected(self._verify(pair), "ARTIFACT_READ_ERROR")

    def test_artifact_hardlink_is_rejected(self) -> None:
        pair = self._make_pair()
        os.link(self.dist / WHEEL_NAME, self.dist / "other-name.whl")
        self.assertRejected(self._verify(pair), "ARTIFACT_READ_ERROR")

    def test_artifact_fifo_is_rejected(self) -> None:
        pair = self._make_pair()
        artifact = self.dist / WHEEL_NAME
        artifact.unlink()
        os.mkfifo(artifact)
        self.assertRejected(self._verify(pair), "ARTIFACT_READ_ERROR")

    def test_dist_directory_symlink_is_rejected(self) -> None:
        pair = self._make_pair()
        linked_dist = self.root / "dist-link"
        linked_dist.symlink_to(self.dist, target_is_directory=True)
        pair["dist_dir"] = linked_dist
        self.assertRejected(self._verify(pair), "ARTIFACT_DIRECTORY_ERROR")

    def test_binding_top_level_is_closed(self) -> None:
        pair = self._make_pair(binding_patch={"unexpected": "field"})
        self.assertRejected(self._verify(pair), "BINDING_CONTRACT_INVALID")

    def test_verification_does_not_write_the_dist_filetree(self) -> None:
        pair = self._make_pair()

        def snapshot(directory: Path) -> list[tuple[str, int, int, str]]:
            records: list[tuple[str, int, int, str]] = []
            for path in sorted(directory.iterdir(), key=lambda item: item.name):
                information = path.lstat()
                digest = _sha256(path.read_bytes()) if stat.S_ISREG(information.st_mode) else ""
                records.append((path.name, stat.S_IFMT(information.st_mode), information.st_size, digest))
            return records

        before = snapshot(self.dist)
        answer = self._verify(pair)
        after = snapshot(self.dist)
        self.assertTrue(answer["eligible_for_publish"])
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
