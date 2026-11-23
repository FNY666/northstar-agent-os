"""Regression tests for release sealing and read-only consumption.

All signing keys here are freshly generated in memory fixtures.  They are not
production credentials and are never written or archived.
"""
from __future__ import annotations

import copy
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from consume_release import consume_release
from seal_release import seal_release
from trusted_common import EvidenceError, sha, strict_json_loads, wire
from tests.sealing_fixtures import build_scenario, make_writable, snapshot


class SealingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.scenario = build_scenario(self.root / "fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seal(self, output: str = "sealed", *, now=None) -> Path:
        target = self.root / output
        answer = seal_release(
            self.scenario.produced_dir,
            self.scenario.build_capture_path,
            self.scenario.dist_dir,
            target,
            self.scenario.trust,
            self.scenario.identity,
            self.scenario.keys["seal"],
            now=self.scenario.now if now is None else now,
        )
        self.assertEqual(0, answer["exit_code"])
        self.assertTrue(answer["eligible_for_publish"])
        return target

    def _consume(self, sealed: Path, identity: dict | None = None, *, now=None) -> dict:
        return consume_release(
            sealed,
            self.scenario.trust,
            self.scenario.identity if identity is None else identity,
            now=self.scenario.now if now is None else now,
        )

    def assertSealRejects(self) -> None:
        with self.assertRaises(EvidenceError):
            self._seal()
        self.assertFalse((self.root / "sealed").exists())

    def assertConsumeRejects(self, sealed: Path, identity: dict | None = None, *, now=None) -> None:
        answer = self._consume(sealed, identity, now=now)
        self.assertFalse(answer["eligible_for_publish"])
        self.assertEqual(2, answer["exit_code"])

    def test_valid_signed_graph_is_eligible_and_retains_historical_gate_pin(self) -> None:
        sealed = self._seal(now=self.scenario.now + timedelta(seconds=5))
        answer = self._consume(sealed, now=self.scenario.now + timedelta(seconds=10))
        self.assertTrue(answer["eligible_for_publish"])
        self.assertEqual(0, answer["exit_code"])
        self.assertTrue((sealed / "producer-gate.json").is_file())
        self.assertTrue((sealed / "release-seal.dsse.json").is_file())
        self.assertNotEqual((sealed / "producer-gate.json").read_bytes(), (sealed / "security-gate.json").read_bytes())
        self.assertEqual(0o400, (sealed / "release-seal.dsse.json").stat().st_mode & 0o777)

    def test_wrong_plan_key_role_is_rejected(self) -> None:
        key_id = next(key for key, value in self.scenario.trust["keys"].items() if value["kinds"] == ["scan-plan"])
        self.scenario.trust["keys"][key_id]["kinds"] = ["expectation"]
        self.assertSealRejects()

    def test_build_capture_graph_plan_pin_mismatch_is_rejected(self) -> None:
        self.scenario.write_build_capture(plan_sha256="f" * 64)
        self.assertSealRejects()

    def test_current_nonce_mismatch_is_rejected(self) -> None:
        sealed = self._seal()
        identity = copy.deepcopy(self.scenario.identity)
        identity["nonce"] = "c" * 64
        self.assertConsumeRejects(sealed, identity)

    def test_current_run_attempt_mismatch_is_rejected(self) -> None:
        sealed = self._seal()
        identity = copy.deepcopy(self.scenario.identity)
        identity["run_attempt"] += 1
        self.assertConsumeRejects(sealed, identity)

    def test_current_source_commit_mismatch_is_rejected(self) -> None:
        sealed = self._seal()
        identity = copy.deepcopy(self.scenario.identity)
        identity["source_commit"] = "c" * 40
        self.assertConsumeRejects(sealed, identity)

    def test_expired_receipt_is_rejected(self) -> None:
        sealed = self._seal()
        self.assertConsumeRejects(sealed, now=self.scenario.now + timedelta(seconds=1801))

    def test_replaced_authenticated_wheel_is_rejected_before_signing(self) -> None:
        wheel = next(iter(self.scenario.wheels))
        (self.scenario.dist_dir / wheel).write_bytes(b"replacement")
        self.assertSealRejects()

    def test_missing_planned_component_wheel_is_rejected(self) -> None:
        wheel = next(iter(self.scenario.wheels))
        (self.scenario.dist_dir / wheel).unlink()
        self.scenario.wheels.pop(wheel)
        self.scenario.write_build_capture()
        self.assertSealRejects()

    def test_extra_dist_file_is_rejected(self) -> None:
        (self.scenario.dist_dir / "unexpected-0.1.0-py3-none-any.whl").write_bytes(b"extra")
        self.assertSealRejects()

    def test_symlink_wheel_is_rejected(self) -> None:
        wheel = next(iter(self.scenario.wheels))
        artifact = self.scenario.dist_dir / wheel
        artifact.unlink()
        target = self.root / "elsewhere.whl"
        target.write_bytes(self.scenario.wheels[wheel])
        artifact.symlink_to(target)
        self.assertSealRejects()

    def test_blocked_gate_is_not_released_even_when_receipt_pin_is_updated(self) -> None:
        gate = strict_json_loads(self.scenario.producer_gate_raw)
        gate["decision"] = "block"
        gate["exit_code"] = 1
        gate["eligible_for_delivery"] = False
        self.scenario.rewrite_expectation_receipt(wire(gate))
        self.assertSealRejects()

    def test_seal_does_not_write_producer_dist_or_build_inputs(self) -> None:
        before_produced = snapshot(self.scenario.produced_dir)
        before_dist = snapshot(self.scenario.dist_dir)
        before_build = (self.scenario.build_capture_path.stat().st_mode & 0o777, sha(self.scenario.build_capture_path.read_bytes()))
        self._seal()
        self.assertEqual(before_produced, snapshot(self.scenario.produced_dir))
        self.assertEqual(before_dist, snapshot(self.scenario.dist_dir))
        self.assertEqual(before_build, (self.scenario.build_capture_path.stat().st_mode & 0o777, sha(self.scenario.build_capture_path.read_bytes())))

    def test_atomic_output_does_not_overwrite_existing_seal(self) -> None:
        sealed = self._seal()
        before = snapshot(sealed)
        with self.assertRaises(EvidenceError):
            self._seal()
        self.assertEqual(before, snapshot(sealed))

    def test_extra_file_in_sealed_directory_fails_closed(self) -> None:
        sealed = self._seal()
        make_writable(sealed)
        (sealed / "untrusted.txt").write_bytes(b"extra")
        self.assertConsumeRejects(sealed)

    def test_sealed_wheel_symlink_fails_closed(self) -> None:
        sealed = self._seal()
        make_writable(sealed)
        wheel = next(name for name in self.scenario.wheels if (sealed / name).exists())
        (sealed / wheel).unlink()
        target = self.root / "substitute.whl"
        target.write_bytes(b"substitute")
        (sealed / wheel).symlink_to(target)
        self.assertConsumeRejects(sealed)

    def test_tampered_release_binding_fails_closed(self) -> None:
        sealed = self._seal()
        make_writable(sealed)
        binding = sealed / "release-binding.json"
        binding.write_bytes(binding.read_bytes() + b" ")
        self.assertConsumeRejects(sealed)

    def test_tampered_historical_producer_gate_fails_closed(self) -> None:
        sealed = self._seal(now=self.scenario.now + timedelta(seconds=5))
        make_writable(sealed)
        gate = sealed / "producer-gate.json"
        gate.write_bytes(gate.read_bytes() + b" ")
        self.assertConsumeRejects(sealed, now=self.scenario.now + timedelta(seconds=10))

    def test_tampered_fresh_seal_gate_fails_closed(self) -> None:
        sealed = self._seal(now=self.scenario.now + timedelta(seconds=5))
        make_writable(sealed)
        gate = sealed / "security-gate.json"
        gate.write_bytes(gate.read_bytes() + b" ")
        self.assertConsumeRejects(sealed, now=self.scenario.now + timedelta(seconds=10))

    def test_revoked_release_role_fails_closed(self) -> None:
        sealed = self._seal()
        key_id = next(key for key, value in self.scenario.trust["keys"].items() if value["kinds"] == ["release-seal"])
        self.scenario.trust["keys"][key_id]["revoked"] = True
        self.assertConsumeRejects(sealed)


if __name__ == "__main__":
    unittest.main()
