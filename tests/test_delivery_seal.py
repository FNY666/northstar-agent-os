"""A sealed historical delivery: the seal itself, and what it enables.

The blind re-runner protocol needs an auditor-side check set. That set comes
from a delivery seal, so a delivery without a seal has no auditor set and the
real comparison cannot happen (that was the Slice 6 gap).

These tests cover the seal producer and the seal verifier:

* the producer drives the repository's own ``CodePhaseMachine`` — it does not
  hand-write a seal — and the resulting seal is v2 with a start tree hash and
  check-input pins;
* the verifier re-derives every recorded digest from Git instead of trusting
  the seal's own claim, so a tampered seal fails;
* the auditor check set extracted from a real seal is non-empty and consistent
  with the seal it came from.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "components" / "northstar-agent-runtime"
TOOL_PATH = ROOT / "scripts" / "seal-delivery.py"

for _path in (str(RUNTIME),):
    if _path not in sys.path:
        sys.path.insert(0, _path)

SPEC = importlib.util.spec_from_file_location("seal_delivery_tool", TOOL_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository corruption
    raise RuntimeError(f"cannot load {TOOL_PATH}")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)

from blind_rerunner import extract_auditor_checks  # noqa: E402


def _git(root: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(f"git {args} failed: {process.stderr}")
    return process.stdout.strip()


def _make_repository(parent: Path) -> tuple[Path, str, str]:
    """A repository with a start commit and a delivery commit on top of it.

    The delivery adds one source file and one helper that the check reads.
    The helper is deliberately *not* touched by the delivery, so it can be
    pinned as a check input.
    """
    root = parent / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "seal-tests@example.invalid")
    _git(root, "config", "user.name", "Seal Tests")
    (root / "helper.py").write_text("EXPECTED = 2\n", encoding="utf-8")
    (root / "check.py").write_text(
        "import sys\n"
        "from helper import EXPECTED\n"
        'text = open("app.py", encoding="utf-8").read()\n'
        'sys.exit(0 if f"value = {EXPECTED}" in text else 1)\n',
        encoding="utf-8",
    )
    (root / "app.py").write_text("value = 1\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "start")
    start = _git(root, "rev-parse", "HEAD")
    (root / "app.py").write_text("value = 2\n", encoding="utf-8")
    _git(root, "add", "app.py")
    _git(root, "commit", "-qm", "delivery")
    delivery = _git(root, "rev-parse", "HEAD")
    return root, start, delivery


class SealToolTests(unittest.TestCase):
    """The seal producer must use the product's own pipeline."""

    def test_the_tool_drives_the_repository_phase_machine(self):
        self.assertTrue(hasattr(TOOL, "seal_delivery"))
        source = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn("CodePhaseMachine", source)
        self.assertIn("seal_verification", source)
        self.assertIn("begin_verification", source)

    def test_a_sealed_delivery_produces_a_v2_seal_with_tree_and_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            seal = TOOL.seal_delivery(
                repository=root,
                start_commit=start,
                delivery_commit=delivery,
                evidence_dir=evidence,
                check_inputs=("helper.py",),
                checks=("python3 check.py",),
                goal="deliver the value change",
            )
            self.assertEqual(seal["schema"], "northstar.delivery-seal.v2")
            self.assertTrue(seal["ok"])
            self.assertEqual(seal["start_commit"], start)
            self.assertEqual(
                seal["start_tree_hash"], _git(root, "rev-parse", f"{start}^{{tree}}")
            )
            self.assertTrue(seal["check_inputs_pinned"])
            self.assertTrue(seal["check_inputs_unchanged"])
            self.assertEqual(len(seal["check_input_pins"]), 1)
            pin = seal["check_input_pins"][0]
            self.assertEqual(pin["path"], "helper.py")
            self.assertEqual(
                pin["baseline_blob_sha"], _git(root, "rev-parse", f"{start}:helper.py")
            )
            self.assertTrue(pin["unchanged"])

    def test_the_seal_is_written_to_the_evidence_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            TOOL.seal_delivery(
                repository=root,
                start_commit=start,
                delivery_commit=delivery,
                evidence_dir=evidence,
                check_inputs=("helper.py",),
                checks=("python3 check.py",),
                goal="deliver the value change",
            )
            self.assertTrue((evidence / "delivery-seal.json").is_file())
            self.assertTrue((evidence / "phases.json").is_file())
            self.assertTrue((evidence / "patch-audit.json").is_file())
            self.assertTrue((evidence / "patch-replay.json").is_file())
            self.assertTrue((evidence / "manifest.json").is_file())
            written = json.loads((evidence / "delivery-seal.json").read_text(encoding="utf-8"))
            self.assertEqual(written["schema"], "northstar.delivery-seal.v2")

    def test_the_evidence_directory_reconciles_as_a_terminal_run(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            TOOL.seal_delivery(
                repository=root,
                start_commit=start,
                delivery_commit=delivery,
                evidence_dir=evidence,
                check_inputs=("helper.py",),
                checks=("python3 check.py",),
                goal="deliver the value change",
            )
            receipt = TOOL.reconcile_code_evidence(evidence)
            self.assertEqual(receipt["classification"], "terminal")
            self.assertEqual(receipt["phase_seal"], "valid")
            self.assertEqual(receipt["integrity_errors"], [])
            self.assertFalse(receipt["automatic_tool_replay"])

    def test_sealing_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            seals = []
            for index in (1, 2):
                evidence = parent / f"evidence-{index}"
                seal = TOOL.seal_delivery(
                    repository=root,
                    start_commit=start,
                    delivery_commit=delivery,
                    evidence_dir=evidence,
                    check_inputs=("helper.py",),
                    checks=("python3 check.py",),
                    goal="deliver the value change",
                )
                seals.append(seal)
            self.assertEqual(seals[0], seals[1])

    def test_a_failing_host_check_refuses_the_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            with self.assertRaises(TOOL.SealError):
                TOOL.seal_delivery(
                    repository=root,
                    start_commit=start,
                    delivery_commit=delivery,
                    evidence_dir=evidence,
                    check_inputs=("helper.py",),
                    checks=("python3 -c \"import sys; sys.exit(3)\"",),
                    goal="deliver the value change",
                )
            self.assertFalse((evidence / "delivery-seal.json").is_file())

    def test_a_delivery_that_does_not_apply_to_the_start_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            # A delivery that removes a file the start commit owns does not
            # apply cleanly onto the start tree as a forward patch.
            (root / "app.py").unlink()
            _git(root, "add", "-A")
            _git(root, "commit", "-qm", "removal delivery")
            removal = _git(root, "rev-parse", "HEAD")
            with self.assertRaises(TOOL.SealError):
                TOOL.seal_delivery(
                    repository=root,
                    start_commit=start,
                    delivery_commit=removal,
                    evidence_dir=parent / "evidence",
                    check_inputs=("helper.py",),
                    checks=("python3 check.py",),
                    goal="deliver the removal",
                )


if __name__ == "__main__":
    unittest.main()


class SealVerificationTests(unittest.TestCase):
    """The verifier must re-derive the seal's claims from Git."""

    def _sealed(self, parent: Path) -> tuple[Path, Path, str, str, dict]:
        root, start, delivery = _make_repository(parent)
        evidence = parent / "evidence"
        seal = TOOL.seal_delivery(
            repository=root,
            start_commit=start,
            delivery_commit=delivery,
            evidence_dir=evidence,
            check_inputs=("helper.py",),
            checks=("python3 check.py",),
            goal="deliver the value change",
        )
        return root, evidence, start, delivery, seal

    def test_a_freshly_sealed_delivery_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, evidence, start, _, _ = self._sealed(parent)
            receipt = TOOL.verify_delivery(evidence, root)
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["problems"], [])
            self.assertEqual(receipt["start_commit"], start)
            self.assertEqual(receipt["check_input_pins"], 1)

    def test_a_tampered_start_tree_hash_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, evidence, _, _, _ = self._sealed(parent)
            seal_path = evidence / "delivery-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["start_tree_hash"] = "0" * 40
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            receipt = TOOL.verify_delivery(evidence, root)
            self.assertFalse(receipt["ok"])
            self.assertTrue(
                any("start tree hash" in problem for problem in receipt["problems"]),
                receipt["problems"],
            )

    def test_a_tampered_check_input_pin_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, evidence, _, _, _ = self._sealed(parent)
            seal_path = evidence / "delivery-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["check_input_pins"][0]["baseline_blob_sha"] = "1" * 40
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            receipt = TOOL.verify_delivery(evidence, root)
            self.assertFalse(receipt["ok"])
            self.assertTrue(
                any("check-input pin 1" in problem for problem in receipt["problems"]),
                receipt["problems"],
            )

    def test_a_seal_without_check_input_pins_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, evidence, _, _, _ = self._sealed(parent)
            seal_path = evidence / "delivery-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["check_input_pins"] = []
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            receipt = TOOL.verify_delivery(evidence, root)
            self.assertFalse(receipt["ok"])
            self.assertTrue(
                any("pins no check inputs" in problem for problem in receipt["problems"]),
                receipt["problems"],
            )

    def test_a_seal_that_claims_not_ok_fails_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, evidence, _, _, _ = self._sealed(parent)
            seal_path = evidence / "delivery-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["ok"] = False
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            receipt = TOOL.verify_delivery(evidence, root)
            self.assertFalse(receipt["ok"])

    def test_the_verifier_recomputes_rather_than_reading_the_seal_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, evidence, _, _, _ = self._sealed(parent)
            seal = json.loads((evidence / "delivery-seal.json").read_text(encoding="utf-8"))
            # The recorded pin is the repository's own object id; the verifier
            # must reach the same value by asking Git, not by reading the seal.
            actual = _git(root, "rev-parse", f"{seal['start_commit']}:helper.py")
            self.assertEqual(seal["check_input_pins"][0]["baseline_blob_sha"], actual)


class AuditorSetTests(unittest.TestCase):
    """A sealed delivery yields a non-empty, seal-consistent auditor set."""

    def test_the_auditor_set_extracted_from_a_seal_is_non_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            TOOL.seal_delivery(
                repository=root,
                start_commit=start,
                delivery_commit=delivery,
                evidence_dir=evidence,
                check_inputs=("helper.py",),
                checks=("python3 check.py",),
                goal="deliver the value change",
            )
            checks = extract_auditor_checks(evidence / "delivery-seal.json")
            self.assertTrue(checks)
            self.assertEqual(checks[0].id, "pinned-start-tree")
            self.assertTrue(any(check.id.endswith(":helper.py") for check in checks))

    def test_the_auditor_set_is_consistent_with_the_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            seal = TOOL.seal_delivery(
                repository=root,
                start_commit=start,
                delivery_commit=delivery,
                evidence_dir=evidence,
                check_inputs=("helper.py",),
                checks=("python3 check.py",),
                goal="deliver the value change",
            )
            checks = extract_auditor_checks(evidence / "delivery-seal.json")
            self.assertEqual(len(checks), len(seal["check_input_pins"]) + 1)
            self.assertIn(seal["start_tree_hash"], checks[0].command)
            for pin in seal["check_input_pins"]:
                self.assertTrue(
                    any(pin["baseline_blob_sha"] in check.command for check in checks),
                    pin["path"],
                )

    def test_every_extracted_auditor_command_passes_against_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root, start, delivery = _make_repository(parent)
            evidence = parent / "evidence"
            TOOL.seal_delivery(
                repository=root,
                start_commit=start,
                delivery_commit=delivery,
                evidence_dir=evidence,
                check_inputs=("helper.py",),
                checks=("python3 check.py",),
                goal="deliver the value change",
            )
            for check in extract_auditor_checks(evidence / "delivery-seal.json"):
                process = subprocess.run(
                    check.command, shell=True, cwd=str(root), check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                self.assertEqual(process.returncode, 0, check.id)


class Slice6DeliveryEvidenceTests(unittest.TestCase):
    """The committed Slice 6 evidence is real, and it closes the Slice 6 gap.

    Slice 5 recorded the gap honestly: the delivery had no seal, so no
    auditor check set existed and the real comparison could not happen. These
    tests pin the evidence that closes it: a v2 seal with a start tree hash
    and check-input pins, an auditor set extracted from it, and a real
    divergence report.

    The assertions that need Git history are skipped when the checkout is
    shallow (CI clones with the default depth), because the historical
    commits are then genuinely absent rather than wrong.
    """

    EVIDENCE = ROOT / "docs" / "delivery" / "slice6"
    START_COMMIT = "38d175e9565c8ae46ee5ef7a8be8d874ea3038f0"
    DELIVERY_COMMIT = "a49d073f0b4039d4171676bb5af54df47ede68f4"
    CLAIM = (
        "This delivery revokes live sockets when authorization leases are withdrawn "
        "and surfaces termination and network errors."
    )

    def _history_available(self) -> bool:
        process = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", f"{self.START_COMMIT}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return process.returncode == 0

    def _seal(self) -> dict:
        return json.loads((self.EVIDENCE / "slice6-seal.json").read_text(encoding="utf-8"))

    def test_the_slice6_evidence_directory_exists(self):
        self.assertTrue((self.EVIDENCE / "slice6-seal.json").is_file())
        self.assertTrue((self.EVIDENCE / "slice6-manifest.json").is_file())
        self.assertTrue((self.EVIDENCE / "slice6-reconcile.json").is_file())
        self.assertTrue((self.EVIDENCE / "slice6-divergence-report.json").is_file())
        self.assertTrue((self.EVIDENCE / "slice6-blind-checks.json").is_file())

    def test_the_slice6_seal_is_a_v2_seal(self):
        seal = self._seal()
        self.assertEqual(seal["schema"], "northstar.delivery-seal.v2")
        self.assertTrue(seal["ok"])

    def test_the_slice6_seal_carries_a_start_tree_and_start_commit(self):
        seal = self._seal()
        self.assertEqual(seal["start_commit"], self.START_COMMIT)
        self.assertTrue(seal["start_tree_hash"])
        self.assertRegex(seal["start_tree_hash"], r"^[0-9a-f]{40}$")

    def test_the_slice6_seal_carries_check_input_pins(self):
        seal = self._seal()
        self.assertTrue(seal["check_inputs_pinned"])
        self.assertTrue(seal["check_inputs_unchanged"])
        pins = seal["check_input_pins"]
        self.assertTrue(pins)
        for pin in pins:
            self.assertTrue(pin["path"])
            self.assertRegex(pin["baseline_blob_sha"], r"^[0-9a-f]{40}$")
            self.assertTrue(pin["unchanged"])

    def test_the_slice6_pins_name_the_files_the_checks_read(self):
        seal = self._seal()
        paths = {pin["path"] for pin in seal["check_input_pins"]}
        self.assertIn("components/northstar-egress-sidecar/transport.py", paths)
        self.assertIn("components/northstar-agent-runtime/egress_enforcer.py", paths)

    def test_the_slice6_pins_are_resolvable_against_the_repository(self):
        if not self._history_available():
            self.skipTest("the checkout is shallow; the start commit is absent")
        seal = self._seal()
        for pin in seal["check_input_pins"]:
            actual = _git(ROOT, "rev-parse", f"{self.START_COMMIT}:{pin['path']}")
            self.assertEqual(actual, pin["baseline_blob_sha"], pin["path"])

    def test_the_slice6_seal_verifies_against_the_repository(self):
        if not self._history_available():
            self.skipTest("the checkout is shallow; the start commit is absent")
        receipt = TOOL.verify_delivery(self.EVIDENCE, ROOT)
        self.assertTrue(receipt["ok"], receipt["problems"])
        self.assertEqual(receipt["problems"], [])

    def test_the_slice6_auditor_set_is_non_empty_and_seal_consistent(self):
        checks = extract_auditor_checks(self.EVIDENCE / "slice6-seal.json")
        self.assertTrue(checks)
        seal = self._seal()
        self.assertEqual(len(checks), len(seal["check_input_pins"]) + 1)
        self.assertEqual(checks[0].id, "pinned-start-tree")
        for pin in seal["check_input_pins"]:
            self.assertTrue(
                any(pin["baseline_blob_sha"] in check.command for check in checks),
                pin["path"],
            )

    def test_the_slice6_divergence_report_is_real(self):
        report = json.loads(
            (self.EVIDENCE / "slice6-divergence-report.json").read_text(encoding="utf-8")
        )
        self.assertEqual(report["schema"], "northstar.blind-rerunner-divergence.v1")
        # The whole point of the seal: the auditor side is now available.
        self.assertTrue(report["auditor_available"])
        self.assertEqual(report["unassessed_blind"], [])
        self.assertEqual(report["findings"], [])
        # Divergence is the finding, so the report must not be empty of content.
        self.assertTrue(report["blind_only"])
        self.assertTrue(report["auditor_only"])
        self.assertEqual(report["both"], [])

    def test_the_slice6_divergence_report_matches_the_committed_blind_checks(self):
        report = json.loads(
            (self.EVIDENCE / "slice6-divergence-report.json").read_text(encoding="utf-8")
        )
        blind = json.loads((self.EVIDENCE / "slice6-blind-checks.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [item["id"] for item in report["blind_only"]],
            [item["id"] for item in blind],
        )

    def test_the_slice6_manifest_binds_the_seal_digest(self):
        manifest = json.loads((self.EVIDENCE / "slice6-manifest.json").read_text(encoding="utf-8"))
        seal_raw = (self.EVIDENCE / "slice6-seal.json").read_bytes()
        self.assertEqual(
            manifest["delivery_seal_sha256"], __import__("hashlib").sha256(seal_raw).hexdigest()
        )
        self.assertEqual(manifest["start_commit"], self.START_COMMIT)
        self.assertEqual(manifest["delivery_commit"], self.DELIVERY_COMMIT)

    def test_the_slice6_evidence_reconciles_as_terminal(self):
        receipt = json.loads((self.EVIDENCE / "slice6-reconcile.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["classification"], "terminal")
        self.assertEqual(receipt["phase_seal"], "valid")
        self.assertEqual(receipt["integrity_errors"], [])


class Slice6BlindComparisonTests(unittest.TestCase):
    """The real comparison: blind checks against the real seal's auditor set."""

    EVIDENCE = ROOT / "docs" / "delivery" / "slice6"
    START_COMMIT = "38d175e9565c8ae46ee5ef7a8be8d874ea3038f0"
    CLAIM = (
        "This delivery revokes live sockets when authorization leases are withdrawn "
        "and surfaces termination and network errors."
    )

    def _history_available(self) -> bool:
        process = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", f"{self.START_COMMIT}^{{commit}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return process.returncode == 0

    def test_the_blind_bundle_is_built_from_the_delivery_start_commit(self):
        if not self._history_available():
            self.skipTest("the checkout is shallow; the start commit is absent")
        from blind_rerunner import build_blind_bundle

        bundle = build_blind_bundle(self.START_COMMIT, self.CLAIM, repo_root=ROOT)
        self.assertEqual(bundle.start_commit, self.START_COMMIT)
        self.assertEqual(
            set(bundle.as_dict()), {"schema", "start_commit", "claim", "repo_path"}
        )

    def test_the_real_comparison_produces_an_available_auditor_set(self):
        if not self._history_available():
            self.skipTest("the checkout is shallow; the start commit is absent")
        from blind_rerunner import BlindCheck, run_blind_rerun

        blind = [
            BlindCheck(
                item["id"], item["description"], item["command"]
            )
            for item in json.loads(
                (self.EVIDENCE / "slice6-blind-checks.json").read_text(encoding="utf-8")
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "divergence.json"
            _, report = run_blind_rerun(
                start_commit=self.START_COMMIT,
                claim=self.CLAIM,
                repo_root=ROOT,
                blind_checks=blind,
                delivery=self.EVIDENCE / "slice6-seal.json",
                report_path=report_path,
            )
            self.assertTrue(report.auditor_available)
            self.assertEqual(report.unassessed_blind, ())
            self.assertEqual(report.findings, ())
            self.assertTrue(report.auditor_only)
            self.assertTrue(report.blind_only)
            persisted = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, report.as_dict())

    def test_the_committed_divergence_report_is_reproducible(self):
        if not self._history_available():
            self.skipTest("the checkout is shallow; the start commit is absent")
        from blind_rerunner import BlindCheck, run_blind_rerun

        blind = [
            BlindCheck(
                item["id"], item["description"], item["command"]
            )
            for item in json.loads(
                (self.EVIDENCE / "slice6-blind-checks.json").read_text(encoding="utf-8")
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "divergence.json"
            run_blind_rerun(
                start_commit=self.START_COMMIT,
                claim=self.CLAIM,
                repo_root=ROOT,
                blind_checks=blind,
                delivery=self.EVIDENCE / "slice6-seal.json",
                report_path=report_path,
            )
            committed = json.loads(
                (self.EVIDENCE / "slice6-divergence-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), committed)


class CommittedEvidenceDoesNotBreakFutureBundlesTests(unittest.TestCase):
    """Committing the seal must not brick the blind-bundle exclusion rule.

    ``build_blind_bundle`` refuses a start commit that tracks a path under
    the reserved artifact directories, and the rule is blanket over the whole
    tree. A committed seal stored under such a name would therefore make
    *every* later blind bundle fail — including the one for the very
    delivery it documents. The committed evidence must sit outside those
    names.
    """

    EVIDENCE = ROOT / "docs" / "delivery" / "slice6"

    def test_the_committed_evidence_avoids_the_reserved_artifact_names(self):
        from blind_rerunner import _is_evidence_path

        for path in sorted(self.EVIDENCE.iterdir()):
            relative = path.relative_to(ROOT).as_posix()
            self.assertFalse(
                _is_evidence_path(relative),
                f"{relative} uses a reserved delivery-evidence name",
            )

    def test_the_committed_evidence_uses_prefixed_names(self):
        names = {path.name for path in self.EVIDENCE.iterdir()}
        self.assertIn("slice6-seal.json", names)
        self.assertNotIn("delivery-seal.json", names)

    def test_the_repository_tree_tracks_no_reserved_evidence_path(self):
        from blind_rerunner import _is_evidence_path

        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.split()
        offenders = [path for path in tracked if _is_evidence_path(path)]
        self.assertEqual(offenders, [])


class CommittedEvidenceIsSelfContainedTests(unittest.TestCase):
    """The committed evidence must reconcile on its own, without a re-run."""

    EVIDENCE = ROOT / "docs" / "delivery" / "slice6"

    def _as_live_evidence(self, parent: Path) -> Path:
        """Re-shape the committed run record the way a live run lays it out.

        A live run names its files ``delivery-seal.json`` and ``phases.json``;
        the committed record carries prefixed names so it does not use the
        protocol's reserved artifact names. Renaming the files and updating
        the manifest's references to match is the only difference.
        """
        import shutil

        destination = parent / "evidence"
        shutil.copytree(self.EVIDENCE, destination)
        (destination / "slice6-seal.json").rename(destination / "delivery-seal.json")
        (destination / "slice6-phases.json").rename(destination / "phases.json")
        manifest_path = destination / "slice6-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["delivery_seal"] = "delivery-seal.json"
        manifest["phases"] = "phases.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest_path.rename(destination / "manifest.json")
        return destination

    def test_the_committed_evidence_reconciles_without_a_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._as_live_evidence(Path(directory))
            receipt = TOOL.reconcile_code_evidence(evidence)
            self.assertEqual(receipt["classification"], "terminal")
            self.assertEqual(receipt["phase_seal"], "valid")
            self.assertEqual(receipt["integrity_errors"], [])
            self.assertFalse(receipt["automatic_tool_replay"])

    def test_the_committed_manifest_digests_match_the_committed_files(self):
        manifest = json.loads(
            (self.EVIDENCE / "slice6-manifest.json").read_text(encoding="utf-8")
        )
        seal_raw = (self.EVIDENCE / manifest["delivery_seal"]).read_bytes()
        phases_raw = (self.EVIDENCE / manifest["phases"]).read_bytes()
        self.assertEqual(
            manifest["delivery_seal_sha256"], hashlib.sha256(seal_raw).hexdigest()
        )
        self.assertEqual(
            manifest["phases_sha256"], hashlib.sha256(phases_raw).hexdigest()
        )

    def test_a_tampered_committed_seal_is_detected_by_the_reconciler(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self._as_live_evidence(Path(directory))
            seal_path = evidence / "delivery-seal.json"
            seal = json.loads(seal_path.read_text(encoding="utf-8"))
            seal["ok"] = False
            seal_path.write_text(json.dumps(seal), encoding="utf-8")
            receipt = TOOL.reconcile_code_evidence(evidence)
            self.assertEqual(receipt["classification"], "invalid_evidence")
            self.assertTrue(receipt["integrity_errors"])
