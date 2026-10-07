"""Tests for failure_bundle: failure bundles, incident state, recovery.

Honest scope: these tests cover the state machine, input validation,
digest pinning, and append-only transition log — not persistence across
restarts (the caller's job) and not failure diagnosis.
"""
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

import support  # noqa: F401

from failure_bundle import (
    FAILURE_BUNDLE_VERSION,
    SCHEMA_PIN,
    FailureBundle,
    FailureBundleError,
    IncidentManager,
    IncidentState,
    StateTransition,
    bundle_digest,
    verify_bundle_digest,
)

DIGEST = "ab" * 32
DIGEST2 = "cd" * 32


def make_bundle(**kw):
    args = {
        "incident_id": "inc-1-tool.exec",
        "failed_action": "tool.exec",
        "error": "exit 1",
        "stack_context": "loop.step:42",
        "state_snapshot_hash": DIGEST,
        "created_seq": 7,
    }
    args.update(kw)
    return FailureBundle(**args)


class BundleValidationTests(unittest.TestCase):
    def test_valid_bundle_constructs(self):
        b = make_bundle()
        self.assertEqual(b.failed_action, "tool.exec")
        self.assertEqual(b.created_seq, 7)

    def test_empty_action_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(failed_action="")

    def test_empty_error_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(error="")

    def test_bad_snapshot_hash_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(state_snapshot_hash="not-hex")

    def test_short_hash_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(state_snapshot_hash="ab" * 31)

    def test_negative_seq_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(created_seq=-1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(created_seq=True)

    def test_non_str_stack_context_rejected(self):
        with self.assertRaises(FailureBundleError):
            make_bundle(stack_context=123)

    def test_bundle_is_frozen(self):
        b = make_bundle()
        with self.assertRaises(Exception):
            b.error = "changed"  # type: ignore[misc]

    def test_as_dict_carries_schema_pin(self):
        self.assertEqual(make_bundle().as_dict()["schema"], SCHEMA_PIN)


class BundleDigestTests(unittest.TestCase):
    def test_digest_is_hex64(self):
        d = bundle_digest(make_bundle())
        self.assertRegex(d, r"^[0-9a-f]{64}$")

    def test_digest_deterministic(self):
        self.assertEqual(bundle_digest(make_bundle()), bundle_digest(make_bundle()))

    def test_digest_changes_with_error(self):
        self.assertNotEqual(
            bundle_digest(make_bundle()),
            bundle_digest(make_bundle(error="exit 2")),
        )

    def test_verify_bundle_digest_true(self):
        b = make_bundle()
        self.assertTrue(verify_bundle_digest(b, bundle_digest(b)))

    def test_verify_bundle_digest_false(self):
        b = make_bundle()
        self.assertFalse(verify_bundle_digest(b, DIGEST))

    def test_verify_rejects_bad_expected(self):
        with self.assertRaises(FailureBundleError):
            verify_bundle_digest(make_bundle(), "zzz")


class TransitionValidationTests(unittest.TestCase):
    def test_valid_transition(self):
        t = StateTransition(
            seq=1, from_state=IncidentState.NORMAL,
            to_state=IncidentState.FAILED, reason="boom",
        )
        self.assertEqual(t.to_state, IncidentState.FAILED)

    def test_empty_reason_rejected(self):
        with self.assertRaises(FailureBundleError):
            StateTransition(
                seq=1, from_state=IncidentState.NORMAL,
                to_state=IncidentState.FAILED, reason="",
            )

    def test_bad_from_state_rejected(self):
        with self.assertRaises(FailureBundleError):
            StateTransition(seq=1, from_state="normal",  # type: ignore[arg-type]
                            to_state=IncidentState.FAILED, reason="x")


class IncidentManagerTests(unittest.TestCase):
    def test_initial_state_normal(self):
        self.assertIs(IncidentManager().state, IncidentState.NORMAL)

    def test_report_failure_creates_bundle_and_failed(self):
        mgr = IncidentManager()
        b = mgr.report_failure("tool.exec", "exit 1",
                               state_snapshot_hash=DIGEST, seq=7)
        self.assertIs(mgr.state, IncidentState.FAILED)
        self.assertIs(mgr.active_bundle, b)
        self.assertEqual(b.failed_action, "tool.exec")
        self.assertEqual(b.created_seq, 7)
        self.assertTrue(b.incident_id.startswith("inc-7-"))

    def test_report_failure_from_degraded(self):
        mgr = IncidentManager()
        mgr.degrade("slow disk", seq=1)
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=2)
        self.assertIs(mgr.state, IncidentState.FAILED)

    def test_second_report_while_failed_refused(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        with self.assertRaises(FailureBundleError):
            mgr.report_failure("tool.exec", "exit 2",
                               state_snapshot_hash=DIGEST2, seq=2)

    def test_report_while_recovering_refused(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        mgr.begin_recovery("ack", seq=2)
        with self.assertRaises(FailureBundleError):
            mgr.report_failure("tool.exec", "exit 2",
                               state_snapshot_hash=DIGEST2, seq=3)

    def test_degrade_normal_to_degraded(self):
        mgr = IncidentManager()
        mgr.degrade("slow disk", seq=1)
        self.assertIs(mgr.state, IncidentState.DEGRADED)

    def test_degrade_from_failed_refused(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        with self.assertRaises(FailureBundleError):
            mgr.degrade("worse", seq=2)

    def test_begin_recovery_from_failed(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        mgr.begin_recovery("operator ack", seq=2)
        self.assertIs(mgr.state, IncidentState.RECOVERING)

    def test_begin_recovery_from_degraded(self):
        mgr = IncidentManager()
        mgr.degrade("slow disk", seq=1)
        mgr.begin_recovery("disk replaced", seq=2)
        self.assertIs(mgr.state, IncidentState.RECOVERING)

    def test_begin_recovery_from_normal_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(FailureBundleError):
            mgr.begin_recovery("nothing to recover", seq=1)

    def test_complete_recovery_archives_and_normal(self):
        mgr = IncidentManager()
        b = mgr.report_failure("tool.exec", "exit 1",
                               state_snapshot_hash=DIGEST, seq=1)
        mgr.begin_recovery("ack", seq=2)
        mgr.complete_recovery("healthcheck green", seq=3)
        self.assertIs(mgr.state, IncidentState.NORMAL)
        self.assertIsNone(mgr.active_bundle)
        archived = mgr.archived_bundles()
        self.assertEqual(len(archived), 1)
        self.assertIs(archived[0], b)

    def test_complete_recovery_from_failed_refused(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        with self.assertRaises(FailureBundleError):
            mgr.complete_recovery("skip recovering", seq=2)

    def test_complete_recovery_from_normal_refused(self):
        mgr = IncidentManager()
        with self.assertRaises(FailureBundleError):
            mgr.complete_recovery("nothing", seq=1)

    def test_full_cycle_then_new_incident(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        mgr.begin_recovery("ack", seq=2)
        mgr.complete_recovery("green", seq=3)
        b2 = mgr.report_failure("memory.write", "denied",
                                state_snapshot_hash=DIGEST2, seq=4)
        self.assertIs(mgr.state, IncidentState.FAILED)
        self.assertEqual(b2.failed_action, "memory.write")
        self.assertEqual(len(mgr.archived_bundles()), 1)

    def test_transition_log_append_only_and_ordered(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=5)
        mgr.begin_recovery("ack", seq=6)
        mgr.complete_recovery("green", seq=7)
        log = mgr.transitions()
        self.assertEqual(len(log), 3)
        self.assertEqual(
            [(t.from_state, t.to_state) for t in log],
            [
                (IncidentState.NORMAL, IncidentState.FAILED),
                (IncidentState.FAILED, IncidentState.RECOVERING),
                (IncidentState.RECOVERING, IncidentState.NORMAL),
            ],
        )
        self.assertEqual([t.seq for t in log], [5, 6, 7])

    def test_transition_log_returns_copy(self):
        mgr = IncidentManager()
        log = mgr.transitions()
        self.assertIsInstance(log, tuple)

    def test_archived_bundle_digest_verifies(self):
        mgr = IncidentManager()
        mgr.report_failure("tool.exec", "exit 1",
                           state_snapshot_hash=DIGEST, seq=1)
        mgr.begin_recovery("ack", seq=2)
        mgr.complete_recovery("green", seq=3)
        archived = mgr.archived_bundles()[0]
        self.assertTrue(verify_bundle_digest(archived, bundle_digest(archived)))


class StandaloneImportTests(unittest.TestCase):
    def test_canonical_json_fallback_standalone_importable(self):
        """Module must import with sibling imports blocked (no wall-clock)."""
        src = (
            "import importlib.abc, sys\n"
            "class Blocker(importlib.abc.MetaPathFinder):\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name == 'canonical_json':\n"
            "            raise ImportError('blocked')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Blocker())\n"
            "import failure_bundle\n"
            "b = failure_bundle.FailureBundle(\n"
            "    incident_id='i', failed_action='a', error='e',\n"
            "    stack_context='', state_snapshot_hash='ab'*32, created_seq=0)\n"
            "print(failure_bundle.bundle_digest(b))\n"
        )
        mod_dir = str(Path(__file__).resolve().parent.parent)
        proc = subprocess.run(
            [sys.executable, "-c", src],
            capture_output=True, text=True, cwd=mod_dir,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stdout.strip(), r"^[0-9a-f]{64}$")

    def test_main_runs(self):
        mod_dir = str(Path(__file__).resolve().parent.parent)
        proc = subprocess.run(
            [sys.executable, str(Path(mod_dir) / "failure_bundle.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("failure-bundle OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
