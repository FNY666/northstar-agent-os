"""Tests for iterated_amplification: safety-instrumented IDA primitive."""

import unittest

from iterated_amplification import (
    SCHEMA_PIN,
    ITERATED_AMPLIFICATION_VERSION,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_BRANCHING,
    AmplificationError,
    AmplifiedResult,
    AmplificationTree,
    Amplifier,
    Decomposition,
    DistillationPair,
    Task,
)


def fresh() -> Amplifier:
    return Amplifier()


def rooted(amp=None, task_id="t0", desc="root task", seq=1):
    amp = amp or fresh()
    amp.register_root(desc, task_id=task_id, seq=seq)
    return amp


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ITERATED_AMPLIFICATION_VERSION, "iterated-amplification.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.iterated-amplification.v1")

    def test_default_caps(self):
        self.assertGreaterEqual(DEFAULT_MAX_DEPTH, 1)
        self.assertGreaterEqual(DEFAULT_MAX_BRANCHING, 1)


class TaskValidationTests(unittest.TestCase):
    def test_frozen(self):
        t = Task(task_id="a", description="d", parent_id=None, depth=0, seq=0)
        with self.assertRaises(Exception):
            t.task_id = "x"  # type: ignore[misc]

    def test_empty_id_rejected(self):
        with self.assertRaises(AmplificationError):
            Task(task_id="", description="d", parent_id=None, depth=0, seq=0)

    def test_empty_description_rejected(self):
        with self.assertRaises(AmplificationError):
            Task(task_id="a", description="  ", parent_id=None, depth=0, seq=0)

    def test_bool_seq_rejected(self):
        with self.assertRaises(AmplificationError):
            Task(task_id="a", description="d", parent_id=None, depth=0, seq=True)

    def test_root_depth_must_be_zero(self):
        with self.assertRaises(AmplificationError):
            Task(task_id="a", description="d", parent_id=None, depth=1, seq=0)


class RegisterTests(unittest.TestCase):
    def test_register_root_happy(self):
        amp = rooted()
        task = amp._tasks["t0"]
        self.assertEqual(task.depth, 0)
        self.assertIsNone(task.parent_id)

    def test_duplicate_root_rejected(self):
        amp = rooted()
        with self.assertRaises(AmplificationError):
            amp.register_root("again", task_id="t0", seq=2)

    def test_bad_caps_rejected(self):
        with self.assertRaises(AmplificationError):
            Amplifier(max_depth=0)
        with self.assertRaises(AmplificationError):
            Amplifier(max_branching=True)


class DecomposeTests(unittest.TestCase):
    def test_decompose_happy(self):
        amp = rooted()
        dec = amp.decompose("t0", ["a", "b"], seq=2)
        self.assertEqual(dec.parent_id, "t0")
        self.assertEqual(dec.child_ids, ("t0.0", "t0.1"))
        self.assertTrue(dec.digest.startswith("sha256:"))
        self.assertEqual(amp._tasks["t0.1"].depth, 1)

    def test_decompose_digest_deterministic(self):
        amp1, amp2 = rooted(task_id="x"), rooted(task_id="x")
        d1 = amp1.decompose("x", ["a"], seq=5)
        d2 = amp2.decompose("x", ["a"], seq=5)
        self.assertEqual(d1.digest, d2.digest)

    def test_decompose_unknown_parent(self):
        amp = rooted()
        with self.assertRaises(AmplificationError):
            amp.decompose("nope", ["a"], seq=1)

    def test_decompose_twice_refused(self):
        amp = rooted()
        amp.decompose("t0", ["a"], seq=2)
        with self.assertRaises(AmplificationError):
            amp.decompose("t0", ["b"], seq=3)

    def test_decompose_empty_refused(self):
        amp = rooted()
        with self.assertRaises(AmplificationError):
            amp.decompose("t0", [], seq=2)

    def test_decompose_over_branching(self):
        amp = Amplifier(max_branching=2)
        amp.register_root("r", task_id="r", seq=1)
        with self.assertRaises(AmplificationError):
            amp.decompose("r", ["a", "b", "c"], seq=2)

    def test_decompose_depth_cap(self):
        amp = Amplifier(max_depth=1)
        amp.register_root("r", task_id="r", seq=1)
        amp.decompose("r", ["a"], seq=2)
        with self.assertRaises(AmplificationError):
            amp.decompose("r.0", ["x"], seq=3)


class AmplifyTests(unittest.TestCase):
    def test_amplify_two_levels(self):
        amp = rooted()
        tree = amp.amplify(
            "t0",
            plan={"t0": ["rev", "exp"], "t0.0": ["rev.a", "rev.b"]},
            depth=2,
            seq=2,
        )
        self.assertEqual(tree.root_id, "t0")
        leaves = amp.leaves("t0")
        self.assertEqual(
            [l.task_id for l in leaves], ["t0.1", "t0.0.0", "t0.0.1"]
        )

    def test_amplify_depth_zero(self):
        amp = rooted()
        tree = amp.amplify("t0", plan={"t0": ["a"]}, depth=0, seq=2)
        self.assertEqual(tree.task_ids, ("t0",))

    def test_amplify_stops_when_plan_exhausted(self):
        amp = rooted()
        tree = amp.amplify("t0", plan={"t0": ["a"]}, depth=5, seq=2)
        self.assertEqual(set(tree.task_ids), {"t0", "t0.0"})

    def test_amplify_unknown_plan_key(self):
        amp = rooted()
        with self.assertRaises(AmplificationError):
            amp.amplify("t0", plan={"zzz": ["a"]}, depth=1, seq=2)

    def test_amplify_bad_depth(self):
        amp = rooted()
        with self.assertRaises(AmplificationError):
            amp.amplify("t0", plan={}, depth=-1, seq=2)
        with self.assertRaises(AmplificationError):
            amp.amplify("t0", plan={}, depth=True, seq=2)

    def test_amplify_depth_cap_enforced(self):
        amp = Amplifier(max_depth=1)
        amp.register_root("r", task_id="r", seq=1)
        with self.assertRaises(AmplificationError):
            amp.amplify("r", plan={"r": ["a"], "r.0": ["x"]}, depth=2, seq=2)


class TreeInspectionTests(unittest.TestCase):
    def test_leaves_registration_order(self):
        amp = rooted()
        amp.decompose("t0", ["c", "b", "a"], seq=2)
        self.assertEqual(
            [l.task_id for l in amp.leaves("t0")], ["t0.0", "t0.1", "t0.2"]
        )

    def test_verify_tree_true(self):
        amp = rooted()
        amp.amplify("t0", plan={"t0": ["a", "b"]}, depth=1, seq=2)
        self.assertTrue(amp.verify_tree("t0"))

    def test_verify_tree_unknown(self):
        amp = rooted()
        self.assertFalse(amp.verify_tree("zzz"))


class CombineTests(unittest.TestCase):
    def _built(self):
        amp = rooted()
        amp.amplify("t0", plan={"t0": ["a", "b"]}, depth=1, seq=2)
        return amp

    def test_combine_happy(self):
        amp = self._built()
        result = amp.combine(
            "t0",
            {"t0.0": "rev ok", "t0.1": "exp ok"},
            synthesized="all clean",
            seq=3,
        )
        self.assertFalse(result.partial)
        self.assertEqual(result.leaf_ids, ("t0.0", "t0.1"))
        self.assertTrue(result.combined_digest.startswith("sha256:"))
        self.assertEqual(len(result.leaf_digests), 2)

    def test_combine_missing_leaf_refused(self):
        amp = self._built()
        with self.assertRaises(AmplificationError):
            amp.combine("t0", {"t0.0": "x"}, synthesized="s", seq=3)

    def test_combine_unknown_leaf_refused(self):
        amp = self._built()
        with self.assertRaises(AmplificationError):
            amp.combine(
                "t0",
                {"t0.0": "x", "t0.1": "y", "t0.9": "z"},
                synthesized="s",
                seq=3,
            )

    def test_combine_empty_output_refused(self):
        amp = self._built()
        with self.assertRaises(AmplificationError):
            amp.combine(
                "t0", {"t0.0": "  ", "t0.1": "y"}, synthesized="s", seq=3
            )

    def test_combine_partial_recorded(self):
        amp = self._built()
        result = amp.combine(
            "t0", {"t0.0": "x"}, synthesized="half", seq=3, allow_partial=True
        )
        self.assertTrue(result.partial)
        self.assertEqual(result.leaf_ids, ("t0.0",))

    def test_combine_non_bool_partial_refused(self):
        amp = self._built()
        with self.assertRaises(AmplificationError):
            amp.combine(
                "t0",
                {"t0.0": "x", "t0.1": "y"},
                synthesized="s",
                seq=3,
                allow_partial=1,
            )

    def test_distillation_ledger(self):
        amp = self._built()
        result = amp.combine(
            "t0", {"t0.0": "x", "t0.1": "y"}, synthesized="s", seq=3
        )
        ledger = amp.distillation_ledger()
        self.assertEqual(len(ledger), 1)
        pair = ledger[0]
        self.assertIsInstance(pair, DistillationPair)
        self.assertEqual(pair.task_id, "t0")
        self.assertEqual(pair.leaf_count, 2)
        self.assertEqual(pair.combined_digest, result.combined_digest)

    def test_audit_event(self):
        amp = self._built()
        result = amp.combine(
            "t0", {"t0.0": "x", "t0.1": "y"}, synthesized="s", seq=3
        )
        event = amp.amplification_audit_event(result, seq=4)
        self.assertEqual(event["audit_seq"], 4)
        self.assertEqual(event["schema"], SCHEMA_PIN)

    def test_main_runs(self):
        from iterated_amplification import main

        main()


if __name__ == "__main__":
    unittest.main()
