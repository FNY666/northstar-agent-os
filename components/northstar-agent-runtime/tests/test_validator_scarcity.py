"""Tests for validator_scarcity.py — 15+ tests."""

import unittest

import validator_scarcity as vs


def make_queue(n, start_seq=0):
    q = vs.SubmissionQueue()
    for i in range(n):
        q.submit(vs.Submission(f"sub-{i}", submitted_seq=start_seq + i))
    return q


class TestCapacity(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(vs.VALIDATOR_SCARCITY_VERSION, "validator-scarcity.v1")

    def test_thresholds(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        self.assertEqual(cap.scarcity_threshold(), 100)
        self.assertEqual(cap.escalation_threshold(), 50)

    def test_rejects_non_positive(self):
        with self.assertRaises(vs.ScarcityError):
            vs.ValidatorCapacity(max_reviews_per_day=0)
        with self.assertRaises(vs.ScarcityError):
            vs.ValidatorCapacity(max_reviews_per_day=-5)

    def test_rejects_bool_and_non_int(self):
        with self.assertRaises(vs.ScarcityError):
            vs.ValidatorCapacity(max_reviews_per_day=True)
        with self.assertRaises(vs.ScarcityError):
            vs.ValidatorCapacity(max_reviews_per_day=10.5)


class TestSubmission(unittest.TestCase):
    def test_frozen(self):
        s = vs.Submission("a", submitted_seq=1)
        with self.assertRaises(Exception):
            s.submission_id = "b"  # type: ignore

    def test_rejects_bad_fields(self):
        with self.assertRaises(vs.ScarcityError):
            vs.Submission("", submitted_seq=1)
        with self.assertRaises(vs.ScarcityError):
            vs.Submission("a", submitted_seq=-1)
        with self.assertRaises(vs.ScarcityError):
            vs.Submission("a", submitted_seq=True)


class TestQueue(unittest.TestCase):
    def test_submit_and_pending(self):
        q = make_queue(3)
        self.assertEqual(q.pending, 3)
        self.assertEqual(len(q), 3)
        self.assertIn("sub-0", q)

    def test_duplicate_rejected(self):
        q = vs.SubmissionQueue()
        q.submit(vs.Submission("a", submitted_seq=0))
        with self.assertRaises(vs.ScarcityError):
            q.submit(vs.Submission("a", submitted_seq=1))

    def test_complete_review(self):
        q = make_queue(2)
        done = q.complete_review("sub-0")
        self.assertEqual(done.submission_id, "sub-0")
        self.assertEqual(q.pending, 1)
        with self.assertRaises(vs.ScarcityError):
            q.complete_review("sub-0")

    def test_iteration_order_deterministic(self):
        q = vs.SubmissionQueue()
        q.submit(vs.Submission("b", submitted_seq=5))
        q.submit(vs.Submission("a", submitted_seq=5))
        q.submit(vs.Submission("c", submitted_seq=1))
        self.assertEqual([s.submission_id for s in q], ["c", "a", "b"])

    def test_pause_blocks_submit(self):
        q = make_queue(1)
        q.pause_intake(seq=10)
        self.assertFalse(q.intake_open)
        with self.assertRaises(vs.IntakePaused):
            q.submit(vs.Submission("late", submitted_seq=11))

    def test_pause_idempotent_and_resume(self):
        q = vs.SubmissionQueue()
        q.pause_intake(seq=1)
        q.pause_intake(seq=2)  # idempotent
        q.resume_intake(seq=3)
        self.assertTrue(q.intake_open)
        q.submit(vs.Submission("ok", submitted_seq=4))
        self.assertEqual(q.pending, 1)


class TestDetect(unittest.TestCase):
    def test_no_scarcity_below_threshold(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        q = make_queue(100)  # exactly 10x -> not scarce (strict >)
        self.assertFalse(vs.detect_scarcity(q, cap))

    def test_scarcity_above_threshold(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        q = make_queue(101)
        self.assertTrue(vs.detect_scarcity(q, cap))

    def test_rejects_bad_inputs(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        with self.assertRaises(vs.ScarcityError):
            vs.detect_scarcity("nope", cap)  # type: ignore
        with self.assertRaises(vs.ScarcityError):
            vs.detect_scarcity(vs.SubmissionQueue(), "nope")  # type: ignore


class TestAssess(unittest.TestCase):
    def test_graduated_none_escalate_pause(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        a = vs.assess_scarcity(make_queue(7), cap, seq=7)
        self.assertEqual(a.recommended_action, vs.ScarcityAction.NONE)
        self.assertFalse(a.scarce)
        a = vs.assess_scarcity(make_queue(60), cap, seq=60)
        self.assertEqual(a.recommended_action, vs.ScarcityAction.ESCALATE)
        self.assertFalse(a.scarce)
        a = vs.assess_scarcity(make_queue(101), cap, seq=101)
        self.assertEqual(a.recommended_action, vs.ScarcityAction.PAUSE_INTAKE)
        self.assertTrue(a.scarce)

    def test_boundary_belongs_to_calmer_side(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        a = vs.assess_scarcity(make_queue(50), cap, seq=50)  # exactly 5x
        self.assertEqual(a.recommended_action, vs.ScarcityAction.NONE)

    def test_assessment_record_shape(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=4)
        a = vs.assess_scarcity(make_queue(41), cap, seq=41)
        d = a.as_dict()
        self.assertEqual(d["schema"], vs.SCHEMA_PIN)
        self.assertEqual(d["pending"], 41)
        self.assertEqual(d["capacity_per_day"], 4)

    def test_apply_assessment_pauses(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        q = make_queue(101)
        a = vs.assess_scarcity(q, cap, seq=101)
        action = q.apply_assessment(a, seq=101)
        self.assertEqual(action, vs.ScarcityAction.PAUSE_INTAKE)
        self.assertFalse(q.intake_open)

    def test_apply_assessment_escalate_leaves_intake_open(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        q = make_queue(60)
        a = vs.assess_scarcity(q, cap, seq=60)
        q.apply_assessment(a, seq=60)
        self.assertTrue(q.intake_open)  # escalation is the host's job

    def test_audit_event(self):
        cap = vs.ValidatorCapacity(max_reviews_per_day=10)
        a = vs.assess_scarcity(make_queue(101), cap, seq=101)
        ev = vs.scarcity_audit_event(a, seq=102)
        self.assertEqual(ev["audit_seq"], 102)
        self.assertTrue(ev["scarce"])

    def test_main(self):
        vs.main()  # smoke: must not raise


if __name__ == "__main__":
    unittest.main()
