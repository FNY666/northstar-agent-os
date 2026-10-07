"""Tests for recursive_reward.py (targeted, 26 tests)."""

import dataclasses
import unittest

from recursive_reward import (
    CONFIDENCE_SMOOTHING,
    LEARNING_RATE,
    RECURSIVE_REWARD_VERSION,
    REWARD_SCHEMA,
    ActionFeatures,
    DecompositionEstimate,
    HumanFeedback,
    RecursiveRewardEstimator,
    RewardError,
    RewardModel,
    RewardPrediction,
    main,
    reward_audit_event,
)


def feats(**kwargs):
    return ActionFeatures(kwargs)


class VersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(RECURSIVE_REWARD_VERSION, "recursive-reward.v1")

    def test_schema_pin(self):
        self.assertEqual(REWARD_SCHEMA, "northstar.recursive-reward.v1")


class ActionFeaturesValidation(unittest.TestCase):
    def test_empty_rejected(self):
        with self.assertRaises(RewardError):
            ActionFeatures({})

    def test_empty_name_rejected(self):
        with self.assertRaises(RewardError):
            ActionFeatures({"": 1.0})

    def test_nan_rejected(self):
        with self.assertRaises(RewardError):
            ActionFeatures({"x": float("nan")})

    def test_inf_rejected(self):
        with self.assertRaises(RewardError):
            ActionFeatures({"x": float("inf")})

    def test_bool_rejected(self):
        with self.assertRaises(RewardError):
            ActionFeatures({"x": True})

    def test_duplicate_name_rejected(self):
        with self.assertRaises(RewardError):
            ActionFeatures([("x", 1.0), ("x", 2.0)])

    def test_canonical_sorted(self):
        f = ActionFeatures({"b": 1.0, "a": 2.0})
        self.assertEqual(f.names(), ("a", "b"))

    def test_frozen(self):
        f = feats(x=1.0)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            f.schema = "other"  # type: ignore[misc]


class FeedbackValidation(unittest.TestCase):
    def test_both_shapes_rejected(self):
        with self.assertRaises(RewardError):
            HumanFeedback(
                "fb", 1, preferred=feats(x=1.0), other=feats(x=0.0),
                action=feats(x=1.0), rating=0.5,
            )

    def test_neither_shape_rejected(self):
        with self.assertRaises(RewardError):
            HumanFeedback("fb", 1)

    def test_rating_out_of_range_rejected(self):
        with self.assertRaises(RewardError):
            HumanFeedback("fb", 1, action=feats(x=1.0), rating=1.5)

    def test_negative_seq_rejected(self):
        with self.assertRaises(RewardError):
            HumanFeedback("fb", -1, action=feats(x=1.0), rating=0.5)

    def test_pairwise_flag(self):
        fb = HumanFeedback("fb", 1, preferred=feats(x=1.0), other=feats(x=0.0))
        self.assertTrue(fb.is_pairwise)


class RewardModelLearning(unittest.TestCase):
    def test_predict_before_training_is_zero_extrapolating(self):
        model = RewardModel()
        prediction = model.predict_reward(feats(x=1.0))
        self.assertEqual(prediction.score, 0.0)
        self.assertEqual(prediction.confidence, 0.0)
        self.assertTrue(prediction.extrapolating)

    def test_pairwise_update_prefers_winner(self):
        model = RewardModel()
        good = feats(helpful=1.0, risky=0.0)
        bad = feats(helpful=0.0, risky=1.0)
        model.train_step(HumanFeedback("fb-1", 1, preferred=good, other=bad))
        self.assertGreater(model.predict_reward(good).score, model.predict_reward(bad).score)

    def test_scalar_update_moves_toward_rating(self):
        model = RewardModel()
        action = feats(x=1.0)
        model.train_step(HumanFeedback("fb-1", 1, action=action, rating=0.8))
        before = model.predict_reward(action).score
        model.train_step(HumanFeedback("fb-2", 2, action=action, rating=0.8))
        after = model.predict_reward(action).score
        self.assertGreater(after, before)
        self.assertLessEqual(after, 0.8)

    def test_confidence_grows_with_coverage(self):
        model = RewardModel()
        action = feats(x=1.0)
        model.train_step(HumanFeedback("fb-1", 1, action=action, rating=0.5))
        low = model.predict_reward(action).confidence
        for i in range(2, 12):
            model.train_step(HumanFeedback(f"fb-{i}", i, action=action, rating=0.5))
        high = model.predict_reward(action).confidence
        self.assertGreater(high, low)
        expected = 11 / (11 + CONFIDENCE_SMOOTHING)
        self.assertAlmostEqual(high, expected)

    def test_partial_extrapolation_flag(self):
        model = RewardModel()
        model.train_step(HumanFeedback("fb-1", 1, action=feats(x=1.0), rating=0.5))
        prediction = model.predict_reward(ActionFeatures({"x": 1.0, "y": 2.0}))
        self.assertTrue(prediction.extrapolating)
        self.assertEqual(prediction.confidence, 0.0)

    def test_duplicate_seq_rejected(self):
        model = RewardModel()
        fb = HumanFeedback("fb-1", 1, action=feats(x=1.0), rating=0.5)
        model.train_step(fb)
        with self.assertRaises(RewardError):
            model.train_step(HumanFeedback("fb-2", 1, action=feats(x=1.0), rating=0.5))

    def test_non_feedback_rejected(self):
        model = RewardModel()
        with self.assertRaises(RewardError):
            model.train_step("not feedback")

    def test_score_clipped(self):
        model = RewardModel()
        action = feats(x=100.0)
        for i in range(20):
            model.train_step(HumanFeedback(f"fb-{i}", i, action=action, rating=1.0))
        self.assertLessEqual(model.predict_reward(action).score, 1.0)

    def test_feedback_log_append_only(self):
        model = RewardModel()
        fb = HumanFeedback("fb-1", 1, action=feats(x=1.0), rating=0.5)
        model.train_step(fb)
        self.assertEqual(model.feedback_log(), (fb,))


class RecursiveEstimator(unittest.TestCase):
    def _trained(self):
        model = RewardModel()
        model.train_step(HumanFeedback("fb-1", 1, action=feats(good=1.0), rating=0.8))
        model.train_step(HumanFeedback("fb-2", 2, action=feats(good=1.0), rating=0.8))
        return model

    def test_leaf_matches_model(self):
        model = self._trained()
        estimator = RecursiveRewardEstimator(model)
        estimator.register_leaf("task-a", feats(good=1.0))
        estimate = estimator.estimate("task-a")
        self.assertTrue(estimate.leaf)
        self.assertAlmostEqual(estimate.score, model.predict_reward(feats(good=1.0)).score)

    def test_composite_mean_and_min_confidence(self):
        model = self._trained()
        estimator = RecursiveRewardEstimator(model)
        estimator.register_leaf("leaf-a", feats(good=1.0))
        estimator.register_leaf("leaf-b", feats(bad=1.0))
        estimator.register_decomposition("parent", ("leaf-a", "leaf-b"))
        estimate = estimator.estimate("parent")
        self.assertFalse(estimate.leaf)
        score_a = estimator.estimate("leaf-a").score
        score_b = estimator.estimate("leaf-b").score
        self.assertAlmostEqual(estimate.score, (score_a + score_b) / 2)
        conf_a = estimator.estimate("leaf-a").confidence
        conf_b = estimator.estimate("leaf-b").confidence
        self.assertAlmostEqual(estimate.confidence, min(conf_a, conf_b))

    def test_three_level_nesting(self):
        model = self._trained()
        estimator = RecursiveRewardEstimator(model)
        estimator.register_leaf("l1", feats(good=1.0))
        estimator.register_leaf("l2", feats(good=1.0))
        estimator.register_decomposition("mid", ("l1", "l2"))
        estimator.register_decomposition("top", ("mid",))
        top = estimator.estimate("top")
        self.assertAlmostEqual(top.score, estimator.estimate("mid").score)
        self.assertAlmostEqual(top.confidence, estimator.estimate("mid").confidence)

    def test_unknown_task_raises(self):
        estimator = RecursiveRewardEstimator(RewardModel())
        with self.assertRaises(RewardError):
            estimator.estimate("nope")

    def test_duplicate_registration_rejected(self):
        estimator = RecursiveRewardEstimator(RewardModel())
        estimator.register_leaf("t", feats(x=1.0))
        with self.assertRaises(RewardError):
            estimator.register_leaf("t", feats(x=2.0))

    def test_self_decomposition_rejected(self):
        estimator = RecursiveRewardEstimator(RewardModel())
        with self.assertRaises(RewardError):
            estimator.register_decomposition("t", ("t",))

    def test_cycle_rejected(self):
        estimator = RecursiveRewardEstimator(RewardModel())
        estimator.register_leaf("a", feats(x=1.0))
        estimator.register_decomposition("b", ("a",))
        with self.assertRaises(RewardError):
            estimator.register_decomposition("a", ("b",))

    def test_one_unevaluated_leaf_taints_parent(self):
        model = self._trained()
        estimator = RecursiveRewardEstimator(model)
        estimator.register_leaf("rated", feats(good=1.0))
        estimator.register_leaf("unrated", feats(never_seen=1.0))
        estimator.register_decomposition("parent", ("rated", "unrated"))
        estimate = estimator.estimate("parent")
        self.assertEqual(estimate.confidence, 0.0)


class AuditEvent(unittest.TestCase):
    def test_shape(self):
        event = reward_audit_event("estimate", "task-1", 0.5, 0.7, 3)
        self.assertEqual(event["type"], "audit.ndjson/1")
        self.assertEqual(event["kind"], "reward.estimate")
        self.assertEqual(event["module"], RECURSIVE_REWARD_VERSION)
        self.assertEqual(event["schema"], REWARD_SCHEMA)

    def test_confidence_bounds_enforced(self):
        with self.assertRaises(RewardError):
            reward_audit_event("estimate", "task-1", 0.5, 1.5, 3)

    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
