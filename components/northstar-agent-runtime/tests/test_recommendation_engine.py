"""Tests for recommendation_engine: 17 cases."""

import ast
import math
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from recommendation_engine import (
    RECOMMENDATION_ENGINE_VERSION,
    RECOMMENDATION_ENGINE_SCHEMA,
    AUDIT_SCHEMA,
    METHODS,
    BadInputError,
    DuplicateInteractionError,
    EvaluationError,
    RecommendationEngine,
    RecommendationError,
    SeqOrderError,
    TrainingError,
    UnknownUserError,
    recommendation_engine_audit_event,
)


def make_engine():
    return RecommendationEngine()


def train_sample(engine, start_seq=1):
    """Books the usercf fixture; returns the next free seq."""
    data = [("u1", "i1", 5), ("u1", "i2", 3),
            ("u2", "i1", 4), ("u2", "i2", 2), ("u2", "i3", 5),
            ("u3", "i1", 1), ("u3", "i2", 5)]
    seq = start_seq
    for user_id, item_id, rating in data:
        engine.add_interaction(user_id, item_id, rating, seq)
        seq += 1
    engine.train(seq)
    return seq + 1


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(RECOMMENDATION_ENGINE_VERSION,
                         "recommendation-engine.v1")
        self.assertEqual(RECOMMENDATION_ENGINE_SCHEMA,
                         "northstar.recommendation-engine.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(METHODS, ("usercf", "itemcf", "popular"))

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "recommendation_engine.py")
        tree = ast.parse(open(path).read())
        allowed = {"__future__", "hashlib", "json", "math", "threading",
                   "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestInteractions(unittest.TestCase):
    def test_add_interaction_roundtrip(self):
        engine = make_engine()
        rec = engine.add_interaction("u1", "i1", 5, 1)
        self.assertEqual(rec.interaction_id, "ixn-1")
        self.assertEqual(rec.user_id, "u1")
        self.assertEqual(rec.item_id, "i1")
        self.assertEqual(rec.rating, 5.0)
        self.assertEqual(rec.seq, 1)
        self.assertTrue(rec.verify())

    def test_add_bad_inputs(self):
        engine = make_engine()
        seq = 0
        bad = [("", "i1", 3), ("u1", "", 3), ("u1", "i1", -1),
               ("u1", "i1", 5.5), ("u1", "i1", float("nan")),
               ("u1", "i1", float("inf")), ("u1", "i1", "3"),
               ("u1", "i1", None), ("u1", "i1", True)]
        for user_id, item_id, rating in bad:
            seq += 1
            with self.assertRaises(BadInputError):
                engine.add_interaction(user_id, item_id, rating, seq)

    def test_seq_discipline(self):
        engine = make_engine()
        engine.add_interaction("u1", "i1", 3, 1)
        for bad_seq in (True, 0, -1, 1):  # bool, negative, rewind
            with self.assertRaises(SeqOrderError):
                engine.add_interaction("u2", "i2", 3, bad_seq)

    def test_failed_mutation_consumes_seq(self):
        engine = make_engine()
        engine.add_interaction("u1", "i1", 3, 1)
        with self.assertRaises(BadInputError):
            engine.add_interaction("u1", "i2", 99, 2)  # bad rating, seq 2 burned
        with self.assertRaises(SeqOrderError):
            engine.add_interaction("u1", "i2", 3, 2)  # seq 2 already consumed
        rec = engine.add_interaction("u1", "i2", 3, 3)
        self.assertEqual(rec.seq, 3)

    def test_duplicate_interaction_refused(self):
        engine = make_engine()
        engine.add_interaction("u1", "i1", 3, 1)
        with self.assertRaises(DuplicateInteractionError):
            engine.add_interaction("u1", "i1", 4, 2)


class TestTrain(unittest.TestCase):
    def test_train_empty_refused(self):
        engine = make_engine()
        with self.assertRaises(TrainingError):
            engine.train(1)

    def test_train_snapshot(self):
        engine = make_engine()
        train_sample(engine)
        snapshot = engine._model
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.n_users, 3)
        self.assertEqual(snapshot.n_items, 3)
        self.assertEqual(snapshot.n_interactions, 7)
        self.assertTrue(snapshot.verify())
        # popularity: i1 and i2 have 3 interactions, i3 has 1; tie broken
        # by mean desc then item id asc.
        self.assertEqual([i for i, _ in snapshot.popularity],
                         ["i1", "i2", "i3"])


class TestRecommend(unittest.TestCase):
    def test_recommend_usercf_exact(self):
        engine = make_engine()
        seq = train_sample(engine)
        recs = engine.recommend("u1", seq, top_n=5, method="usercf")
        self.assertTrue(recs.verify())
        self.assertEqual(recs.item_ids(), ("i3",))
        # u1's only positive-similarity neighbor is u2, who rated i3=5,
        # so the weighted average collapses to 5.0.
        self.assertAlmostEqual(recs.recommendations[0].score, 5.0, places=9)
        self.assertEqual(recs.recommendations[0].rank, 1)
        self.assertEqual(recs.method, "usercf")
        self.assertEqual(recs.top_n, 5)

    def test_recommend_excludes_seen(self):
        engine = make_engine()
        seq = train_sample(engine)
        recs = engine.recommend("u2", seq, top_n=5, method="usercf")
        # u2 has seen everything; nothing is rankable.
        self.assertEqual(recs.item_ids(), ())

    def test_recommend_itemcf_fallback_user_mean(self):
        engine = make_engine()
        seq = train_sample(engine)
        recs = engine.recommend("u1", seq, top_n=5, method="itemcf")
        self.assertEqual(recs.item_ids(), ("i3",))
        # i3 shares no positive item similarity with u1's seen items
        # (its only rater's centered rating is 0), so the score falls
        # back to u1's mean: (5 + 3) / 2 = 4.0.
        self.assertEqual(recs.recommendations[0].score, 4.0)

    def test_recommend_popular_order_and_cold_start(self):
        engine = make_engine()
        seq = train_sample(engine)
        recs = engine.recommend("u1", seq, top_n=5, method="popular")
        self.assertEqual(recs.item_ids(), ("i3",))  # only unseen item
        cold = engine.recommend("ghost", seq + 1, top_n=5, method="popular")
        self.assertEqual(cold.item_ids(), ("i1", "i2", "i3"))

    def test_recommend_unknown_user(self):
        engine = make_engine()
        seq = train_sample(engine)
        with self.assertRaises(UnknownUserError):
            engine.recommend("ghost", seq, method="usercf")
        with self.assertRaises(UnknownUserError):
            engine.recommend("ghost", seq, method="itemcf")

    def test_recommend_bad_inputs(self):
        engine = make_engine()
        seq = train_sample(engine)
        with self.assertRaises(BadInputError):
            engine.recommend("u1", seq, method="matrix-factorization")
        with self.assertRaises(BadInputError):
            engine.recommend("u1", seq, top_n=0)
        with self.assertRaises(BadInputError):
            engine.recommend("u1", seq, top_n=51)
        with self.assertRaises(BadInputError):
            engine.recommend("", seq)
        with self.assertRaises(SeqOrderError):
            engine.recommend("u1", -1)

    def test_recommend_concurrent_reads(self):
        engine = make_engine()
        seq = train_sample(engine)
        results = []
        errors = []

        def worker():
            try:
                results.append(
                    engine.recommend("u1", seq, top_n=3, method="usercf"))
            except Exception as exc:  # pragma: no cover - diagnostic
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r.item_ids() == ("i3",) for r in results))


class TestEvaluate(unittest.TestCase):
    def test_evaluate_metrics(self):
        engine = make_engine()
        seq = 1
        data = [("u1", "i1", 5), ("u1", "i2", 3),
                ("u2", "i1", 4), ("u2", "i2", 2), ("u2", "i3", 4),
                ("u3", "i1", 2), ("u3", "i2", 4), ("u3", "i3", 1)]
        for user_id, item_id, rating in data:
            engine.add_interaction(user_id, item_id, rating, seq)
            seq += 1
        engine.train(seq)
        seq += 1
        report = engine.evaluate(seq, [("u1", "i3", 5.0)], top_k=2)
        self.assertTrue(report.verify())
        self.assertEqual(report.n_held_out, 1)
        self.assertEqual(report.n_scored, 1)
        self.assertEqual(report.n_skipped, 0)
        # u1's only positive neighbor is u2 (rated i3=4) -> pred 4.0,
        # actual 5.0 -> squared error 1.0 -> rmse 1.0.
        self.assertAlmostEqual(report.rmse, 1.0, places=9)
        # u1's top-2 contains exactly the one relevant held-out item.
        self.assertAlmostEqual(report.precision_at_k, 0.5, places=9)
        self.assertAlmostEqual(report.recall_at_k, 1.0, places=9)

    def test_evaluate_skips_unknown_and_empty_refused(self):
        engine = make_engine()
        seq = train_sample(engine)
        report = engine.evaluate(seq, [("ghost", "i1", 5.0)], top_k=2)
        self.assertEqual(report.n_scored, 0)
        self.assertEqual(report.n_skipped, 1)
        self.assertIsNone(report.rmse)
        self.assertEqual(report.precision_at_k, 0.0)
        self.assertEqual(report.recall_at_k, 0.0)
        with self.assertRaises(EvaluationError):
            engine.evaluate(seq + 1, [], top_k=2)
        with self.assertRaises(EvaluationError):
            engine.evaluate(seq + 2, [("u1",)], top_k=2)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_bad_kind(self):
        engine = make_engine()
        seq = train_sample(engine)
        log = engine.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertIn("interaction-added", kinds)
        self.assertIn("trained", kinds)
        for event in log:
            self.assertEqual(event["schema"], "audit.ndjson/1")
            self.assertEqual(event["module"], "recommendation_engine")
            self.assertEqual(event["moduleVersion"],
                             "recommendation-engine.v1")
        recs = engine.recommend("u1", seq, method="usercf")
        self.assertEqual(engine.audit_log()[-1]["kind"], "recommended")
        # raw ratings never cross the audit boundary
        self.assertNotIn("rating", engine.audit_log()[-1]["detail"])
        with self.assertRaises(RecommendationError):
            recommendation_engine_audit_event("nope", 1)

    def test_main_self_check(self):
        import recommendation_engine as mod
        mod.main()


if __name__ == "__main__":
    unittest.main()
