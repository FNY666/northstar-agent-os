"""Tests for memory_flat_vs_graph: flat vs graph retrieval comparison."""
import math
import unittest

from memory_flat_vs_graph import (
    SCHEMA_PIN,
    FlatMemory,
    GraphMemory,
    BenchmarkResult,
    benchmark_both,
    cosine,
    embed,
    f1_at_k,
    recommend,
    main,
)


class EmbedTest(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(embed("the cat sat"), embed("the cat sat"))

    def test_l2_normalized(self):
        v = embed("hello world hello")
        norm = math.sqrt(sum(x * x for x in v))
        self.assertAlmostEqual(norm, 1.0, places=9)

    def test_case_insensitive(self):
        self.assertEqual(embed("Cat"), embed("cat"))

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            embed(123)


class CosineTest(unittest.TestCase):
    def test_self_is_one(self):
        v = embed("some text here")
        self.assertAlmostEqual(cosine(v, v), 1.0, places=9)

    def test_zero_vector_is_zero(self):
        z = embed("!!!")  # no alphanumeric tokens -> zero vector
        self.assertEqual(cosine(z, embed("hello")), 0.0)

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            cosine((1.0, 0.0), (1.0,))


class FlatMemoryTest(unittest.TestCase):
    def test_add_returns_indices(self):
        m = FlatMemory()
        self.assertEqual(m.add("doc one"), 0)
        self.assertEqual(m.add("doc two"), 1)
        self.assertEqual(len(m), 2)

    def test_empty_text_rejected(self):
        m = FlatMemory()
        with self.assertRaises(ValueError):
            m.add("   ")

    def test_retrieve_ranks_best_first(self):
        m = FlatMemory()
        m.add("the cat sat on the mat")
        m.add("quantum field theory")
        hits = m.retrieve("cat", top_k=2)
        self.assertEqual(hits[0].doc_index, 0)
        self.assertGreater(hits[0].score, hits[1].score)

    def test_top_k_validation(self):
        m = FlatMemory()
        m.add("x")
        with self.assertRaises(ValueError):
            m.retrieve("x", top_k=0)
        with self.assertRaises(ValueError):
            m.retrieve("x", top_k=True)


class GraphMemoryTest(unittest.TestCase):
    def test_unknown_edge_index_raises(self):
        g = GraphMemory()
        g.add("node")
        with self.assertRaises(ValueError):
            g.add_edge(0, 5)

    def test_self_loop_raises(self):
        g = GraphMemory()
        g.add("node")
        with self.assertRaises(ValueError):
            g.add_edge(0, 0)

    def test_neighbor_boost_reranks(self):
        # Query matches doc 0 lexically; doc 1 is lexically unrelated but
        # linked to doc 0. With boost, doc 1 outranks a mid-match doc 2.
        g = GraphMemory(boost=2.0)
        g.add("the cat sat on the mat")   # 0: strong match
        g.add("zzz qqq www")              # 1: no match, boosted via edge
        g.add("cat")                      # 2: weak match (single token)
        g.add_edge(0, 1)
        hits = g.retrieve("cat sat mat", top_k=3)
        order = [s.doc_index for s in hits]
        # doc 1 has no lexical match at all, but its boosted score
        # (via linked doc 0) outranks doc 2's weak single-token match.
        self.assertLess(order.index(1), order.index(2))


class F1Test(unittest.TestCase):
    def test_perfect(self):
        p, r, f = f1_at_k([0, 1], {0, 1})
        self.assertAlmostEqual(p, 1.0)
        self.assertAlmostEqual(r, 1.0)
        self.assertAlmostEqual(f, 1.0)

    def test_zero(self):
        p, r, f = f1_at_k([2, 3], {0, 1})
        self.assertEqual((p, r, f), (0.0, 0.0, 0.0))

    def test_empty_retrieved(self):
        self.assertEqual(f1_at_k([], {0}), (0.0, 0.0, 0.0))

    def test_partial(self):
        p, r, f = f1_at_k([0, 2], {0, 1})
        self.assertAlmostEqual(p, 0.5)
        self.assertAlmostEqual(r, 0.5)
        self.assertAlmostEqual(f, 0.5)


class BenchmarkTest(unittest.TestCase):
    def _corpus(self):
        return (
            ["the cat sat on the mat", "nutrition guidelines for pets",
             "mat cleaning instructions"],
            [(0, 1)],
            ["cat food"],
            [{1}],
        )

    def test_runs_and_returns_result(self):
        docs, edges, queries, relevant = self._corpus()
        res = benchmark_both(docs, edges, queries, relevant, top_k=2)
        self.assertIsInstance(res, BenchmarkResult)
        self.assertEqual(res.num_queries, 1)
        self.assertEqual(res.top_k, 2)
        self.assertIn("schema", res.as_dict())
        self.assertEqual(res.as_dict()["schema"], SCHEMA_PIN)

    def test_mismatched_lengths_raise(self):
        docs, edges, queries, relevant = self._corpus()
        with self.assertRaises(ValueError):
            benchmark_both(docs, edges, ["a", "b"], relevant)

    def test_empty_documents_raise(self):
        with self.assertRaises(ValueError):
            benchmark_both([], [], ["q"], [set()])

    def test_empty_queries_raise(self):
        with self.assertRaises(ValueError):
            benchmark_both(["d"], [], [], [])

    def test_out_of_range_relevant_raises(self):
        docs, edges, queries, _ = self._corpus()
        with self.assertRaises(ValueError):
            benchmark_both(docs, edges, queries, [{9}])


class RecommendTest(unittest.TestCase):
    def _res(self, flat_f1, graph_f1):
        return BenchmarkResult(
            flat_f1=flat_f1, graph_f1=graph_f1,
            flat_precision=flat_f1, flat_recall=flat_f1,
            graph_precision=graph_f1, graph_recall=graph_f1,
            num_queries=1, top_k=2,
        )

    def test_flat_wins(self):
        self.assertEqual(recommend(self._res(0.9, 0.4)), "flat")

    def test_graph_wins(self):
        self.assertEqual(recommend(self._res(0.3, 0.8)), "graph")

    def test_tie_goes_flat(self):
        # Selective Forgetting doctrine: the burden of proof is on graph.
        self.assertEqual(recommend(self._res(0.5, 0.5)), "flat")

    def test_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            recommend("flat")

    def test_end_to_end_graph_can_win(self):
        # Query lexically matches doc 0; the answer is doc 1, linked to 0.
        docs = ["the cat sat on the mat", "nutrition guidelines for pets",
                "quantum field theory lecture notes"]
        edges = [(0, 1)]
        res = benchmark_both(docs, edges, ["cat food"], [{1}], top_k=2)
        # Graph's neighbor boost should surface doc 1 above doc 2 here.
        self.assertGreaterEqual(res.graph_f1, res.flat_f1)

    def test_main_runs(self):
        main()


if __name__ == "__main__":
    unittest.main()
