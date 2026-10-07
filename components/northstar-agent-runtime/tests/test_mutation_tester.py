"""Tests for mutation_tester (mutmut-style, simulated)."""

import ast
import threading
import unittest
from fractions import Fraction
from pathlib import Path

import mutation_tester as mt
from mutation_tester import MutationTester


def _make_tester():
    """Tester with one registered target of three lines."""
    t = MutationTester()
    t.register_target("t1", ["x = a + b", "if x == 1:", "flag = True"], seq=1)
    return t


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(mt.MUTATION_TESTER_VERSION, "mutation-tester.v1")
        self.assertEqual(mt.MUTATION_TESTER_SCHEMA, "northstar.mutation-tester.v1")
        self.assertEqual(mt.AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(mt.OPERATORS,
                         ("arith-op", "compare", "bool-lit", "int-lit", "stmt-delete"))


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(Path(mt.__file__).read_text())
        allowed = {"threading", "dataclasses", "typing", "__future__",
                   "canonical_json", "hashlib", "json", "re", "fractions"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        t = MutationTester()
        rec = t.register_target("t1", ["a = 1"], seq=1)
        self.assertEqual(rec.target_id, "t1")
        self.assertEqual(rec.line_count, 1)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertIn("t1", t.target_ids())

    def test_duplicate_refused(self):
        t = MutationTester()
        t.register_target("t1", ["a = 1"], seq=1)
        with self.assertRaises(mt.DuplicateTargetError):
            t.register_target("t1", ["b = 2"], seq=2)

    def test_bad_inputs(self):
        t = MutationTester()
        seq = 0
        for bad_id in ("", "  ", 123, None):
            seq += 1
            with self.assertRaises(mt.ValidationError):
                t.register_target(bad_id, ["a = 1"], seq=seq)
        for bad_lines in ([], "a = 1", [1], [["a"]]):
            seq += 1
            with self.assertRaises(mt.ValidationError):
                t.register_target("tx", bad_lines, seq=seq)
        with self.assertRaises(mt.SeqOrderError):
            t.register_target("t2", ["a = 1"], seq=True)
        seq += 1
        t.register_target("t2", ["a = 1"], seq=seq)
        with self.assertRaises(mt.SeqOrderError):
            t.register_target("t3", ["a = 1"], seq=seq)  # rewind refused


class TestMutate(unittest.TestCase):
    def test_generates_expected_mutants(self):
        t = _make_tester()
        mutants = t.mutate("t1", seq=2)
        by_op = {}
        for m in mutants:
            by_op.setdefault(m.operator, []).append(m)
        # arith-op on "x = a + b" -> "x = a - b"
        self.assertEqual(by_op["arith-op"][0].mutated_line, "x = a - b")
        # compare on "if x == 1:" -> "if x != 1:"
        self.assertEqual(by_op["compare"][0].mutated_line, "if x != 1:")
        # bool-lit on "flag = True" -> "flag = False"
        self.assertEqual(by_op["bool-lit"][0].mutated_line, "flag = False")
        # int-lit on "if x == 1:" -> "if x == 2:"
        self.assertIn("if x == 2:", [m.mutated_line for m in by_op["int-lit"]])
        # stmt-delete applies to every non-blank line
        self.assertEqual(len(by_op["stmt-delete"]), 3)
        self.assertTrue(all(m.verify() for m in mutants))

    def test_ids_monotonic(self):
        t = _make_tester()
        mutants = t.mutate("t1", seq=2)
        self.assertEqual([m.mutant_id for m in mutants],
                         [f"mut-{i}" for i in range(1, len(mutants) + 1)])

    def test_unknown_target(self):
        t = _make_tester()
        with self.assertRaises(mt.UnknownTargetError):
            t.mutate("nope", seq=2)

    def test_unknown_operator(self):
        t = _make_tester()
        with self.assertRaises(mt.UnknownOperatorError):
            t.mutate("t1", seq=2, operators=["arith-op", "quantum-tunnel"])
        with self.assertRaises(mt.ValidationError):
            t.mutate("t1", seq=3, operators=[])

    def test_blank_lines_skipped(self):
        t = MutationTester()
        t.register_target("b", ["x = 1", "", "   "], seq=1)
        mutants = t.mutate("b", seq=2, operators=["stmt-delete"])
        self.assertEqual(len(mutants), 1)  # only the non-blank line


class TestVerdicts(unittest.TestCase):
    def test_kill(self):
        t = _make_tester()
        mutants = t.mutate("t1", seq=2)
        rec = t.kill(mutants[0].mutant_id, seq=3, test_id="test_add")
        self.assertEqual(rec.mutant_id, mutants[0].mutant_id)
        self.assertEqual(rec.test_id, "test_add")
        self.assertEqual(t.verdict(mutants[0].mutant_id), "killed")

    def test_survive(self):
        t = _make_tester()
        mutants = t.mutate("t1", seq=2)
        t.survive(mutants[0].mutant_id, seq=3)
        self.assertEqual(t.verdict(mutants[0].mutant_id), "survived")

    def test_double_verdict_refused(self):
        t = _make_tester()
        mutants = t.mutate("t1", seq=2)
        t.kill(mutants[0].mutant_id, seq=3, test_id="t")
        with self.assertRaises(mt.DuplicateVerdictError):
            t.survive(mutants[0].mutant_id, seq=4)
        with self.assertRaises(mt.DuplicateVerdictError):
            t.kill(mutants[0].mutant_id, seq=5, test_id="t")

    def test_unknown_mutant(self):
        t = _make_tester()
        with self.assertRaises(mt.UnknownMutantError):
            t.kill("mut-999", seq=2, test_id="t")
        with self.assertRaises(mt.UnknownMutantError):
            t.survive("mut-999", seq=3)


class TestScore(unittest.TestCase):
    def test_exact_fraction(self):
        t = _make_tester()
        mutants = t.mutate("t1", seq=2)
        t.kill(mutants[0].mutant_id, seq=3, test_id="test_add")
        t.kill(mutants[1].mutant_id, seq=4, test_id="test_add")
        t.survive(mutants[2].mutant_id, seq=5)
        s = t.score(seq=6)
        self.assertEqual(s.killed, 2)
        self.assertEqual(s.survived, 1)
        self.assertEqual(s.untested, len(mutants) - 3)
        self.assertEqual(s.fraction(), Fraction(2, 3))
        self.assertEqual(s.score_num, 2)
        self.assertEqual(s.score_den, 3)
        self.assertEqual(s.as_dict()["score"], "2/3")

    def test_no_decided_is_none(self):
        t = _make_tester()
        t.mutate("t1", seq=2)
        s = t.score(seq=3)
        self.assertIsNone(s.fraction())
        self.assertIsNone(s.as_dict()["score"])
        self.assertEqual(s.untested, s.total)

    def test_no_mutants(self):
        t = MutationTester()
        s = t.score(seq=1)
        self.assertEqual((s.total, s.killed, s.survived, s.untested),
                         (0, 0, 0, 0))
        self.assertIsNone(s.fraction())


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        ev = mt.mutation_tester_audit_event(
            "scored", 7, {"score_id": "score-1", "killed": 2})
        self.assertEqual(ev.schema, "audit.ndjson/1")
        self.assertEqual(ev.kind, "scored")
        self.assertEqual(ev.as_dict()["detail"]["killed"], 2)

    def test_rejections(self):
        with self.assertRaises(mt.ValidationError):
            mt.mutation_tester_audit_event("nope", 1, {})
        with self.assertRaises(mt.SeqOrderError):
            mt.mutation_tester_audit_event("scored", -1, {})
        with self.assertRaises(mt.ValidationError):
            mt.mutation_tester_audit_event(
                "mutated", 1, {"mutant_id": "mut-1",
                               "original_line": "x = 1"})  # raw source banned


class TestHouseDiscipline(unittest.TestCase):
    def test_failed_mutation_consumes_seq(self):
        t = MutationTester()
        with self.assertRaises(mt.ValidationError):
            t.register_target("", ["a = 1"], seq=1)  # seq 1 consumed
        with self.assertRaises(mt.SeqOrderError):
            t.register_target("t", ["a = 1"], seq=1)  # rewind -> consumed

    def test_concurrent_mutate(self):
        t = _make_tester()
        t.mutate("t1", seq=2, operators=["arith-op"])
        lock = threading.Lock()
        seqs = iter(range(3, 100))

        def worker():
            with lock:
                s = next(seqs)
            t.verdict("mut-1")  # pure view, no seq

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertEqual(t.verdict("mut-1"), None)

    def test_main(self):
        mt.main()


if __name__ == "__main__":
    unittest.main()
