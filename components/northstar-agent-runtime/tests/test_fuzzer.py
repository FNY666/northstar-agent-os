"""Targeted tests for the fuzzer interface."""

import ast
import dataclasses
import threading
import unittest
from pathlib import Path

from fuzzer import (
    Fuzzer,
    FuzzerError,
    UnknownTargetError,
    DuplicateTargetError,
    BadInputError,
    UnknownCrashError,
    NoReproError,
    SeqOrderError,
    TargetRecord,
    SeedInput,
    CrashRecord,
    MinimizedCrash,
    FuzzReport,
    fuzzer_audit_event,
    FUZZER_VERSION,
    FUZZER_SCHEMA,
    AUDIT_KINDS,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "fuzzer.py"


def benign(data: bytes) -> None:
    return None


def crasher(data: bytes) -> None:
    if b"\xde\xad" in data:
        raise ValueError("planted crash")


def magic_crasher(data: bytes) -> None:
    if b"MAGIC" in data:
        raise RuntimeError("magic crash")


def new_fuzzer():
    fz = Fuzzer()
    fz.register_target("t", benign, seq=0)
    return fz


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(FUZZER_VERSION, "fuzzer.v1")
        self.assertEqual(FUZZER_SCHEMA, "northstar.fuzzer.v1")
        for kind in ("target-registered", "seed-added", "dictionary-added",
                     "fuzzed", "reproduced", "minimized", "rejected"):
            self.assertIn(kind, AUDIT_KINDS)


class TestTargets(unittest.TestCase):
    def test_register_roundtrip(self):
        fz = Fuzzer()
        rec = fz.register_target("t1", benign, seq=0)
        self.assertIsInstance(rec, TargetRecord)
        self.assertEqual(rec.target_id, "t1")
        self.assertTrue(rec.digest.startswith("sha256:"))
        # digest is deterministic
        fz2 = Fuzzer()
        rec2 = fz2.register_target("t1", benign, seq=0)
        self.assertEqual(rec.digest, rec2.digest)

    def test_register_duplicate(self):
        fz = Fuzzer()
        fz.register_target("t", benign, seq=0)
        with self.assertRaises(DuplicateTargetError):
            fz.register_target("t", benign, seq=1)

    def test_register_bad_inputs(self):
        fz = Fuzzer()
        with self.assertRaises(BadInputError):
            fz.register_target("", benign, seq=0)
        with self.assertRaises(BadInputError):
            fz.register_target("t", "not-callable", seq=1)
        with self.assertRaises(UnknownTargetError):
            fz.add_seed("nope", b"abc", seq=2)


class TestSeeds(unittest.TestCase):
    def test_add_seed_roundtrip(self):
        fz = new_fuzzer()
        rec = fz.add_seed("t", b"hello", seq=1)
        self.assertIsInstance(rec, SeedInput)
        self.assertEqual(rec.seed_id, "in-1")
        self.assertEqual(rec.size, 5)
        self.assertTrue(rec.input_digest.startswith("sha256:"))
        self.assertEqual(len(fz.corpus("t")), 1)

    def test_add_seed_dedupe_idempotent(self):
        fz = new_fuzzer()
        r1 = fz.add_seed("t", b"hello", seq=1)
        r2 = fz.add_seed("t", b"hello", seq=2)
        self.assertEqual(r1.seed_id, r2.seed_id)
        self.assertEqual(len(fz.corpus("t")), 1)

    def test_add_seed_bad_inputs(self):
        fz = new_fuzzer()
        s = 10
        for bad in (b"", "str", None, 123):
            with self.assertRaises(BadInputError):
                fz.add_seed("t", bad, seq=s)
            s += 1
        with self.assertRaises(BadInputError):
            fz.add_seed("t", b"x" * ((1 << 20) + 1), seq=s)

    def test_add_dictionary(self):
        fz = new_fuzzer()
        n = fz.add_dictionary("t", [b"\xde\xad", b"tok"], seq=1)
        self.assertEqual(n, 2)
        self.assertEqual(fz.stats("t")["dictionary_tokens"], 2)
        # duplicates collapse
        n2 = fz.add_dictionary("t", [b"a", b"a", b"b"], seq=2)
        self.assertEqual(n2, 2)

    def test_add_dictionary_bad(self):
        fz = new_fuzzer()
        with self.assertRaises(BadInputError):
            fz.add_dictionary("t", [], seq=1)
        with self.assertRaises(BadInputError):
            fz.add_dictionary("t", [b""], seq=2)
        with self.assertRaises(BadInputError):
            fz.add_dictionary("t", ["str"], seq=3)
        with self.assertRaises(BadInputError):
            fz.add_dictionary("t", [b"x" * 65], seq=4)


class TestFuzz(unittest.TestCase):
    def test_fuzz_finds_planted_crash(self):
        fz = Fuzzer()
        fz.register_target("t", crasher, seq=0)
        fz.add_seed("t", b"\x00\xde\xad\x00", seq=1)
        report = fz.fuzz("t", seq=2, iterations=50, seed=3)
        self.assertIsInstance(report, FuzzReport)
        self.assertEqual(report.execs, 1 + 50)
        self.assertGreaterEqual(report.new_crashes, 1)
        crashes = fz.crashes("t")
        self.assertEqual(len(crashes), len(set(c.crash_id for c in crashes)))
        self.assertEqual(crashes[0].exc_type, "ValueError")
        self.assertTrue(crashes[0].digest.startswith("sha256:"))

    def test_fuzz_benign_no_crash(self):
        fz = new_fuzzer()
        fz.add_seed("t", b"hello world", seq=1)
        report = fz.fuzz("t", seq=2, iterations=50, seed=9)
        self.assertEqual(report.new_crashes, 0)
        self.assertEqual(len(fz.crashes("t")), 0)
        self.assertEqual(report.execs, 1 + 50)
        self.assertGreater(report.coverage_edges, 0)

    def test_fuzz_deterministic_replay(self):
        def run():
            fz = Fuzzer()
            fz.register_target("t", crasher, seq=0)
            fz.add_seed("t", b"\x00\xde\xad\x00", seq=1)
            fz.add_seed("t", b"other seed", seq=2)
            return fz.fuzz("t", seq=3, iterations=100, seed=42).digest
        self.assertEqual(run(), run())

    def test_fuzz_bad_inputs(self):
        fz = new_fuzzer()
        fz.add_seed("t", b"abc", seq=1)
        s = 2
        with self.assertRaises(UnknownTargetError):
            fz.fuzz("nope", seq=s, iterations=10)
        s += 1
        for bad_iter in (0, -1, True, "10", 1.5):
            with self.assertRaises(BadInputError):
                fz.fuzz("t", seq=s, iterations=bad_iter)
            s += 1
        for bad_seed in (-1, True, "x", 1.5):
            with self.assertRaises(BadInputError):
                fz.fuzz("t", seq=s, seed=bad_seed)
            s += 1
        # empty corpus refused
        fz2 = Fuzzer()
        fz2.register_target("e", benign, seq=0)
        with self.assertRaises(BadInputError):
            fz2.fuzz("e", seq=1, iterations=10)

    def test_fuzz_execs_counts_calibration(self):
        fz = new_fuzzer()
        fz.add_seed("t", b"a", seq=1)
        fz.add_seed("t", b"b", seq=2)
        report = fz.fuzz("t", seq=3, iterations=30, seed=1)
        self.assertEqual(report.execs, 2 + 30)


class TestTriage(unittest.TestCase):
    def _crashing(self):
        fz = Fuzzer()
        fz.register_target("t", magic_crasher, seq=0)
        fz.add_seed("t", b"xxMAGICyy", seq=1)
        fz.fuzz("t", seq=2, iterations=10, seed=5)
        crash_id = fz.crashes("t")[0].crash_id
        return fz, crash_id

    def test_reproduce_true(self):
        fz, crash_id = self._crashing()
        self.assertTrue(fz.reproduce(crash_id, seq=3))

    def test_reproduce_unknown(self):
        fz = new_fuzzer()
        with self.assertRaises(UnknownCrashError):
            fz.reproduce("cr-999", seq=1)

    def test_minimize_shrinks(self):
        fz, crash_id = self._crashing()
        mini = fz.minimize(crash_id, seq=3)
        self.assertIsInstance(mini, MinimizedCrash)
        self.assertLessEqual(mini.minimized_size, mini.original_size)
        self.assertEqual(mini.data, b"MAGIC")
        self.assertIn(b"MAGIC", mini.data)
        # minimized input still reproduces
        self.assertTrue(fz.reproduce(crash_id, seq=4))
        self.assertEqual(fz.minimized_input(crash_id), b"MAGIC")

    def test_minimize_unknown_crash(self):
        fz = new_fuzzer()
        with self.assertRaises(UnknownCrashError):
            fz.minimize("cr-999", seq=1)

    def test_minimize_no_repro(self):
        gate = {"on": True}

        def flaky(data: bytes) -> None:
            if gate["on"] and b"ZZ" in data:
                raise ValueError("flaky")

        fz = Fuzzer()
        fz.register_target("t", flaky, seq=0)
        fz.add_seed("t", b"aZZb", seq=1)
        fz.fuzz("t", seq=2, iterations=5, seed=1)
        crash_id = fz.crashes("t")[0].crash_id
        gate["on"] = False  # target changed under us
        with self.assertRaises(NoReproError):
            fz.minimize(crash_id, seq=3)
        self.assertFalse(fz.reproduce(crash_id, seq=4))

    def test_crash_input_accessor(self):
        fz, crash_id = self._crashing()
        raw = fz.crash_input(crash_id)
        self.assertIsInstance(raw, bytes)
        self.assertIn(b"MAGIC", raw)
        with self.assertRaises(UnknownCrashError):
            fz.crash_input("cr-999")

    def test_crash_dedupe(self):
        fz = Fuzzer()
        fz.register_target("t", crasher, seq=0)
        fz.add_seed("t", b"\xde\xad", seq=1)
        fz.add_seed("t", b"\x00\xde\xad", seq=2)
        fz.fuzz("t", seq=3, iterations=5, seed=1)
        keys = [(c.exc_type, c.input_digest) for c in fz.crashes("t")]
        self.assertEqual(len(keys), len(set(keys)))


class TestSeq(unittest.TestCase):
    def test_seq_strictly_increasing(self):
        fz = Fuzzer()
        fz.register_target("t", benign, seq=0)
        with self.assertRaises(SeqOrderError):
            fz.register_target("u", benign, seq=0)  # rewind
        with self.assertRaises(SeqOrderError):
            fz.add_seed("t", b"x", seq=True)
        with self.assertRaises(SeqOrderError):
            fz.add_seed("t", b"x", seq=-1)
        with self.assertRaises(SeqOrderError):
            fz.add_seed("t", b"x", seq="1")

    def test_failed_mutation_consumes_seq(self):
        fz = new_fuzzer()
        with self.assertRaises(BadInputError):
            fz.add_seed("t", b"", seq=1)  # fails, but consumes 1
        with self.assertRaises(SeqOrderError):
            fz.add_seed("t", b"ok", seq=1)  # already consumed
        rec = fz.add_seed("t", b"ok", seq=2)
        self.assertEqual(rec.seed_id, "in-1")


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in AUDIT_KINDS:
            ev = fuzzer_audit_event(kind, 7, {"target_id": "t"})
            self.assertEqual(ev["schema"], "northstar.audit.ndjson/1")
            self.assertEqual(ev["module"], FUZZER_VERSION)
            self.assertEqual(ev["event"], kind)
            self.assertEqual(ev["audit_seq"], 7)
            self.assertEqual(ev["target_id"], "t")

    def test_audit_rejections(self):
        with self.assertRaises(FuzzerError):
            fuzzer_audit_event("bogus-kind", 0, {})
        with self.assertRaises(FuzzerError):
            fuzzer_audit_event("fuzzed", 0, {"raw": b"bytes-not-allowed"})
        with self.assertRaises(SeqOrderError):
            fuzzer_audit_event("fuzzed", -1, {})
        with self.assertRaises(FuzzerError):
            fuzzer_audit_event("fuzzed", 0, "not-a-dict")


class TestViews(unittest.TestCase):
    def test_stats_and_views(self):
        fz = Fuzzer()
        fz.register_target("t", benign, seq=0)
        fz.add_seed("t", b"abc", seq=1)
        st = fz.stats("t")
        self.assertEqual(st["corpus_size"], 1)
        self.assertEqual(st["crash_count"], 0)
        self.assertGreater(st["coverage_edges"], 0)
        self.assertEqual(st["execs"], 0)
        with self.assertRaises(UnknownTargetError):
            fz.stats("nope")
        with self.assertRaises(UnknownTargetError):
            fz.corpus("nope")
        self.assertEqual(fz.crashes(), ())

    def test_frozen_records(self):
        fz = new_fuzzer()
        rec = fz.add_seed("t", b"abc", seq=1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rec.size = 999  # type: ignore[misc]


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "math", "random",
            "threading", "dataclasses", "typing", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestConcurrency(unittest.TestCase):
    def test_concurrent_seed_adds(self):
        fz = new_fuzzer()
        lock = threading.Lock()
        counter = {"n": 10}

        def worker(i):
            with lock:
                counter["n"] += 1
                s = counter["n"]
            fz.add_seed("t", f"seed-{i}".encode(), seq=s)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        ids = [r.seed_id for r in fz.corpus("t")]
        self.assertEqual(len(ids), len(set(ids)))


class TestMain(unittest.TestCase):
    def test_main(self):
        import fuzzer as mod
        mod.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
