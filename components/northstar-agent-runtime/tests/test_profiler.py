"""Tests for the profiler interface (pprof-style sampling bookkeeping)."""

import ast
import threading
import unittest
from pathlib import Path

from profiler import (
    PROFILER_VERSION,
    SCHEMA_PIN,
    FrameStats,
    Flamegraph,
    LifecycleError,
    Profiler,
    ProfilerError,
    ProfileReport,
    profiler_audit_event,
)


class VersionPinsTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PROFILER_VERSION, "profiler.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.profiler.v1")

    def test_report_carries_pins(self):
        p = Profiler("s")
        p.start(0)
        r = p.stop(1)
        self.assertEqual(r.version, PROFILER_VERSION)
        self.assertEqual(r.schema, SCHEMA_PIN)


class SessionLifecycleTest(unittest.TestCase):
    def test_start_stop_roundtrip(self):
        p = Profiler("s")
        self.assertFalse(p.is_running())
        p.start(1)
        self.assertTrue(p.is_running())
        r = p.stop(2)
        self.assertFalse(p.is_running())
        self.assertIsInstance(r, ProfileReport)

    def test_double_start_refused(self):
        p = Profiler("s")
        p.start(1)
        with self.assertRaises(LifecycleError):
            p.start(2)

    def test_record_without_start_refused(self):
        p = Profiler("s")
        with self.assertRaises(LifecycleError):
            p.record(["main"], 1)

    def test_stop_without_start_refused(self):
        p = Profiler("s")
        with self.assertRaises(LifecycleError):
            p.stop(1)

    def test_record_after_stop_refused(self):
        p = Profiler("s")
        p.start(1)
        p.stop(2)
        with self.assertRaises(LifecycleError):
            p.record(["main"], 3)

    def test_empty_session_id_refused(self):
        for bad in ("", None, 123, True):
            with self.assertRaises(ProfilerError):
                Profiler(bad)

    def test_sessions_isolated(self):
        a, b = Profiler("a"), Profiler("b")
        a.start(1)
        a.record(["main", "x"], 2)
        a.stop(3)
        # b never ran: its reports are empty and it never sees a's data.
        self.assertEqual(b.reports(), ())


class AggregationTest(unittest.TestCase):
    def _profile(self):
        p = Profiler("s")
        p.start(1)
        p.record(["main", "serve", "handle"], 2)
        p.record(["main", "serve", "handle"], 3)
        p.record(["main", "serve", "encode"], 4)
        p.record(["main", "idle"], 5)
        return p.stop(6)

    def test_total_samples(self):
        self.assertEqual(self._profile().total_samples, 4)

    def test_self_vs_cumulative(self):
        by_frame = {f.frame: f for f in self._profile().frame_stats}
        self.assertEqual(by_frame["handle"].self_samples, 2)
        self.assertEqual(by_frame["handle"].cumulative_samples, 2)
        self.assertEqual(by_frame["serve"].self_samples, 0)
        self.assertEqual(by_frame["serve"].cumulative_samples, 3)
        self.assertEqual(by_frame["main"].cumulative_samples, 4)

    def test_frames_sorted(self):
        frames = [f.frame for f in self._profile().frame_stats]
        self.assertEqual(frames, sorted(frames))

    def test_digest_deterministic(self):
        r1, r2 = self._profile(), self._profile()
        self.assertEqual(r1.record_digest(), r2.record_digest())

    def test_digest_content_bound(self):
        r1 = self._profile()
        p = Profiler("s")
        p.start(1)
        p.record(["main", "serve", "other"], 2)
        r2 = p.stop(3)
        self.assertNotEqual(r1.record_digest(), r2.record_digest())

    def test_top_frames(self):
        top = self._profile().top_frames(2)
        self.assertEqual([f.frame for f in top], ["main", "serve"])

    def test_frozen_records(self):
        r = self._profile()
        with self.assertRaises(AttributeError):
            r.total_samples = 99  # type: ignore[misc]
        f = r.frame_stats[0]
        with self.assertRaises(AttributeError):
            f.self_samples = 99  # type: ignore[misc]


class FlamegraphTest(unittest.TestCase):
    def test_folded_lines(self):
        p = Profiler("s")
        p.start(1)
        p.record(["main", "serve", "handle"], 2)
        p.record(["main", "serve", "handle"], 3)
        p.record(["main", "serve", "encode"], 4)
        p.stop(5)
        fg = p.flamegraph()
        self.assertIsInstance(fg, Flamegraph)
        self.assertEqual(fg.lines, ("main;serve;encode 1", "main;serve;handle 2"))
        self.assertEqual(fg.total_samples, 3)

    def test_explicit_report_ok(self):
        p = Profiler("s")
        p.start(1)
        p.record(["a", "b"], 2)
        r = p.stop(3)
        fg = p.flamegraph(report=r)
        self.assertEqual(fg.lines, ("a;b 1",))

    def test_stale_report_refused(self):
        p = Profiler("s")
        p.start(1)
        p.record(["a"], 2)
        r1 = p.stop(3)
        p.start(4)
        p.record(["z"], 5)
        p.stop(6)
        with self.assertRaises(ProfilerError):
            p.flamegraph(report=r1)

    def test_flamegraph_digest_deterministic(self):
        def build():
            p = Profiler("s")
            p.start(1)
            p.record(["a", "b"], 2)
            p.stop(3)
            return p.flamegraph().record_digest()

        self.assertEqual(build(), build())

    def test_no_closed_profile_refused(self):
        p = Profiler("s")
        with self.assertRaises(LifecycleError):
            p.flamegraph()


class InputValidationTest(unittest.TestCase):
    def test_bad_seqs(self):
        p = Profiler("s")
        for bad in (True, -1, 1.5, "2", None):
            with self.assertRaises(ProfilerError):
                p.start(bad)

    def test_seq_must_increase(self):
        p = Profiler("s")
        p.start(5)
        with self.assertRaises(ProfilerError):
            p.record(["a"], 5)
        with self.assertRaises(ProfilerError):
            p.stop(4)

    def test_bad_stacks(self):
        p = Profiler("s")
        p.start(1)
        for bad in ([], (), ["ok", 42], ["ok", b"bytes"], [""], "not-a-list"):
            with self.assertRaises(ProfilerError):
                p.record(bad, 2)

    def test_deep_stack_refused(self):
        p = Profiler("s")
        p.start(1)
        with self.assertRaises(ProfilerError):
            p.record(["f"] * 300, 2)

    def test_huge_integral_cannot_pin(self):
        # Integral magnitudes > 2**53 cannot be digest-pinned (JCS float-loss
        # caveat): record_digest() must refuse fail-closed.
        r = ProfileReport(
            session_id="s",
            total_samples=1,
            frame_stats=(FrameStats(frame="f", self_samples=1, cumulative_samples=1),),
            seq_start=0,
            seq_end=2**54,
        )
        with self.assertRaises(ProfilerError):
            r.record_digest()

    def test_sample_count_view(self):
        p = Profiler("s")
        p.start(1)
        p.record(["a"], 2)
        p.record(["b"], 3)
        self.assertEqual(p.sample_count(), 2)
        p.stop(4)
        self.assertEqual(p.sample_count(), 0)


class AuditEventTest(unittest.TestCase):
    def test_shapes(self):
        ev = profiler_audit_event("profile-started", 3, session_id="s")
        self.assertEqual(ev["event"], "profiler.profile-started")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["profiler_version"], PROFILER_VERSION)
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_unknown_kind_refused(self):
        with self.assertRaises(ProfilerError):
            profiler_audit_event("bogus", 1)

    def test_bad_seq_refused(self):
        with self.assertRaises(ProfilerError):
            profiler_audit_event("profile-started", -1)


class ConcurrencyTest(unittest.TestCase):
    def test_concurrent_records(self):
        p = Profiler("s")
        p.start(1)
        seq = [1]
        lock = threading.Lock()

        def work(n):
            for i in range(20):
                with lock:
                    seq[0] += 1
                    s = seq[0]
                p.record([f"fn-{n}"], s)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(p.sample_count(), 100)
        r = p.stop(seq[0] + 1)
        self.assertEqual(r.total_samples, 100)


class StdlibOnlyTest(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "profiler.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "__future__", "hashlib", "hmac", "threading", "dataclasses", "typing"
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class MainSelfCheckTest(unittest.TestCase):
    def test_main(self):
        import profiler as mod

        mod.main()


if __name__ == "__main__":
    unittest.main()
