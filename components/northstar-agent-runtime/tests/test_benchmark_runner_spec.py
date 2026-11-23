"""Spec-API companion tests: task() / run() / leaderboard() on benchmark_runner.

The tracked module already owned register()/bench()/compare()/regress();
this file covers the additive task()/leaderboard() API. All pre-existing
tests in test_benchmark_runner.py are untouched.
"""

import subprocess
import sys

import pytest

from benchmark_runner import (
    BenchmarkRunner,
    BenchmarkRun,
    BenchmarkSpec,
    LeaderboardEntry,
    LeaderboardReport,
    UnknownBenchmarkError,
    ValidationError,
    NoRunError,
)


def _five(r, name, seq, durations, note=""):
    r.register(name, seq, runs=5)
    return r.bench(name, seq + 1, durations, note=note)


class TestTask:
    def test_task_roundtrip_matches_spec(self):
        r = BenchmarkRunner()
        spec = r.register("hash", 1, cmdline="sha256sum f", runs=5)
        task = r.task("hash")
        assert isinstance(task, BenchmarkSpec)
        assert task == spec
        assert task.spec_pin == spec.spec_pin

    def test_task_unknown_name(self):
        r = BenchmarkRunner()
        with pytest.raises(UnknownBenchmarkError):
            r.task("nope")

    def test_task_bad_name(self):
        r = BenchmarkRunner()
        for bad in ("", "   ", None, 5, b"hash"):
            with pytest.raises(ValidationError):
                r.task(bad)

    def test_run_roundtrip(self):
        r = BenchmarkRunner()
        _five(r, "hash", 1, [100, 200, 300, 400, 500])
        run = r.run("run-1")
        assert isinstance(run, BenchmarkRun)
        assert run.name == "hash"
        assert run.median_us == 300

    def test_run_unknown(self):
        r = BenchmarkRunner()
        with pytest.raises(NoRunError):
            r.run("run-99")


class TestLeaderboard:
    def test_empty_as_data(self):
        r = BenchmarkRunner()
        r.register("idle", 1, runs=5)
        board = r.leaderboard(2)
        assert isinstance(board, LeaderboardReport)
        assert board.entries == ()
        assert board.metric == "median_us"

    def test_fastest_first_default_median(self):
        r = BenchmarkRunner()
        _five(r, "slow", 1, [600, 610, 620, 630, 640])
        _five(r, "fast", 3, [100, 200, 300, 400, 500])
        board = r.leaderboard(5)
        assert [e.name for e in board.entries] == ["fast", "slow"]
        assert [e.rank for e in board.entries] == [1, 2]
        assert board.entries[0].median_us == 300

    def test_metric_vocabulary_flips_ranking(self):
        # g: median 10, max 1000 ; h: median 100, max 100
        r = BenchmarkRunner()
        _five(r, "g", 1, [10, 10, 10, 10, 1000])
        _five(r, "h", 3, [100, 100, 100, 100, 100])
        by_median = r.leaderboard(5, metric="median_us")
        by_max = r.leaderboard(5, metric="max_us")
        by_mean = r.leaderboard(5, metric="mean_us")
        assert [e.name for e in by_median.entries] == ["g", "h"]
        assert [e.name for e in by_max.entries] == ["h", "g"]
        assert [e.name for e in by_mean.entries] == ["h", "g"]
        for m in ("min_us", "p90_us"):
            b = r.leaderboard(6, metric=m)
            assert isinstance(b, LeaderboardReport)
            assert b.metric == m

    def test_bad_metric(self):
        r = BenchmarkRunner()
        _five(r, "a", 1, [100, 200, 300, 400, 500])
        for bad in ("", "MEDIAN_US", "variance", None, 42):
            with pytest.raises(ValidationError):
                r.leaderboard(3, metric=bad)

    def test_skips_benchmarks_with_no_run(self):
        r = BenchmarkRunner()
        _five(r, "ran", 1, [100, 200, 300, 400, 500])
        r.register("never", 3, runs=5)
        board = r.leaderboard(4)
        assert [e.name for e in board.entries] == ["ran"]

    def test_pure_read_no_seq_consumption_no_audit(self):
        r = BenchmarkRunner()
        _five(r, "a", 1, [100, 200, 300, 400, 500])
        _five(r, "b", 3, [600, 610, 620, 630, 640])
        audit_before = len(r.audit_log())
        # a jumpy seq would poison _last_seq if the read consumed it
        b1 = r.leaderboard(99)
        b2 = r.leaderboard(99)
        assert b1.report_pin == b2.report_pin
        assert len(r.audit_log()) == audit_before
        r.bench("a", 5, [110, 210, 310, 410, 510])
        assert r.latest("a").median_us == 310

    def test_bad_seq(self):
        r = BenchmarkRunner()
        _five(r, "a", 1, [100, 200, 300, 400, 500])
        for bad in (True, -1, "2", 2.5, None):
            with pytest.raises(ValidationError):
                r.leaderboard(bad)

    def test_tie_break_by_name_deterministic(self):
        r = BenchmarkRunner()
        _five(r, "zzz", 1, [100, 200, 300, 400, 500])
        _five(r, "aaa", 3, [100, 200, 300, 400, 500])
        board = r.leaderboard(5)
        assert [e.name for e in board.entries] == ["aaa", "zzz"]

    def test_cross_instance_pin_determinism(self):
        def build():
            r = BenchmarkRunner()
            _five(r, "a", 1, [100, 200, 300, 400, 500])
            _five(r, "b", 3, [600, 610, 620, 630, 640])
            return r.leaderboard(5)

        b1, b2 = build(), build()
        assert b1.report_pin == b2.report_pin
        assert b1.entries[0].entry_pin == b2.entries[0].entry_pin

    def test_pins_and_fields(self):
        r = BenchmarkRunner()
        _five(r, "a", 1, [100, 200, 300, 400, 500])
        board = r.leaderboard(3)
        assert board.schema == "northstar.benchmark-runner.v1"
        assert board.version == "benchmark-runner.v1"
        e = board.entries[0]
        assert isinstance(e, LeaderboardEntry)
        assert e.entry_pin.startswith("sha256:")
        assert (e.min_us, e.max_us, e.mean_us, e.p90_us) == (100, 500, 300, 500)
        assert e.schema == "northstar.benchmark-runner.v1"
        # entry pins differ by content: rank-2 of another board != rank-1 pin
        _five(r, "b", 4, [600, 610, 620, 630, 640])
        board2 = r.leaderboard(6)
        assert board2.entries[1].entry_pin != board2.entries[0].entry_pin


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, "benchmark_runner.py"], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert "benchmark-runner OK" in proc.stdout
