"""Tests for the seccomp capability probe itself.

The probe is what the benchmark cases trust, so it has to answer the
question it claims to answer. A probe that always says "yes" turns every
host into a host that reports a broken product; a probe that always says
"no" quietly deletes the seccomp proof from the benchmark. Both are worse
than the failure they were meant to remove.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import support  # noqa: F401  (bootstraps sys.path)
import governance_bench  # noqa: E402


class SeccompProbeTests(unittest.TestCase):
    def test_the_probe_answers_a_question_about_this_host(self):
        self.assertIsInstance(governance_bench.seccomp_filter_loadable(), bool)

    def test_the_probe_agrees_with_what_the_runtime_can_do(self):
        # If the probe says yes, the runtime has to manage it: the filter
        # loader has to produce a child that reports "Seccomp: 2".
        import subprocess

        if not governance_bench.seccomp_filter_loadable():
            self.skipTest("this host cannot install a BPF filter")

        from tools.seccomp import prctl_loader_argv

        argv = prctl_loader_argv(
            ["sh", "-c", "grep -q 'Seccomp:\\t2' /proc/self/status"]
        )
        completed = subprocess.run(argv, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr[-400:])

    def test_the_probe_is_cached_so_a_benchmark_run_does_not_reprobe(self):
        original = governance_bench._SECCOMP_LOADABLE
        governance_bench._SECCOMP_LOADABLE = None
        self.addCleanup(
            setattr, governance_bench, "_SECCOMP_LOADABLE", original
        )
        first = governance_bench.seccomp_filter_loadable()
        governance_bench._SECCOMP_LOADABLE = not first
        self.assertEqual(
            governance_bench.seccomp_filter_loadable(),
            not first,
            "the probe answered differently on the second call, so it is not cached",
        )


if __name__ == "__main__":
    unittest.main()
