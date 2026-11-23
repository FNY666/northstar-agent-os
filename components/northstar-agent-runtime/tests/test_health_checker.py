"""Tests for health_checker.py (targeted, standalone)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from health_checker import (
    HEALTH_CHECKER_VERSION,
    SCHEMA_PIN,
    CheckResult,
    HealthCheck,
    HealthChecker,
    HealthCheckError,
    HealthReport,
    HealthStatus,
    health_audit_event,
)


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HEALTH_CHECKER_VERSION, "health-checker.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.health-checker.v1")


class TestHealthCheckValidation(unittest.TestCase):
    def test_empty_name_rejected(self):
        with self.assertRaises(ValueError):
            HealthCheck("", lambda seq: True)

    def test_noncallable_rejected(self):
        with self.assertRaises(TypeError):
            HealthCheck("x", "not-a-fn")

    def test_critical_must_be_bool(self):
        with self.assertRaises(TypeError):
            HealthCheck("x", lambda seq: True, critical="yes")

    def test_wrong_schema_rejected(self):
        with self.assertRaises(ValueError):
            HealthCheck("x", lambda seq: True, schema="nope")

    def test_zero_arg_fn_allowed(self):
        HealthCheck("x", lambda: True)

    def test_one_arg_fn_allowed(self):
        HealthCheck("x", lambda seq: True)

    def test_two_arg_fn_rejected(self):
        with self.assertRaises(HealthCheckError):
            HealthCheck("x", lambda a, b: True)

    def test_frozen(self):
        c = HealthCheck("x", lambda seq: True)
        with self.assertRaises(Exception):
            c.name = "y"  # noqa: B018


class TestAggregation(unittest.TestCase):
    def _mk(self, specs):
        hc = HealthChecker()
        for name, fn, critical in specs:
            hc.register(HealthCheck(name, fn, critical=critical))
        return hc

    def test_all_healthy(self):
        hc = self._mk([("a", lambda s: True, True), ("b", lambda s: True, False)])
        r = hc.check_all(seq=1)
        self.assertEqual(r.overall, HealthStatus.HEALTHY.value)

    def test_critical_failure_unhealthy(self):
        hc = self._mk([("a", lambda s: True, True), ("b", lambda s: False, True)])
        r = hc.check_all(seq=1)
        self.assertEqual(r.overall, HealthStatus.UNHEALTHY.value)

    def test_noncritical_failure_degraded(self):
        hc = self._mk([("a", lambda s: True, True), ("b", lambda s: False, False)])
        r = hc.check_all(seq=1)
        self.assertEqual(r.overall, HealthStatus.DEGRADED.value)

    def test_empty_registry_healthy(self):
        hc = HealthChecker()
        r = hc.check_all(seq=1)
        self.assertEqual(r.overall, HealthStatus.HEALTHY.value)

    def test_raising_check_is_failure_not_crash(self):
        def boom(seq):
            raise RuntimeError("probe exploded")

        hc = self._mk([("boom", boom, True), ("ok", lambda s: True, True)])
        r = hc.check_all(seq=1)
        self.assertEqual(r.overall, HealthStatus.UNHEALTHY.value)
        boom_res = [x for x in r.results if x.name == "boom"][0]
        self.assertEqual(boom_res.status, HealthStatus.UNHEALTHY.value)
        self.assertIn("RuntimeError", boom_res.detail)

    def test_registration_order_preserved(self):
        hc = self._mk(
            [("zeta", lambda s: True, True), ("alpha", lambda s: True, True)]
        )
        r = hc.check_all(seq=1)
        self.assertEqual([x.name for x in r.results], ["zeta", "alpha"])

    def test_duplicate_name_rejected(self):
        hc = HealthChecker()
        hc.register(HealthCheck("a", lambda s: True))
        with self.assertRaises(HealthCheckError):
            hc.register(HealthCheck("a", lambda s: True))

    def test_bad_seq_rejected(self):
        hc = HealthChecker()
        with self.assertRaises(HealthCheckError):
            hc.check_all(seq=-1)
        with self.assertRaises(HealthCheckError):
            hc.check_all(seq=True)

    def test_tuple_result_with_detail(self):
        hc = self._mk([("a", lambda s: (True, "latency 12ms"), True)])
        r = hc.check_all(seq=3)
        self.assertEqual(r.results[0].detail, "latency 12ms")
        self.assertEqual(r.results[0].status, HealthStatus.HEALTHY.value)

    def test_bad_fn_return_shape_rejected_at_run(self):
        hc = self._mk([("a", lambda s: "yes", True)])
        r = hc.check_all(seq=1)
        self.assertEqual(r.overall, HealthStatus.UNHEALTHY.value)

    def test_results_frozen_and_digest_pinned(self):
        hc = self._mk([("a", lambda s: True, True)])
        r = hc.check_all(seq=7)
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertTrue(all(x.digest.startswith("sha256:") for x in r.results))
        with self.assertRaises(Exception):
            r.overall = "x"  # noqa: B018

    def test_report_deterministic(self):
        specs = [("a", lambda s: True, True), ("b", lambda s: (False, "x"), False)]
        r1 = self._mk(specs).check_all(seq=5)
        r2 = self._mk(specs).check_all(seq=5)
        self.assertEqual(r1.digest, r2.digest)

    def test_registered_names(self):
        hc = self._mk([("a", lambda s: True, True), ("b", lambda s: True, True)])
        self.assertEqual(hc.registered(), ("a", "b"))

    def test_audit_event_shape(self):
        hc = self._mk([("a", lambda s: True, True)])
        r = hc.check_all(seq=9)
        ev = health_audit_event(r, seq=9)
        self.assertEqual(ev["kind"], "health-check")
        self.assertEqual(ev["audit_seq"], 9)
        self.assertEqual(ev["overall"], HealthStatus.HEALTHY.value)

    def test_audit_event_bad_type(self):
        with self.assertRaises(TypeError):
            health_audit_event("nope", seq=1)

    def test_method_audit_event(self):
        hc = HealthChecker()
        r = hc.check_all(seq=4)
        ev = hc.health_audit_event(r)
        self.assertEqual(ev["kind"], "health-check")
        self.assertEqual(ev["audit_seq"], 4)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import health_checker

        health_checker.main()


if __name__ == "__main__":
    unittest.main()
