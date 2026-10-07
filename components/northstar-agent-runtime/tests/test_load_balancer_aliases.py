"""Tests for load_balancer spec aliases: backend(), route(), health().

backend() wraps add_backend(); route() wraps select(); health() is native.
"""

import unittest

from load_balancer import (
    LOAD_BALANCER_VERSION,
    Backend,
    LoadBalancer,
    LoadBalancerError,
    NoHealthyBackendError,
    SelectRecord,
    UnknownBackendError,
    main,
)


class TestBackendAlias(unittest.TestCase):
    def test_backend_roundtrip(self):
        lb = LoadBalancer()
        rec = lb.backend("web-1", 0)
        self.assertIsInstance(rec, Backend)
        self.assertEqual(rec.backend_id, "web-1")
        self.assertEqual(rec.weight, 1)
        self.assertTrue(rec.healthy)
        self.assertEqual(rec.active_connections, 0)
        self.assertEqual(lb.backend_ids(), ("web-1",))

    def test_backend_with_weight(self):
        lb = LoadBalancer()
        rec = lb.backend("web-1", 0, weight=4)
        self.assertEqual(rec.weight, 4)

    def test_backend_duplicate_refused(self):
        lb = LoadBalancer()
        lb.backend("web-1", 0)
        with self.assertRaises(LoadBalancerError):
            lb.backend("web-1", 1)

    def test_backend_validation(self):
        lb = LoadBalancer()
        with self.assertRaises(LoadBalancerError):
            lb.backend("", 0)
        with self.assertRaises(LoadBalancerError):
            lb.backend(True, 0)  # type: ignore
        with self.assertRaises(LoadBalancerError):
            lb.backend("a", 0, weight=0)
        with self.assertRaises(LoadBalancerError):
            lb.backend("a", -1)

    def test_backend_reregister_after_remove(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        lb.remove_backend("a", 1)
        rec = lb.backend("a", 2, weight=2)
        self.assertEqual(rec.weight, 2)


class TestRouteAlias(unittest.TestCase):
    def test_route_round_robin(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        lb.backend("b", 1)
        picks = [lb.route("round-robin", i).backend_id for i in range(4)]
        self.assertEqual(picks, ["a", "b", "a", "b"])

    def test_route_weighted(self):
        lb = LoadBalancer()
        lb.backend("a", 0, weight=3)
        lb.backend("b", 1, weight=1)
        picks = [lb.route("weighted-round-robin", i).backend_id for i in range(4)]
        self.assertEqual(picks.count("a"), 3)
        self.assertEqual(picks.count("b"), 1)

    def test_route_least_connections(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        lb.backend("b", 1)
        lb.acquire("a", 0)
        self.assertEqual(lb.route("least-connections", 1).backend_id, "b")

    def test_route_least_load(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        lb.backend("b", 1)
        lb.report_load("a", 0.8, 0)
        lb.report_load("b", 0.2, 1)
        self.assertEqual(lb.route("least-load", 2).backend_id, "b")

    def test_route_skips_unhealthy(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        lb.backend("b", 1)
        lb.health("b", False, 2)
        for i in range(3):
            self.assertEqual(lb.route("round-robin", i).backend_id, "a")

    def test_route_empty_fail_closed(self):
        lb = LoadBalancer()
        with self.assertRaises(NoHealthyBackendError):
            lb.route("round-robin", 0)

    def test_route_unknown_algorithm(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        with self.assertRaises(LoadBalancerError):
            lb.route("magic", 1)

    def test_route_record_shape(self):
        lb = LoadBalancer()
        lb.backend("a", 0)
        rec = lb.route("round-robin", 5)
        self.assertIsInstance(rec, SelectRecord)
        self.assertEqual(rec.version, LOAD_BALANCER_VERSION)
        self.assertEqual(rec.algorithm, "round-robin")
        self.assertEqual(rec.backend_id, "a")
        self.assertEqual(rec.seq, 5)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_route_health_unknown_backend(self):
        lb = LoadBalancer()
        with self.assertRaises(UnknownBackendError):
            lb.health("ghost", False, 0)


class TestMainStillPasses(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
