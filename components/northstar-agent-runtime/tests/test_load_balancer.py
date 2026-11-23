"""Tests for load_balancer.py — deterministic backend selection."""

import unittest

from load_balancer import (
    ALGORITHMS,
    LOAD_BALANCER_VERSION,
    SCHEMA_PIN,
    Backend,
    LoadBalancer,
    LoadBalancerError,
    NoHealthyBackendError,
    SelectRecord,
    UnknownBackendError,
    load_balancer_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(LOAD_BALANCER_VERSION, "load-balancer.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.load-balancer.v1")

    def test_algorithms(self):
        self.assertEqual(
            ALGORITHMS,
            ("round-robin", "weighted-round-robin", "least-connections", "least-load"),
        )


class TestRegistration(unittest.TestCase):
    def test_add_backend_happy_path(self):
        lb = LoadBalancer()
        rec = lb.add_backend("a", 0)
        self.assertIsInstance(rec, Backend)
        self.assertEqual(rec.backend_id, "a")
        self.assertEqual(rec.weight, 1)
        self.assertTrue(rec.healthy)
        self.assertEqual(rec.active_connections, 0)
        self.assertEqual(rec.load, 0.0)
        self.assertEqual(lb.backend_ids(), ("a",))

    def test_add_backend_weight(self):
        lb = LoadBalancer()
        rec = lb.add_backend("a", 0, weight=5)
        self.assertEqual(rec.weight, 5)

    def test_add_duplicate_refused(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        with self.assertRaises(LoadBalancerError):
            lb.add_backend("a", 1)

    def test_add_validation(self):
        lb = LoadBalancer()
        with self.assertRaises(LoadBalancerError):
            lb.add_backend("", 0)
        with self.assertRaises(LoadBalancerError):
            lb.add_backend(True, 0)
        with self.assertRaises(LoadBalancerError):
            lb.add_backend("a", 0, weight=0)
        with self.assertRaises(LoadBalancerError):
            lb.add_backend("a", 0, weight=-2)
        with self.assertRaises(LoadBalancerError):
            lb.add_backend("a", 0, weight=True)
        with self.assertRaises(LoadBalancerError):
            lb.add_backend("a", -1)

    def test_remove_backend(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.remove_backend("a", 1)
        self.assertEqual(lb.backend_ids(), ())
        with self.assertRaises(UnknownBackendError):
            lb.remove_backend("a", 2)

    def test_get_unknown(self):
        lb = LoadBalancer()
        with self.assertRaises(UnknownBackendError):
            lb.get("ghost")


class TestRoundRobin(unittest.TestCase):
    def test_cycles_registration_order(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        lb.add_backend("c", 2)
        picks = [lb.select("round-robin", i).backend_id for i in range(7)]
        self.assertEqual(picks, ["a", "b", "c", "a", "b", "c", "a"])


class TestWeightedRoundRobin(unittest.TestCase):
    def test_smooth_distribution(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0, weight=3)
        lb.add_backend("b", 1, weight=1)
        lb.add_backend("c", 2, weight=1)
        picks = [lb.select("weighted-round-robin", i).backend_id for i in range(5)]
        # nginx smooth WRR trace for 3:1:1 -> a b a c a (a x3, b x1, c x1)
        self.assertEqual(picks, ["a", "b", "a", "c", "a"])
        # full cycle repeats
        picks = [lb.select("weighted-round-robin", i).backend_id for i in range(5)]
        self.assertEqual(picks, ["a", "b", "a", "c", "a"])
        counts = [lb.select("weighted-round-robin", i).backend_id for i in range(10)]
        self.assertEqual(counts.count("a"), 6)
        self.assertEqual(counts.count("b"), 2)
        self.assertEqual(counts.count("c"), 2)

    def test_equal_weights_match_round_robin(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        picks = [lb.select("weighted-round-robin", i).backend_id for i in range(4)]
        self.assertEqual(picks, ["a", "b", "a", "b"])


class TestLeastConnections(unittest.TestCase):
    def test_picks_fewest(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        lb.acquire("a", 0)
        self.assertEqual(lb.select("least-connections", 0).backend_id, "b")

    def test_acquire_release_accounting(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.acquire("a", 0)
        lb.acquire("a", 1)
        self.assertEqual(lb.get("a").active_connections, 2)
        lb.release("a", 0)
        self.assertEqual(lb.get("a").active_connections, 1)

    def test_release_without_acquire_refused(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        with self.assertRaises(LoadBalancerError):
            lb.release("a", 0)

    def test_acquire_on_unhealthy_refused(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.health("a", False, 1)
        with self.assertRaises(LoadBalancerError):
            lb.acquire("a", 2)

    def test_tie_breaks_by_registration_order(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        self.assertEqual(lb.select("least-connections", 0).backend_id, "a")


class TestLeastLoad(unittest.TestCase):
    def test_picks_lowest_load(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        lb.report_load("a", 0.9, 0)
        lb.report_load("b", 0.1, 1)
        self.assertEqual(lb.select("least-load", 0).backend_id, "b")

    def test_load_validation(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        for bad in (float("nan"), float("inf"), -0.1, True, "high"):
            with self.assertRaises(LoadBalancerError):
                lb.report_load("a", bad, 0)

    def test_report_load_unknown_backend(self):
        lb = LoadBalancer()
        with self.assertRaises(UnknownBackendError):
            lb.report_load("ghost", 0.5, 0)


class TestHealth(unittest.TestCase):
    def test_unhealthy_skipped(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        lb.health("b", False, 2)
        picks = {lb.select("round-robin", i).backend_id for i in range(4)}
        self.assertEqual(picks, {"a"})

    def test_health_unknown_backend(self):
        lb = LoadBalancer()
        with self.assertRaises(UnknownBackendError):
            lb.health("ghost", False, 0)

    def test_health_must_be_bool(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        with self.assertRaises(LoadBalancerError):
            lb.health("a", 1, 1)


class TestFailClosed(unittest.TestCase):
    def test_select_empty_raises(self):
        lb = LoadBalancer()
        with self.assertRaises(NoHealthyBackendError):
            lb.select("round-robin", 0)

    def test_select_all_unhealthy_raises(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.health("a", False, 1)
        with self.assertRaises(NoHealthyBackendError):
            lb.select("least-connections", 2)

    def test_unknown_algorithm(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        with self.assertRaises(LoadBalancerError):
            lb.select("magic-hash", 0)

    def test_removed_backend_not_selected(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        lb.add_backend("b", 1)
        lb.remove_backend("a", 2)
        for i in range(3):
            self.assertEqual(lb.select("round-robin", i).backend_id, "b")


class TestRecords(unittest.TestCase):
    def test_select_record_shape(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        rec = lb.select("round-robin", 7)
        self.assertIsInstance(rec, SelectRecord)
        self.assertEqual(rec.version, "load-balancer.v1")
        self.assertEqual(rec.algorithm, "round-robin")
        self.assertEqual(rec.backend_id, "a")
        self.assertEqual(rec.seq, 7)
        self.assertTrue(rec.digest.startswith("sha256:"))
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_digest_determinism(self):
        lb1 = LoadBalancer()
        lb1.add_backend("a", 0)
        lb2 = LoadBalancer()
        lb2.add_backend("a", 0)
        r1 = lb1.select("round-robin", 42)
        r2 = lb2.select("round-robin", 42)
        self.assertEqual(r1.digest, r2.digest)

    def test_frozen_records(self):
        lb = LoadBalancer()
        lb.add_backend("a", 0)
        rec = lb.select("round-robin", 0)
        with self.assertRaises(AttributeError):
            rec.backend_id = "b"  # type: ignore


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = load_balancer_audit_event("selected", 3, backend_id="a")
        self.assertEqual(ev["event"], "selected")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["module"], LOAD_BALANCER_VERSION)
        self.assertEqual(ev["backend_id"], "a")

    def test_audit_bad_kind(self):
        with self.assertRaises(LoadBalancerError):
            load_balancer_audit_event("hacked", 0)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
