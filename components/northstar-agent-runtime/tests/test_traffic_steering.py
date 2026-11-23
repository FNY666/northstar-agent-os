"""Tests for traffic_steering."""

import os
import unittest

from traffic_steering import (
    TrafficSteering,
    TrafficSteeringError,
    BadOriginError,
    DuplicateOriginError,
    UnknownOriginError,
    AlreadyFailedOverError,
    NotFailedOverError,
    BadWeightError,
    BadPolicyError,
    NoHealthyOriginError,
    SeqOrderError,
    OriginRecord,
    WeightRecord,
    RouteDecision,
    ProbeRecord,
    FailoverRecord,
    RecoveryRecord,
    POLICIES,
    REGIONS,
    _MODULE_VERSION,
    _SCHEMA_PIN,
    _stdlib_only_ok,
    traffic_steering_audit_event,
    main,
)


def make_ts():
    events = []
    return TrafficSteering(audit=events.append), events


class PinsTest(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(_MODULE_VERSION, "traffic-steering.v1")
        self.assertEqual(_SCHEMA_PIN, "northstar.traffic-steering.v1")

    def test_policy_vocabulary(self):
        self.assertEqual(POLICIES, ("geo", "latency", "weighted"))

    def test_regions_non_empty(self):
        self.assertIn("us-east", REGIONS)
        self.assertIn("eu-west", REGIONS)

    def test_stdlib_only(self):
        here = os.path.dirname(os.path.abspath(__file__))
        mod = os.path.join(os.path.dirname(here), "traffic_steering.py")
        ok, why = _stdlib_only_ok(mod)
        self.assertTrue(ok, why)


class RegisterTest(unittest.TestCase):
    def test_register_roundtrip(self):
        ts, _ = make_ts()
        rec = ts.register_origin("edge-a", "us-east", 1, latency_ms=20, capacity=50)
        self.assertEqual(rec.origin_id, "edge-a")
        self.assertEqual(rec.region, "us-east")
        self.assertTrue(rec.verify_digest())
        self.assertTrue(ts.is_healthy("edge-a"))
        self.assertEqual(ts.origin_ids(), ("edge-a",))

    def test_register_defaults(self):
        ts, _ = make_ts()
        rec = ts.register_origin("edge-a", "eu-west", 1)
        self.assertEqual(rec.latency_ms, 50)
        self.assertEqual(rec.capacity, 100)
        # default weight is 1
        self.assertEqual(ts.weight_of("edge-a"), 1)

    def test_duplicate_refused(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        with self.assertRaises(DuplicateOriginError):
            ts.register_origin("edge-a", "eu-west", 2)

    def test_bad_region_refused(self):
        ts, _ = make_ts()
        with self.assertRaises(BadOriginError):
            ts.register_origin("edge-a", "mars", 1)

    def test_bad_inputs_refused(self):
        ts, _ = make_ts()
        bad = [
            ("", "us-east", 1),          # empty id
            ("edge-a", "us-east", 1),    # valid baseline for control
        ]
        with self.assertRaises(BadOriginError):
            ts.register_origin(bad[0][0], bad[0][1], bad[0][2])
        # negative latency
        with self.assertRaises(BadOriginError):
            ts.register_origin("x", "us-east", 2, latency_ms=-1)
        # bool latency
        with self.assertRaises(BadOriginError):
            ts.register_origin("x", "us-east", 3, latency_ms=True)
        # zero capacity
        with self.assertRaises(BadOriginError):
            ts.register_origin("x", "us-east", 4, capacity=0)
        # bad seq kind
        with self.assertRaises(SeqOrderError):
            ts.register_origin("x", "us-east", True)
        # seq rewind
        ts.register_origin("ok", "us-east", 5)
        with self.assertRaises(SeqOrderError):
            ts.register_origin("ok2", "us-east", 5)


class WeightTest(unittest.TestCase):
    def test_set_weight(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        rec = ts.set_weight("edge-a", 7, 2)
        self.assertEqual(rec.weight, 7)
        self.assertTrue(rec.verify_digest())
        self.assertEqual(ts.weight_of("edge-a"), 7)

    def test_bad_weight_refused(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        for bad in (0, -3, True, 1.5, "10"):
            with self.assertRaises(BadWeightError, msg=f"weight={bad!r}"):
                ts.set_weight("edge-a", bad, ts._seq + 1)

    def test_unknown_origin_weight(self):
        ts, _ = make_ts()
        with self.assertRaises(UnknownOriginError):
            ts.set_weight("nope", 3, 1)


class RouteTest(unittest.TestCase):
    def _two(self):
        ts, events = make_ts()
        ts.register_origin("edge-a", "us-east", 1, latency_ms=20)
        ts.register_origin("edge-b", "eu-west", 2, latency_ms=80)
        return ts, events

    def test_geo_same_region(self):
        ts, _ = self._two()
        d = ts.route("req-1", "us-east", 3, policy="geo")
        self.assertEqual(d.origin_id, "edge-a")
        self.assertEqual(d.matched, "region")
        self.assertTrue(d.verify_digest())
        self.assertEqual(ts.decision(d.decision_id).origin_id, "edge-a")

    def test_geo_fallback_lowest_latency(self):
        ts, _ = self._two()
        d = ts.route("req-1", "ap-south", 3, policy="geo")
        self.assertEqual(d.origin_id, "edge-a")
        self.assertEqual(d.matched, "lowest-latency")

    def test_latency_policy(self):
        ts, _ = self._two()
        d = ts.route("req-1", "eu-west", 3, policy="latency")
        self.assertEqual(d.origin_id, "edge-a")
        self.assertEqual(d.matched, "latency")

    def test_weighted_deterministic(self):
        ts, _ = self._two()
        d1 = ts.route("req-1", "us-east", 3, policy="weighted")
        d2 = ts.route("req-1", "us-east", 4, policy="weighted")
        self.assertEqual(d1.origin_id, d2.origin_id)
        self.assertEqual(d1.matched, "weighted-bucket")

    def test_weighted_respects_weights(self):
        ts, _ = self._two()
        ts.set_weight("edge-b", 1000000, 3)
        # with overwhelming weight on edge-b, a sample of requests all land there
        got = {ts.route(f"r-{i}", "us-east", 4, policy="weighted").origin_id
               for i in range(50)}
        self.assertEqual(got, {"edge-b"})

    def test_route_skips_unhealthy(self):
        ts, _ = self._two()
        ts.failover("edge-a", 3, reason="drill")
        d = ts.route("req-1", "us-east", 4, policy="geo")
        self.assertEqual(d.origin_id, "edge-b")

    def test_no_healthy_refused(self):
        ts, _ = self._two()
        ts.failover("edge-a", 3)
        ts.failover("edge-b", 4)
        with self.assertRaises(NoHealthyOriginError):
            ts.route("req-1", "us-east", 5, policy="geo")

    def test_bad_policy_refused(self):
        ts, _ = self._two()
        with self.assertRaises(BadPolicyError):
            ts.route("req-1", "us-east", 3, policy="round-robin")

    def test_bad_request_refused(self):
        ts, _ = self._two()
        with self.assertRaises(BadOriginError):
            ts.route("req-1", "mars", 3, policy="geo")
        with self.assertRaises(BadOriginError):
            ts.route("", "us-east", 4, policy="geo")


class FailoverTest(unittest.TestCase):
    def test_failover_recover_cycle(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        fo = ts.failover("edge-a", 2, reason="maintenance")
        self.assertFalse(fo.automatic)
        self.assertTrue(fo.verify_digest())
        self.assertFalse(ts.is_healthy("edge-a"))
        with self.assertRaises(AlreadyFailedOverError):
            ts.failover("edge-a", 3)
        rec = ts.recover("edge-a", 4)
        self.assertTrue(rec.verify_digest())
        self.assertTrue(ts.is_healthy("edge-a"))
        with self.assertRaises(NotFailedOverError):
            ts.recover("edge-a", 5)

    def test_failover_unknown(self):
        ts, _ = make_ts()
        with self.assertRaises(UnknownOriginError):
            ts.failover("nope", 1)

    def test_probe_auto_failover(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        p1 = ts.probe("edge-a", False, 2)
        self.assertEqual(p1.consecutive_failures, 1)
        ts.probe("edge-a", False, 3)
        p3 = ts.probe("edge-a", False, 4)
        self.assertEqual(p3.consecutive_failures, 3)
        self.assertTrue(p3.verify_digest())
        self.assertFalse(ts.is_healthy("edge-a"))

    def test_probe_ok_resets_failures(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        ts.probe("edge-a", False, 2)
        ts.probe("edge-a", True, 3)
        p = ts.probe("edge-a", False, 4)
        self.assertEqual(p.consecutive_failures, 1)
        self.assertTrue(ts.is_healthy("edge-a"))

    def test_probe_bad_ok_refused(self):
        ts, _ = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        with self.assertRaises(BadOriginError):
            ts.probe("edge-a", "yes", 2)


class SeqAuditTest(unittest.TestCase):
    def test_failed_mutation_consumes_seq(self):
        ts, events = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        with self.assertRaises(DuplicateOriginError):
            ts.register_origin("edge-a", "eu-west", 2)
        # seq 2 was consumed by the failed mutation
        with self.assertRaises(SeqOrderError):
            ts.register_origin("edge-b", "eu-west", 2)
        ts.register_origin("edge-b", "eu-west", 3)  # works with fresh seq

    def test_audit_shapes(self):
        ts, events = make_ts()
        ts.register_origin("edge-a", "us-east", 1)
        kinds = {e["event"] for e in events}
        self.assertIn("origin-registered", kinds)
        for e in events:
            self.assertEqual(e["schema_version"], "audit.ndjson/1")
            self.assertEqual(e["module"], "traffic-steering.v1")

    def test_audit_event_helper(self):
        ev = traffic_steering_audit_event("routed", 9, {"origin_id": "edge-a"})
        self.assertEqual(ev["event"], "routed")
        self.assertEqual(ev["seq"], 9)
        with self.assertRaises(TrafficSteeringError):
            traffic_steering_audit_event("bogus", 1, {})

    def test_origin_lookup_unknown(self):
        ts, _ = make_ts()
        with self.assertRaises(UnknownOriginError):
            ts.origin("nope")
        with self.assertRaises(UnknownOriginError):
            ts.is_healthy("nope")

    def test_main(self):
        self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
