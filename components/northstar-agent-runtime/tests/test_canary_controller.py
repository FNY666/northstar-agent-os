"""Tests for canary_controller: deterministic canary traffic splitting."""

import unittest

from canary_controller import (
    CANARY_CONTROLLER_VERSION,
    SCHEMA_PIN,
    Canary,
    CanaryController,
    CanaryError,
    PromotionReport,
    RouteDecision,
    _draw,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CANARY_CONTROLLER_VERSION, "canary-controller.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.canary-controller.v1")


class CanaryRecordTests(unittest.TestCase):
    def test_canary_frozen(self):
        canary = Canary(version="v2", traffic_pct=5.0)
        with self.assertRaises(Exception):
            canary.version = "v3"  # type: ignore[misc]

    def test_canary_validation(self):
        with self.assertRaises(TypeError):
            Canary(version="", traffic_pct=5.0)
        with self.assertRaises(TypeError):
            Canary(version="v2", traffic_pct=True)
        with self.assertRaises(ValueError):
            Canary(version="v2", traffic_pct=-1.0)
        with self.assertRaises(ValueError):
            Canary(version="v2", traffic_pct=100.1)
        with self.assertRaises(ValueError):
            Canary(version="v2", traffic_pct=float("nan"))

    def test_canary_as_dict(self):
        record = Canary(version="v2", traffic_pct=5.0).as_dict()
        self.assertEqual(record["schema"], SCHEMA_PIN)
        self.assertEqual(record["version"], "v2")
        self.assertEqual(record["traffic_pct"], 5.0)


class RouteTests(unittest.TestCase):
    def test_no_canary_routes_stable(self):
        controller = CanaryController("v1")
        decision = controller.route("req-1")
        self.assertEqual(decision.served_by, "stable")
        self.assertEqual(decision.version, "v1")

    def test_zero_pct_routes_stable(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 0.0)
        self.assertEqual(controller.route("req-1").served_by, "stable")

    def test_full_pct_routes_canary(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 100.0)
        decision = controller.route("req-1")
        self.assertEqual(decision.served_by, "canary")
        self.assertEqual(decision.version, "v2")

    def test_routing_deterministic(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 50.0)
        first = controller.route("req-abc")
        second = controller.route("req-abc")
        self.assertEqual(first, second)
        self.assertEqual(first.draw, _draw("req-abc"))

    def test_draw_within_bounds(self):
        for rid in ("a", "b", "req-1", "req-2", "x" * 64):
            draw = _draw(rid)
            self.assertGreaterEqual(draw, 0.0)
            self.assertLess(draw, 100.0)

    def test_split_serves_both_slices(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 50.0)
        served = {controller.route(f"req-{i}").served_by for i in range(200)}
        self.assertEqual(served, {"stable", "canary"})

    def test_mapping_input(self):
        controller = CanaryController("v1")
        decision = controller.route({"request_id": "req-9"})
        self.assertEqual(decision.request_id, "req-9")

    def test_malformed_input(self):
        controller = CanaryController("v1")
        with self.assertRaises(TypeError):
            controller.route(123)
        with self.assertRaises(TypeError):
            controller.route({"nope": 1})
        with self.assertRaises(TypeError):
            controller.route("")

    def test_decision_frozen(self):
        controller = CanaryController("v1")
        decision = controller.route("req-1")
        with self.assertRaises(Exception):
            decision.served_by = "canary"  # type: ignore[misc]


class LifecycleTests(unittest.TestCase):
    def test_promote(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 10.0)
        report = controller.promote()
        self.assertIsInstance(report, PromotionReport)
        self.assertEqual(report.promoted, "v2")
        self.assertEqual(report.previous_stable, "v1")
        self.assertEqual(controller.status().stable_version, "v2")
        self.assertIsNone(controller.status().canary)
        # After promotion everything routes to the new stable.
        self.assertEqual(controller.route("req-1").served_by, "stable")
        self.assertEqual(controller.route("req-1").version, "v2")

    def test_promote_without_canary(self):
        controller = CanaryController("v1")
        with self.assertRaises(CanaryError):
            controller.promote()

    def test_rollback(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 10.0)
        dropped = controller.rollback()
        self.assertEqual(dropped, "v2")
        self.assertEqual(controller.status().stable_version, "v1")
        self.assertIsNone(controller.status().canary)

    def test_rollback_without_canary(self):
        controller = CanaryController("v1")
        with self.assertRaises(CanaryError):
            controller.rollback()

    def test_double_deploy_refused(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 10.0)
        with self.assertRaises(CanaryError):
            controller.deploy_canary("v3", 10.0)

    def test_canary_must_differ_from_stable(self):
        controller = CanaryController("v1")
        with self.assertRaises(CanaryError):
            controller.deploy_canary("v1", 10.0)

    def test_deploy_after_promote(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 10.0)
        controller.promote()
        canary = controller.deploy_canary("v3", 5.0)
        self.assertEqual(canary.version, "v3")
        self.assertEqual(controller.status().stable_version, "v2")


class AuditTests(unittest.TestCase):
    def test_audit_event(self):
        controller = CanaryController("v1")
        decision = controller.route("req-1")
        event = controller.canary_audit_event(decision, 7)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["request_id"], "req-1")

    def test_audit_event_validation(self):
        controller = CanaryController("v1")
        decision = controller.route("req-1")
        with self.assertRaises(TypeError):
            controller.canary_audit_event("nope", 1)
        with self.assertRaises(TypeError):
            controller.canary_audit_event(decision, -1)
        with self.assertRaises(TypeError):
            controller.canary_audit_event(decision, True)

    def test_events_log(self):
        controller = CanaryController("v1")
        controller.deploy_canary("v2", 10.0)
        controller.promote()
        kinds = [e["event"] for e in controller.events()]
        self.assertEqual(kinds, ["deployed", "promoted"])


class MainTests(unittest.TestCase):
    def test_main(self):
        import canary_controller

        canary_controller.main()


if __name__ == "__main__":
    unittest.main()
