"""Tests for event_bridge: 17 cases."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import event_bridge
from event_bridge import (
    EVENT_BRIDGE_SCHEMA,
    EVENT_BRIDGE_VERSION,
    AUDIT_SCHEMA,
    RULE_ENABLED,
    RULE_DISABLED,
    OUTCOME_DELIVERED,
    OUTCOME_RETRY_SCHEDULED,
    OUTCOME_DEAD_LETTERED,
    BadEventError,
    BadPatternError,
    BadTransformerError,
    DuplicateDeadLetterError,
    DuplicateRuleError,
    DuplicateTargetError,
    EventBridge,
    EventBridgeError,
    ReplayStateError,
    SeqOrderError,
    TransformFailedError,
    UnknownDeadLetterError,
    UnknownRuleError,
    UnknownTargetError,
    event_bridge_audit_event,
    pattern_matches,
)


def _event(**detail):
    return {"source": "app.orders", "detail-type": "Order Placed",
            "detail": detail}


def _bridge_with_route(seq_start=0):
    """Bridge with one rule, one plain target, one failing target."""
    bridge = EventBridge()
    bridge.put_rule(
        "orders",
        {"source": ["app.orders"],
         "detail-type": ["Order Placed"],
         "detail": {"state": ["pending"]}},
        seq_start, description="pending orders")
    bridge.add_target("orders", "good", seq_start + 1, endpoint="queue://good")
    bridge.add_target("orders", "flaky", seq_start + 2, endpoint="queue://flaky",
                     max_attempts=2, simulate_failure=True)
    return bridge, seq_start + 3


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(EVENT_BRIDGE_VERSION, "event-bridge.v1")
        self.assertEqual(EVENT_BRIDGE_SCHEMA, "northstar.event-bridge.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only_ast(self):
        path = os.path.join(os.path.dirname(__file__), "..", "event_bridge.py")
        with open(path) as handle:
            tree = ast.parse(handle.read())
        allowed = {"re", "threading", "dataclasses", "typing",
                   "__future__", "hashlib", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed,
                                  f"non-stdlib import: {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              f"non-stdlib import: {node.module}")


class TestRules(unittest.TestCase):
    def test_put_rule_roundtrip(self):
        bridge = EventBridge()
        record = bridge.put_rule("r1", {"source": ["a"]}, 0)
        self.assertEqual(record.rule_id, "r1")
        self.assertEqual(record.state, RULE_ENABLED)
        self.assertTrue(record.verify())
        self.assertEqual(bridge.rule_ids(), ("r1",))
        self.assertTrue(bridge.describe_rule("r1", 0).verify())

    def test_put_rule_rejects_bad_patterns(self):
        bridge = EventBridge()
        bad = [
            {},                          # empty
            {"": ["a"]},                  # empty key
            {"source": []},               # empty match list
            {"source": "a"},              # not a list
            {"source": [1.5]},            # float in pattern
            {"source": {"anything-but": "x"}},  # anything-but not a list
            {"source": {"anything-but": []}},  # empty anything-but
            {"source": {"prefix": ""}},   # empty prefix
            {"detail": {}},               # empty nested
        ]
        seq = 0
        for i, pattern in enumerate(bad):
            # bad patterns raise before seq consumption, so seq stays 0
            with self.assertRaises((BadPatternError, EventBridgeError),
                                   msg=f"pattern={pattern!r}"):
                bridge.put_rule(f"bad-{i}", pattern, seq)

    def test_duplicate_rule_refused(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        with self.assertRaises(DuplicateRuleError):
            bridge.put_rule("r1", {"source": ["a"]}, 1)

    def test_disable_enable_rule(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        bridge.add_target("r1", "t1", 1)
        disabled = bridge.disable_rule("r1", 2)
        self.assertEqual(disabled.state, RULE_DISABLED)
        self.assertTrue(disabled.verify())
        report = bridge.route("e1", {"source": "a", "detail-type": "d"}, 3)
        self.assertEqual(report.matched_rule_ids, ())
        self.assertEqual(report.deliveries, ())
        enabled = bridge.enable_rule("r1", 4)
        self.assertEqual(enabled.state, RULE_ENABLED)
        report = bridge.route("e2", {"source": "a", "detail-type": "d"}, 5)
        self.assertEqual(report.matched_rule_ids, ("r1",))

    def test_unknown_rule_errors(self):
        bridge = EventBridge()
        with self.assertRaises(UnknownRuleError):
            bridge.describe_rule("nope", 0)
        # disable_rule consumes seq 0 even though it raises UnknownRuleError
        with self.assertRaises(UnknownRuleError):
            bridge.disable_rule("nope", 0)
        with self.assertRaises(UnknownRuleError):
            bridge.add_target("nope", "t1", 1)


class TestTargets(unittest.TestCase):
    def test_add_target_roundtrip(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        record = bridge.add_target("r1", "t1", 1, endpoint="queue://x",
                                   max_attempts=5)
        self.assertTrue(record.verify())
        self.assertEqual(record.max_attempts, 5)
        self.assertEqual(bridge.target_ids("r1"), ("t1",))
        with self.assertRaises(DuplicateTargetError):
            bridge.add_target("r1", "t1", 2)
        bridge.remove_target("r1", "t1", 3)
        self.assertEqual(bridge.target_ids("r1"), ())
        with self.assertRaises(UnknownTargetError):
            bridge.remove_target("r1", "t1", 4)

    def test_add_target_bad_transformer(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        bad_transformers = [
            # template placeholder not defined in paths map
            {"input_paths_map": {"a": "$.detail.a"},
             "input_template": "<b>"},
            # path not starting with $
            {"input_paths_map": {"a": "detail.a"},
             "input_template": "<a>"},
            # bad placeholder name
            {"input_paths_map": {"9bad": "$.detail.a"},
             "input_template": "<9bad>"},
            # template not a str
            {"input_paths_map": {}, "input_template": 42},
        ]
        seq = 1
        for transformer in bad_transformers:
            with self.assertRaises(BadTransformerError,
                                   msg=f"{transformer!r}"):
                bridge.add_target("r1", f"t{seq}", seq,
                                  input_transformer=transformer)
                seq += 1
        # max_attempts must be int >= 1, not bool
        with self.assertRaises(EventBridgeError):
            bridge.add_target("r1", "tb1", seq, max_attempts=0)
        with self.assertRaises(EventBridgeError):
            bridge.add_target("r1", "tb2", seq + 1, max_attempts=True)


class TestTransform(unittest.TestCase):
    def _bridge(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        bridge.add_target(
            "r1", "t1", 1,
            input_transformer={
                "input_paths_map": {
                    "order_id": "$.detail.orderId",
                    "n": "$.detail.count",
                },
                "input_template": '{"id": <order_id>, "n": <n>}',
            })
        bridge.add_target("r1", "plain", 2)
        return bridge

    def test_transform_happy_path(self):
        bridge = self._bridge()
        record = bridge.transform(
            "r1", "t1", _event(orderId="ord-9", count=3), 3)
        self.assertEqual(record.transformed, '{"id": ord-9, "n": 3}')
        self.assertTrue(record.verify())

    def test_transform_passthrough_without_transformer(self):
        bridge = self._bridge()
        event = _event(orderId="x")
        record = bridge.transform("r1", "plain", event, 3)
        import json
        self.assertEqual(json.loads(record.transformed)["detail"]["orderId"], "x")
        self.assertTrue(record.verify())

    def test_transform_unresolvable_path(self):
        bridge = self._bridge()
        with self.assertRaises(TransformFailedError):
            bridge.transform("r1", "t1", _event(), 3)
        with self.assertRaises(UnknownTargetError):
            bridge.transform("r1", "nope", _event(orderId="x"), 3)


class TestRoute(unittest.TestCase):
    def test_route_delivers_to_matching_target(self):
        bridge, seq = _bridge_with_route()
        report = bridge.route("e1", _event(state="pending"), seq)
        self.assertTrue(report.verify())
        self.assertEqual(report.matched_rule_ids, ("orders",))
        by_target = {d.target_id: d for d in report.deliveries}
        self.assertEqual(by_target["good"].outcome, OUTCOME_DELIVERED)
        self.assertTrue(by_target["good"].verify())
        self.assertEqual(bridge.route_count(), 1)

    def test_route_no_match_is_empty(self):
        bridge, seq = _bridge_with_route()
        report = bridge.route("e1", _event(state="shipped"), seq)
        self.assertEqual(report.matched_rule_ids, ())
        self.assertEqual(report.deliveries, ())
        self.assertTrue(report.verify())

    def test_route_rejects_bad_events(self):
        bridge, seq = _bridge_with_route()
        with self.assertRaises(BadEventError):
            bridge.route("e1", {"detail-type": "d"}, seq)  # no source
        with self.assertRaises(BadEventError):
            bridge.route("e2", {"source": "a", "detail-type": "d",
                                "x": float("nan")}, seq + 1)
        with self.assertRaises(BadEventError):
            bridge.route("e3", {"source": "a", "detail-type": "d",
                                "x": 2 ** 53}, seq + 2)

    def test_route_retry_then_dead_letters(self):
        bridge, seq = _bridge_with_route()
        first = bridge.route("e1", _event(state="pending"), seq)
        flaky = {d.target_id: d for d in first.deliveries}["flaky"]
        self.assertEqual(flaky.outcome, OUTCOME_RETRY_SCHEDULED)
        self.assertEqual(flaky.attempt, 1)
        self.assertEqual(flaky.dead_letter_id, "")
        second = bridge.route("e1", _event(state="pending"), seq + 1)
        flaky2 = {d.target_id: d for d in second.deliveries}["flaky"]
        self.assertEqual(flaky2.outcome, OUTCOME_DEAD_LETTERED)
        self.assertEqual(flaky2.attempt, 2)
        self.assertNotEqual(flaky2.dead_letter_id, "")
        self.assertEqual(bridge.dead_letter_ids(), (flaky2.dead_letter_id,))
        record = bridge.dead_letter(flaky2.dead_letter_id)
        self.assertTrue(record.verify())
        self.assertEqual(record.reason, "simulated-failure")
        self.assertEqual(record.attempts, 2)

    def test_pattern_language(self):
        self.assertTrue(pattern_matches(
            {"source": ["a", "b"]}, {"source": "b"}))
        self.assertFalse(pattern_matches(
            {"source": ["a"]}, {"source": "b"}))
        self.assertTrue(pattern_matches(
            {"detail": {"state": {"anything-but": ["shipped"]}}},
            {"detail": {"state": "pending"}}))
        self.assertFalse(pattern_matches(
            {"detail": {"state": {"anything-but": ["shipped"]}}},
            {"detail": {"state": "shipped"}}))
        self.assertTrue(pattern_matches(
            {"detail": {"id": {"prefix": "ord-"}}},
            {"detail": {"id": "ord-42"}}))
        self.assertFalse(pattern_matches(
            {"source": ["a"], "missing": ["x"]}, {"source": "a"}))


class TestDeadLetter(unittest.TestCase):
    def test_manual_dlq_duplicate_and_replay(self):
        bridge = EventBridge()
        first = bridge.dlq("e1", 0, "operator-quarantine", target_id="t1",
                           attempts=3)
        self.assertTrue(first.verify())
        self.assertFalse(first.replayed)
        with self.assertRaises(DuplicateDeadLetterError):
            bridge.dlq("e1", 1, "again", target_id="t1")
        # same event, different target is a distinct pair
        bridge.dlq("e1", 2, "other target", target_id="t2")
        replayed = bridge.replay(first.dead_letter_id, 3)
        self.assertTrue(replayed.verify())
        self.assertEqual(replayed.event_id, "e1")
        with self.assertRaises(ReplayStateError):
            bridge.replay(first.dead_letter_id, 4)
        with self.assertRaises(UnknownDeadLetterError):
            bridge.replay("dlq-999", 5)
        # after replay the pair may be dead-lettered again
        bridge.dlq("e1", 6, "re-quarantine", target_id="t1")
        self.assertEqual(len(bridge.dead_letter_ids()), 3)


class TestSeqDiscipline(unittest.TestCase):
    def test_seq_must_strictly_increase(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        with self.assertRaises(SeqOrderError):
            bridge.put_rule("r2", {"source": ["a"]}, 0)  # rewind
        with self.assertRaises(EventBridgeError):
            bridge.put_rule("r2", {"source": ["a"]}, True)  # bool seq
        # pure views validate but do not consume the seq
        bridge.describe_rule("r1", 0)
        bridge.put_rule("r2", {"source": ["a"]}, 1)  # still accepted

    def test_failed_mutation_consumes_seq(self):
        bridge = EventBridge()
        bridge.put_rule("r1", {"source": ["a"]}, 0)
        with self.assertRaises(DuplicateRuleError):
            bridge.put_rule("r1", {"source": ["a"]}, 1)  # duplicate id
        # the failed duplicate consumed seq 1, so the next must be > 1
        with self.assertRaises(SeqOrderError):
            bridge.put_rule("r2", {"source": ["a"]}, 1)


class TestAudit(unittest.TestCase):
    def test_audit_event_shapes(self):
        event = event_bridge_audit_event(
            "routed", 3, rule_id="r1", target_id="t1",
            detail={"event_digest": "sha256:abc", "matched": 2})
        self.assertEqual(event["schema"], AUDIT_SCHEMA)
        self.assertEqual(event["kind"], "event-bridge.routed")
        self.assertEqual(event["version"], EVENT_BRIDGE_VERSION)
        self.assertEqual(event["schema_ref"], EVENT_BRIDGE_SCHEMA)
        self.assertEqual(event["rule_id"], "r1")
        self.assertEqual(event["detail"]["matched"], 2)

    def test_audit_rejects_unknown_kind(self):
        with self.assertRaises(EventBridgeError):
            event_bridge_audit_event("nope", 0)

    def test_audit_bans_raw_payloads(self):
        for banned in ("event", "payload", "transformed", "template",
                       "paths_map"):
            with self.assertRaises(EventBridgeError, msg=banned):
                event_bridge_audit_event(
                    "routed", 0, detail={banned: "raw"})


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        # main() must not raise; it asserts the full lifecycle itself.
        event_bridge.main()


if __name__ == "__main__":
    unittest.main()
