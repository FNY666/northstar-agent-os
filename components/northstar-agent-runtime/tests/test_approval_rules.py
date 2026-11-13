"""Standing approval rules: approval as data that survives the process.

The rules under test:

* a rule that pins arguments tolerates extra keys in the call;
* a rule that pins arguments fails when a pinned key is missing;
* a rule that pins arguments fails when a pinned key holds a different value
  or a different type;
* a rule with no pinned arguments matches every call to its tool;
* the rules serialise to plain dicts and come back from them, so they can be
  carried in a checkpoint's ``extra`` field or a session record.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import support  # noqa: F401  (bootstraps sys.path)

from approval_rules import (  # noqa: E402
    ApprovalRuleError,
    ToolApprovalRule,
    ToolApprovalState,
)


class ArgumentMatchingTests(unittest.TestCase):
    def test_extra_keys_are_tolerated(self):
        rule = ToolApprovalRule("Read", {"path": "/tmp/a"})
        self.assertTrue(rule.matches("Read", {"path": "/tmp/a", "limit": 10}))
        self.assertTrue(rule.matches("Read", {"path": "/tmp/a"}))

    def test_a_missing_pinned_key_fails(self):
        rule = ToolApprovalRule("Read", {"path": "/tmp/a"})
        self.assertFalse(rule.matches("Read", {"limit": 10}))
        self.assertFalse(rule.matches("Read", {}))

    def test_a_different_value_fails(self):
        rule = ToolApprovalRule("Read", {"path": "/tmp/a"})
        self.assertFalse(rule.matches("Read", {"path": "/tmp/b"}))

    def test_a_different_type_fails(self):
        # A pinned 1 must not match a call's True: bool is a subclass of int.
        rule = ToolApprovalRule("Write", {"count": 1})
        self.assertFalse(rule.matches("Write", {"count": True}))
        self.assertFalse(rule.matches("Write", {"count": "1"}))
        self.assertTrue(rule.matches("Write", {"count": 1}))

    def test_a_rule_without_arguments_matches_every_call(self):
        rule = ToolApprovalRule("Bash")
        self.assertTrue(rule.matches("Bash", {}))
        self.assertTrue(rule.matches("Bash", {"command": "ls"}))

    def test_a_rule_only_matches_its_own_tool(self):
        rule = ToolApprovalRule("Read", {"path": "/tmp/a"})
        self.assertFalse(rule.matches("Write", {"path": "/tmp/a"}))

    def test_a_server_label_bounds_the_rule(self):
        rule = ToolApprovalRule("Read", {"path": "/tmp/a"}, server_label="fs-1")
        self.assertTrue(rule.matches("Read", {"path": "/tmp/a"}, server_label="fs-1"))
        self.assertFalse(rule.matches("Read", {"path": "/tmp/a"}, server_label="fs-2"))
        self.assertFalse(rule.matches("Read", {"path": "/tmp/a"}))


class SerialisationTests(unittest.TestCase):
    def test_a_rule_round_trips_through_a_dict(self):
        rule = ToolApprovalRule("Read", {"path": "/tmp/a"}, server_label="fs-1")
        payload = rule.as_dict()
        self.assertIsInstance(payload, dict)
        restored = ToolApprovalRule.from_dict(payload)
        self.assertEqual(restored.tool_name, "Read")
        self.assertEqual(restored.arguments, {"path": "/tmp/a"})
        self.assertEqual(restored.server_label, "fs-1")

    def test_the_state_round_trips_through_a_dict(self):
        state = ToolApprovalState(rules=[ToolApprovalRule("Read", {"path": "/tmp/a"})])
        payload = state.as_dict()
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["version"], "northstar.approval-rules.v1")
        restored = ToolApprovalState.from_dict(payload)
        self.assertTrue(restored.authorises("Read", {"path": "/tmp/a"}))
        self.assertFalse(restored.authorises("Read", {"path": "/tmp/b"}))

    def test_the_state_carries_the_open_and_answered_approvals(self):
        state = ToolApprovalState()
        state.queued_approval_requests.append({"approval_id": "a-1", "tool": "Read"})
        state.collected_approval_responses.append({"approval_id": "a-1", "allowed": True})
        restored = ToolApprovalState.from_dict(state.as_dict())
        self.assertEqual(restored.queued_approval_requests, [{"approval_id": "a-1", "tool": "Read"}])
        self.assertEqual(restored.collected_approval_responses, [{"approval_id": "a-1", "allowed": True}])

    def test_a_repeated_rule_replaces_the_earlier_one(self):
        state = ToolApprovalState()
        state.add_rule(ToolApprovalRule("Read", {"path": "/a"}))
        state.add_rule(ToolApprovalRule("Read", {"path": "/b"}))
        self.assertEqual(len(state.rules), 1)
        self.assertTrue(state.authorises("Read", {"path": "/b"}))
        self.assertFalse(state.authorises("Read", {"path": "/a"}))

    def test_a_malformed_rule_is_refused(self):
        with self.assertRaises(ApprovalRuleError):
            ToolApprovalRule("", {"path": "/a"})
        with self.assertRaises(ApprovalRuleError):
            ToolApprovalRule("Read", "not-a-mapping")
        with self.assertRaises(ApprovalRuleError):
            ToolApprovalRule.from_dict({"tool_name": 7})
        with self.assertRaises(ApprovalRuleError):
            ToolApprovalState.from_dict({"rules": "not-a-list"})


class CheckpointCarryTests(unittest.TestCase):
    def test_the_state_travels_in_a_checkpoint_extra_field(self):
        from checkpoints import build, durable_state, from_record

        state = ToolApprovalState(rules=[ToolApprovalRule("Read", {"path": "/tmp/a"})])
        payload = build(
            session_id="s-1",
            record_index=0,
            transcript=[],
            turns=1,
            tool_calls=0,
            cost_usd=0.0,
            usage={},
            model="m",
            provider="p",
            permission_mode="default",
        )
        checkpoint = from_record({"type": "checkpoint", "index": 0, **payload})
        carried = durable_state(checkpoint, extra={"approval_state": state.as_dict()})
        restored = ToolApprovalState.from_dict(carried["approval_state"])
        self.assertTrue(restored.authorises("Read", {"path": "/tmp/a"}))


if __name__ == "__main__":
    unittest.main()
