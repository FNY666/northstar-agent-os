"""Tests for kill_approval_combo: the brake overrides the human loop."""

import os
import tempfile
import unittest

from approval_chain import ApprovalChain
from kill_approval_combo import (
    KILL_APPROVAL_COMBO_VERSION,
    SCHEMA_PIN,
    EmergencyStopReport,
    KillApprovalGate,
)
from kill_switch import KillSwitch


def make_gate(**kwargs):
    tmp = tempfile.mkdtemp()
    switch = KillSwitch(os.path.join(tmp, "ks.json"))
    chain_kwargs = {"approver_secret": bytes(range(32))}
    chain_kwargs.update(kwargs.pop("chain_kwargs", {}))
    chain = ApprovalChain(**chain_kwargs)
    return KillApprovalGate(switch, chain), switch, chain


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(KILL_APPROVAL_COMBO_VERSION, "kill-approval-combo.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.kill-approval-combo.v1")


class TestConstructor(unittest.TestCase):
    def test_rejects_non_switch(self):
        chain = ApprovalChain(approver_secret=bytes(range(32)))
        with self.assertRaises(TypeError):
            KillApprovalGate("not-a-switch", chain)

    def test_rejects_non_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            switch = KillSwitch(os.path.join(tmp, "ks.json"))
            with self.assertRaises(TypeError):
                KillApprovalGate(switch, "not-a-chain")


class TestIntake(unittest.TestCase):
    def test_request_delegates_when_calm(self):
        gate, _, _ = make_gate()
        rid = gate.request_approval("db.query", "abstain", 100)
        self.assertIsNotNone(rid)
        self.assertEqual(gate.poll(rid, 100), "pending")

    def test_request_refused_while_triggered(self):
        gate, switch, _ = make_gate()
        switch.trigger(reason="boom", seq=1)
        rid = gate.request_approval("db.query", "abstain", 100)
        self.assertIsNone(rid)

    def test_intake_works_after_rollback(self):
        gate, switch, _ = make_gate()
        point = switch.create_rollback_point({"app": "state"}, reason="pre", seq=1)
        switch.trigger(reason="boom", seq=2)
        self.assertIsNone(gate.request_approval("db.query", "x", 100))
        switch.rollback(point.point_id, reason="restore", seq=3)
        rid = gate.request_approval("db.query", "x", 100)
        self.assertIsNotNone(rid)


class TestDecision(unittest.TestCase):
    def test_approve_delegates_when_calm(self):
        gate, _, _ = make_gate()
        rid = gate.request_approval("db.query", "abstain", 100)
        receipt = gate.approve(rid, "human:op", 100)
        self.assertIsNotNone(receipt)

    def test_approve_blocked_while_triggered(self):
        gate, switch, _ = make_gate()
        rid = gate.request_approval("db.query", "abstain", 100)
        switch.trigger(reason="boom", seq=101)
        self.assertIsNone(gate.approve(rid, "human:op", 101))

    def test_collect_delegates(self):
        gate, _, _ = make_gate()
        rid = gate.request_approval("db.query", "abstain", 100)
        issued = gate.approve(rid, "human:op", 100)
        collected = gate.collect_receipt(rid)
        self.assertEqual(collected, issued)


class TestExecution(unittest.TestCase):
    def _approved_receipt(self, gate, action="robot.move_to", seq=100):
        rid = gate.request_approval(action, "abstain", seq)
        return gate.approve(rid, "human:op", seq)

    def test_execute_allow_when_calm(self):
        gate, _, _ = make_gate()
        receipt = self._approved_receipt(gate)
        self.assertEqual(
            gate.execute_with_approval({"action_type": "robot.move_to"}, receipt),
            "allow",
        )

    def test_execute_denied_while_triggered_despite_receipt(self):
        gate, switch, _ = make_gate()
        receipt = self._approved_receipt(gate)
        switch.trigger(reason="boom", seq=101)
        self.assertEqual(
            gate.execute_with_approval({"action_type": "robot.move_to"}, receipt),
            "deny",
        )

    def test_execute_denied_without_receipt(self):
        gate, _, _ = make_gate()
        self.assertEqual(
            gate.execute_with_approval({"action_type": "db.query"}, None), "deny"
        )

    def test_execute_detailed_triggered_record(self):
        gate, switch, _ = make_gate()
        receipt = self._approved_receipt(gate)
        switch.trigger(reason="boom", seq=101)
        decision = gate.execute_detailed({"action_type": "robot.move_to"}, receipt)
        self.assertEqual(decision.verdict, "deny")
        self.assertEqual(decision.edge_verdict, "kill-switch-triggered")
        self.assertFalse(decision.receipt_ok)

    def test_execute_detailed_delegates_when_calm(self):
        gate, _, _ = make_gate()
        receipt = self._approved_receipt(gate)
        decision = gate.execute_detailed({"action_type": "robot.move_to"}, receipt)
        self.assertEqual(decision.verdict, "allow")


class TestEmergencyStop(unittest.TestCase):
    def test_stop_triggers_switch(self):
        gate, _, _ = make_gate()
        report = gate.emergency_stop("misbehaving", seq=5)
        self.assertTrue(report.switch_triggered)
        self.assertEqual(gate.check(), (False, "kill-switch-triggered"))

    def test_stop_cancels_pending(self):
        gate, _, _ = make_gate()
        r1 = gate.request_approval("db.query", "a", 100)
        r2 = gate.request_approval("db.delete", "b", 100)
        report = gate.emergency_stop("misbehaving", seq=101)
        self.assertEqual(set(report.cancelled), {r1, r2})
        self.assertEqual(gate.poll(r1, 101), "denied")
        self.assertEqual(gate.poll(r2, 101), "denied")

    def test_report_shape(self):
        gate, _, _ = make_gate()
        report = gate.emergency_stop("x", seq=1)
        self.assertIsInstance(report, EmergencyStopReport)
        d = report.as_dict()
        self.assertEqual(d["schema"], "northstar.kill-approval-combo.v1")
        self.assertEqual(d["version"], "kill-approval-combo.v1")
        self.assertEqual(d["cancelled"], [])
        self.assertEqual(d["already_closed"], [])

    def test_stop_leaves_decided_in_already_closed(self):
        gate, _, _ = make_gate()
        rid = gate.request_approval("db.query", "a", 100)
        gate.approve(rid, "human:op", 100)  # decided: approved
        report = gate.emergency_stop("x", seq=101)
        self.assertEqual(report.cancelled, ())
        self.assertEqual(report.already_closed, (rid,))

    def test_stop_leaves_expired_in_already_closed(self):
        gate, _, _ = make_gate()
        rid = gate.request_approval("db.query", "a", 100, sla_ticks=1)
        self.assertEqual(gate.poll(rid, 200), "expired")
        report = gate.emergency_stop("x", seq=200)
        self.assertEqual(report.cancelled, ())
        self.assertEqual(report.already_closed, (rid,))

    def test_stop_idempotent(self):
        gate, _, _ = make_gate()
        rid = gate.request_approval("db.query", "a", 100)
        first = gate.emergency_stop("x", seq=101)
        self.assertEqual(first.cancelled, (rid,))
        second = gate.emergency_stop("y", seq=102)
        self.assertEqual(second.cancelled, ())
        self.assertEqual(second.already_closed, (rid,))

    def test_stop_validation(self):
        gate, _, _ = make_gate()
        with self.assertRaises(ValueError):
            gate.emergency_stop("", seq=1)
        with self.assertRaises(ValueError):
            gate.emergency_stop("x", seq=-1)
        with self.assertRaises(ValueError):
            gate.emergency_stop("x", seq=True)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        from kill_approval_combo import main

        main()


if __name__ == "__main__":
    unittest.main()
