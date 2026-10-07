"""Tests for disaster_recovery: 17 cases."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from disaster_recovery import (
    DISASTER_RECOVERY_VERSION,
    DISASTER_RECOVERY_SCHEMA,
    ActiveFailoverError,
    BadFailoverError,
    BadPlanError,
    BadTestError,
    DisasterRecovery,
    DisasterRecoveryError,
    DuplicatePlanError,
    NoActiveFailoverError,
    SeqOrderError,
    UnknownPlanError,
    disaster_recovery_audit_event,
    main,
)


def fresh():
    return DisasterRecovery()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(DISASTER_RECOVERY_VERSION, "disaster-recovery.v1")
        self.assertEqual(DISASTER_RECOVERY_SCHEMA, "northstar.disaster-recovery.v1")

    def test_stdlib_only(self):
        path = os.path.join(os.path.dirname(__file__), "..", "disaster_recovery.py")
        tree = ast.parse(open(path).read())
        allowed = {"hashlib", "threading", "dataclasses", "typing",
                   "__future__", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main_self_check(self):
        main()


class TestPlan(unittest.TestCase):
    def test_plan_roundtrip_verify(self):
        dr = fresh()
        rec = dr.plan("p1", "site a", 1, rpo_target_seq=100,
                      rto_target_seq=50, tier="platinum")
        self.assertTrue(rec.verify())
        self.assertEqual(rec.schema, DISASTER_RECOVERY_SCHEMA)
        self.assertEqual(dr.plan_record("p1"), rec)
        self.assertIn("p1", dr.plan_ids())
        self.assertEqual(dr.plan_status("p1"), "ready")

    def test_duplicate_plan_refused(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=10, rto_target_seq=10,
               tier="gold")
        with self.assertRaises(DuplicatePlanError):
            dr.plan("p1", "site a2", 2, rpo_target_seq=10, rto_target_seq=10,
                    tier="gold")

    def test_bad_plan_inputs(self):
        dr = fresh()
        with self.assertRaises(DisasterRecoveryError):
            dr.plan("", "x", 1, rpo_target_seq=10, rto_target_seq=10,
                    tier="gold")
        with self.assertRaises(BadPlanError):
            dr.plan("p2", "x", 2, rpo_target_seq=0, rto_target_seq=10,
                    tier="gold")
        with self.assertRaises(BadPlanError):
            dr.plan("p3", "x", 3, rpo_target_seq=10, rto_target_seq=10,
                    tier="diamond")
        with self.assertRaises(BadPlanError):
            dr.plan("p4", "x", 4, rpo_target_seq=200, rto_target_seq=10,
                    tier="platinum")

    def test_unknown_plan(self):
        dr = fresh()
        with self.assertRaises(UnknownPlanError):
            dr.plan_record("nope")


class TestFailover(unittest.TestCase):
    def _dr(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=100, rto_target_seq=50,
               tier="platinum")
        return dr

    def test_failover_roundtrip(self):
        dr = self._dr()
        fo = dr.failover("p1", 2, "region-outage", data_loss_seq=40,
                         downtime_seq=20)
        self.assertTrue(fo.verify())
        self.assertTrue(fo.rpo_met)
        self.assertTrue(fo.rto_met)
        self.assertEqual(dr.plan_status("p1"), "active-failover")
        self.assertEqual(dr.active_failover("p1"), fo)
        self.assertIn(fo.failover_id, dr.failover_ids())

    def test_target_miss_is_data(self):
        dr = self._dr()
        fo = dr.failover("p1", 2, "ransomware", data_loss_seq=5000,
                         downtime_seq=9000)
        self.assertFalse(fo.rpo_met)
        self.assertFalse(fo.rto_met)

    def test_failover_unknown_plan(self):
        dr = fresh()
        with self.assertRaises(UnknownPlanError):
            dr.failover("ghost", 1, "region-outage", data_loss_seq=0,
                        downtime_seq=0)

    def test_overlapping_failover_refused(self):
        dr = self._dr()
        dr.failover("p1", 2, "region-outage", data_loss_seq=0, downtime_seq=0)
        with self.assertRaises(ActiveFailoverError):
            dr.failover("p1", 3, "datacenter-loss", data_loss_seq=0,
                        downtime_seq=0)

    def test_bad_failover_inputs(self):
        dr = self._dr()
        with self.assertRaises(BadFailoverError):
            dr.failover("p1", 2, "alien-invasion", data_loss_seq=0,
                        downtime_seq=0)
        with self.assertRaises(BadFailoverError):
            dr.failover("p1", 3, "region-outage", data_loss_seq=-1,
                        downtime_seq=0)


class TestFailback(unittest.TestCase):
    def test_failback_cycle(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=100, rto_target_seq=50,
               tier="platinum")
        dr.failover("p1", 2, "datacenter-loss", data_loss_seq=10,
                    downtime_seq=10)
        fb = dr.failback("p1", 3, recovery_seq=15)
        self.assertTrue(fb.verify())
        self.assertEqual(dr.plan_status("p1"), "ready")

    def test_failback_without_failover(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=100, rto_target_seq=50,
               tier="platinum")
        with self.assertRaises(NoActiveFailoverError):
            dr.failback("p1", 2, recovery_seq=0)


class TestDrill(unittest.TestCase):
    def test_drill_roundtrip(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=100, rto_target_seq=50,
               tier="platinum")
        rep = dr.test("p1", 2, "game-day", measured_loss_seq=10,
                      measured_downtime_seq=10)
        self.assertTrue(rep.verify())
        self.assertTrue(rep.rpo_met and rep.rto_met)
        self.assertIn(rep.test_id, dr.test_ids())

    def test_drill_bad_kind(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=100, rto_target_seq=50,
               tier="platinum")
        with self.assertRaises(BadTestError):
            dr.test("p1", 2, "chaos-monkey", measured_loss_seq=0,
                    measured_downtime_seq=0)

    def test_drill_during_failover_refused(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=100, rto_target_seq=50,
               tier="platinum")
        dr.failover("p1", 2, "network-partition", data_loss_seq=0,
                    downtime_seq=0)
        with self.assertRaises(ActiveFailoverError):
            dr.test("p1", 3, "tabletop", measured_loss_seq=0,
                    measured_downtime_seq=0)


class TestSeqAndAudit(unittest.TestCase):
    def test_seq_ordering_and_burn(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=10, rto_target_seq=10,
               tier="gold")
        with self.assertRaises(SeqOrderError):
            dr.plan("p1", "dup", 1, rpo_target_seq=10, rto_target_seq=10,
                    tier="gold")  # rewind: 1 <= 1
        with self.assertRaises(SeqOrderError):
            dr.plan("p2", "x", True, rpo_target_seq=10, rto_target_seq=10,
                    tier="gold")  # bool seq
        with self.assertRaises(SeqOrderError):
            dr.plan("p2", "x", -1, rpo_target_seq=10, rto_target_seq=10,
                    tier="gold")  # negative seq
        # failed mutation at seq 2 burned it: next legal seq must exceed it
        with self.assertRaises(DuplicatePlanError):
            dr.plan("p1", "dup", 2, rpo_target_seq=10, rto_target_seq=10,
                    tier="gold")

    def test_audit_shapes_and_banned_keys(self):
        dr = fresh()
        dr.plan("p1", "site a", 1, rpo_target_seq=10, rto_target_seq=10,
               tier="gold")
        kinds = [e["kind"] for e in dr.audit_log()]
        self.assertIn("disaster-recovery.plan-defined", kinds)
        for e in dr.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], DISASTER_RECOVERY_VERSION)
        with self.assertRaises(DisasterRecoveryError):
            disaster_recovery_audit_event("nope.kind", {}, 1)
        with self.assertRaises(DisasterRecoveryError):
            disaster_recovery_audit_event(
                "disaster-recovery.plan-defined",
                {"plan_id": "p1", "data_loss_seq": 5}, 2)


if __name__ == "__main__":
    unittest.main()
