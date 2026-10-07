"""Targeted tests for blue_green_deploy."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import blue_green_deploy as bgd
from blue_green_deploy import (
    BLUE_GREEN_DEPLOY_SCHEMA,
    BLUE_GREEN_DEPLOY_VERSION,
    BlueGreenError,
    Deployment,
    SwitchRecord,
    blue_green_audit_event,
    create,
    rollback,
    switch,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BLUE_GREEN_DEPLOY_VERSION, "blue-green-deploy.v1")

    def test_schema_pin(self):
        self.assertEqual(BLUE_GREEN_DEPLOY_SCHEMA, "northstar.blue-green-deploy.v1")


class TestCreate(unittest.TestCase):
    def test_defaults_to_blue(self):
        d = create("v1", "v2")
        self.assertEqual(d.active, "blue")
        self.assertIsNone(d.previous)
        self.assertEqual(d.switches, 0)

    def test_explicit_green(self):
        d = create("v1", "v2", active="green")
        self.assertEqual(d.active, "green")

    def test_serving_and_staged(self):
        d = create("v1", "v2")
        self.assertEqual(d.serving(), "v1")
        self.assertEqual(d.staged(), "v2")
        d2 = create("v1", "v2", active="green")
        self.assertEqual(d2.serving(), "v2")
        self.assertEqual(d2.staged(), "v1")

    def test_empty_blue_rejected(self):
        with self.assertRaises(BlueGreenError):
            create("", "v2")

    def test_whitespace_version_rejected(self):
        with self.assertRaises(BlueGreenError):
            create("v1", "   ")

    def test_non_str_version_rejected(self):
        with self.assertRaises(BlueGreenError):
            create("v1", 123)

    def test_bool_version_rejected(self):
        with self.assertRaises(BlueGreenError):
            create(True, "v2")

    def test_bad_active_rejected(self):
        with self.assertRaises(BlueGreenError):
            create("v1", "v2", active="purple")

    def test_previous_must_differ_from_active(self):
        with self.assertRaises(BlueGreenError):
            Deployment(blue_version="v1", green_version="v2", active="blue", previous="blue")


class TestSwitch(unittest.TestCase):
    def test_switch_flips_active(self):
        d = create("v1", "v2")
        d2, rec = switch(d, seq=1)
        self.assertEqual(d2.active, "green")
        self.assertEqual(d2.serving(), "v2")
        self.assertEqual(d2.previous, "blue")
        self.assertEqual(d2.switches, 1)
        self.assertEqual(rec.action, "switch")
        self.assertEqual(rec.seq, 1)

    def test_switch_is_immutable(self):
        d = create("v1", "v2")
        switch(d, seq=1)
        self.assertEqual(d.active, "blue")
        self.assertIsNone(d.previous)

    def test_double_switch_returns(self):
        d = create("v1", "v2")
        d2, _ = switch(d, seq=1)
        d3, _ = switch(d2, seq=2)
        self.assertEqual(d3.active, "blue")
        self.assertEqual(d3.previous, "green")
        self.assertEqual(d3.switches, 2)

    def test_switch_bad_seq_rejected(self):
        d = create("v1", "v2")
        for bad in (-1, True, "1", None):
            with self.assertRaises(BlueGreenError):
                switch(d, seq=bad)

    def test_switch_wrong_type_rejected(self):
        with self.assertRaises(BlueGreenError):
            switch("not-a-deployment", seq=1)


class TestRollback(unittest.TestCase):
    def test_rollback_restores_previous(self):
        d = create("v1", "v2")
        d2, _ = switch(d, seq=1)
        d3, rec = rollback(d2, seq=2)
        self.assertEqual(d3.active, "blue")
        self.assertEqual(d3.serving(), "v1")
        self.assertEqual(d3.previous, "green")
        self.assertEqual(rec.action, "rollback")

    def test_rollback_with_no_history_fails_closed(self):
        d = create("v1", "v2")
        with self.assertRaises(BlueGreenError):
            rollback(d, seq=1)

    def test_rollback_is_immutable(self):
        d = create("v1", "v2")
        d2, _ = switch(d, seq=1)
        rollback(d2, seq=2)
        self.assertEqual(d2.active, "green")

    def test_rollback_after_rollback(self):
        d = create("v1", "v2")
        d2, _ = switch(d, seq=1)
        d3, _ = rollback(d2, seq=2)
        d4, _ = rollback(d3, seq=3)
        self.assertEqual(d4.active, "green")
        self.assertEqual(d4.serving(), "v2")

    def test_rollback_bad_seq_rejected(self):
        d = create("v1", "v2")
        d2, _ = switch(d, seq=1)
        with self.assertRaises(BlueGreenError):
            rollback(d2, seq=-1)

    def test_rollback_wrong_type_rejected(self):
        with self.assertRaises(BlueGreenError):
            rollback(None, seq=1)


class TestRecords(unittest.TestCase):
    def test_deployment_frozen(self):
        d = create("v1", "v2")
        with self.assertRaises(Exception):
            d.active = "green"  # type: ignore

    def test_deployment_as_dict(self):
        d = create("v1", "v2")
        asd = d.as_dict()
        self.assertEqual(asd["schema"], BLUE_GREEN_DEPLOY_SCHEMA)
        self.assertEqual(asd["active"], "blue")
        self.assertIsNone(asd["previous"])

    def test_switch_record_bad_action_rejected(self):
        d = create("v1", "v2")
        with self.assertRaises(BlueGreenError):
            SwitchRecord(deployment=d, action="deploy", seq=1)

    def test_switch_record_as_dict(self):
        d = create("v1", "v2")
        _, rec = switch(d, seq=7)
        asd = rec.as_dict()
        self.assertEqual(asd["schema"], BLUE_GREEN_DEPLOY_SCHEMA)
        self.assertEqual(asd["action"], "switch")
        self.assertEqual(asd["seq"], 7)


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        d = create("v1", "v2")
        _, rec = switch(d, seq=3)
        ev = blue_green_audit_event(rec, "completed")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "blue-green.switch")
        self.assertEqual(ev["outcome"], "completed")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["serving"], "v2")
        self.assertEqual(ev["active"], "green")
        self.assertEqual(ev["previous"], "blue")

    def test_audit_bad_outcome_rejected(self):
        d = create("v1", "v2")
        _, rec = switch(d, seq=1)
        with self.assertRaises(BlueGreenError):
            blue_green_audit_event(rec, "maybe")

    def test_audit_wrong_record_type_rejected(self):
        with self.assertRaises(BlueGreenError):
            blue_green_audit_event("nope", "completed")


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        bgd.main()


if __name__ == "__main__":
    unittest.main()
