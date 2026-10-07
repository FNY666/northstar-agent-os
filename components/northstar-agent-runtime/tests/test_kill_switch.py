"""Tests for kill_switch: host kill switch with rollback points (WAAL liability)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import warnings

import kill_switch
from kill_switch import (
    BASIS_ALLOW,
    BASIS_TRIGGERED,
    EVENT_ARMED,
    EVENT_DISARMED,
    EVENT_ROLLBACK,
    EVENT_TRIGGERED,
    KILL_SWITCH_VERSION,
    SCHEMA_PIN,
    KillSwitch,
    LiabilityRecord,
    RollbackPoint,
    RollbackRecord,
)


def make_switch(**kwargs):
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "kill-switch.json")
    return KillSwitch(path, **kwargs), tmp


class FreshSwitchTests(unittest.TestCase):
    def test_fresh_switch_is_disarmed_and_allows(self):
        ks, _ = make_switch()
        self.assertFalse(ks.is_armed)
        self.assertFalse(ks.is_triggered)
        self.assertEqual(ks.check(), (True, BASIS_ALLOW))

    def test_module_version_and_schema_pin(self):
        self.assertEqual(KILL_SWITCH_VERSION, "kill-switch.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.kill-switch.v1")


class ArmDisarmTests(unittest.TestCase):
    def test_arm_transitions_and_is_idempotent(self):
        ks, _ = make_switch()
        self.assertTrue(ks.arm("upgrade window", seq=1))
        self.assertTrue(ks.is_armed)
        self.assertFalse(ks.arm("again", seq=2))  # already armed
        self.assertEqual(ks.check(), (True, BASIS_ALLOW))

    def test_disarm_transitions_and_is_idempotent(self):
        ks, _ = make_switch()
        ks.arm("window", seq=1)
        self.assertTrue(ks.disarm(seq=2))
        self.assertFalse(ks.is_armed)
        self.assertFalse(ks.disarm(seq=3))  # already disarmed

    def test_arm_requires_nonempty_reason(self):
        ks, _ = make_switch()
        with self.assertRaises(ValueError):
            ks.arm("", seq=1)

    def test_arm_rejects_bad_seq(self):
        ks, _ = make_switch()
        with self.assertRaises(TypeError):
            ks.arm("x", seq=True)
        with self.assertRaises(ValueError):
            ks.arm("x", seq=-1)


class TriggerTests(unittest.TestCase):
    def test_trigger_denies_everything(self):
        ks, _ = make_switch()
        ks.arm("window", seq=1)
        self.assertTrue(ks.trigger(reason="misbehaving", seq=2))
        self.assertTrue(ks.is_triggered)
        self.assertEqual(ks.check(), (False, BASIS_TRIGGERED))

    def test_trigger_fires_from_disarmed(self):
        # An emergency brake must always fire, even if never armed.
        ks, _ = make_switch()
        self.assertTrue(ks.trigger(reason="panic", seq=1))
        self.assertEqual(ks.check(), (False, BASIS_TRIGGERED))

    def test_trigger_is_idempotent(self):
        ks, _ = make_switch()
        self.assertTrue(ks.trigger(reason="one", seq=1))
        self.assertFalse(ks.trigger(reason="two", seq=2))

    def test_trigger_is_sticky_disarm_refused(self):
        ks, _ = make_switch()
        ks.trigger(reason="x", seq=1)
        with self.assertRaises(ValueError):
            ks.disarm(seq=2)
        with self.assertRaises(ValueError):
            ks.arm("y", seq=3)
        self.assertEqual(ks.check(), (False, BASIS_TRIGGERED))


class RollbackPointTests(unittest.TestCase):
    def test_create_rollback_point_pins_state_hash(self):
        ks, _ = make_switch()
        point = ks.create_rollback_point({"a": 1}, reason="pre-upgrade", seq=10)
        self.assertIsInstance(point, RollbackPoint)
        self.assertTrue(point.point_id.startswith("rp-"))
        self.assertTrue(point.state_hash.startswith("sha256:"))
        self.assertEqual(point.seq, 10)
        self.assertEqual(point.created_reason, "pre-upgrade")
        self.assertEqual(ks.current_state_hash, point.state_hash)

    def test_points_chain_in_creation_order(self):
        ks, _ = make_switch()
        p1 = ks.create_rollback_point({"a": 1}, reason="one", seq=1)
        p2 = ks.create_rollback_point({"a": 2}, reason="two", seq=2)
        self.assertIsNone(p1.prev_point_id)
        self.assertEqual(p2.prev_point_id, p1.point_id)
        self.assertEqual([p.point_id for p in ks.rollback_points()], [p1.point_id, p2.point_id])

    def test_point_ids_are_deterministic(self):
        ks1, _ = make_switch()
        ks2, _ = make_switch()
        p1 = ks1.create_rollback_point({"a": 1}, reason="r", seq=5)
        p2 = ks2.create_rollback_point({"a": 1}, reason="r", seq=5)
        self.assertEqual(p1.point_id, p2.point_id)
        self.assertEqual(p1.state_hash, p2.state_hash)

    def test_state_hash_rejects_malformed(self):
        ks, _ = make_switch()
        with self.assertRaises(TypeError):
            ks.create_rollback_point("not-a-mapping", reason="r", seq=1)  # type: ignore[arg-type]


class RollbackTests(unittest.TestCase):
    def _triggered_with_point(self):
        ks, tmp = make_switch()
        point = ks.create_rollback_point({"v": 1}, reason="good", seq=1)
        ks.create_rollback_point({"v": 2}, reason="later", seq=2)
        ks.trigger(reason="bad", seq=3)
        return ks, tmp, point

    def test_rollback_restores_point_and_clears_trigger(self):
        ks, _, point = self._triggered_with_point()
        record = ks.rollback(point.point_id, reason="restore good", seq=4)
        self.assertIsInstance(record, RollbackRecord)
        self.assertEqual(record.to_point_id, point.point_id)
        self.assertEqual(record.to_state_hash, point.state_hash)
        self.assertEqual(ks.current_state_hash, point.state_hash)
        self.assertFalse(ks.is_triggered)
        self.assertFalse(ks.is_armed)  # left disarmed for deliberate re-arm
        self.assertEqual(ks.check(), (True, BASIS_ALLOW))

    def test_rollback_requires_triggered(self):
        ks, _ = make_switch()
        point = ks.create_rollback_point({"v": 1}, reason="good", seq=1)
        with self.assertRaises(ValueError):
            ks.rollback(point.point_id, reason="r", seq=2)

    def test_rollback_unknown_point_raises_keyerror(self):
        ks, _ = make_switch()
        ks.trigger(reason="x", seq=1)
        with self.assertRaises(KeyError):
            ks.rollback("rp-nope", reason="r", seq=2)

    def test_rollback_log_is_chained(self):
        ks, _, point = self._triggered_with_point()
        r1 = ks.rollback(point.point_id, reason="first", seq=4)
        # trigger again and roll back again to extend the chain
        ks.arm("re-arm", seq=5)
        ks.trigger(reason="bad again", seq=6)
        r2 = ks.rollback(point.point_id, reason="second", seq=7)
        self.assertEqual(r1.prev_digest, "")
        self.assertEqual(r2.prev_digest, r1.digest)
        self.assertEqual(len(ks.rollback_log()), 2)

    def test_rearm_after_rollback(self):
        ks, _, point = self._triggered_with_point()
        ks.rollback(point.point_id, reason="restore", seq=4)
        self.assertTrue(ks.arm("post-incident", seq=5))
        self.assertTrue(ks.is_armed)


class PersistenceTests(unittest.TestCase):
    def test_trigger_survives_restart(self):
        ks, tmp = make_switch()
        path = os.path.join(tmp, "kill-switch.json")
        ks.arm("window", seq=1)
        ks.trigger(reason="bad", seq=2)
        ks2 = KillSwitch(path)
        self.assertTrue(ks2.is_triggered)
        self.assertEqual(ks2.check(), (False, BASIS_TRIGGERED))

    def test_rollback_points_survive_restart(self):
        ks, tmp = make_switch()
        path = os.path.join(tmp, "kill-switch.json")
        point = ks.create_rollback_point({"v": 9}, reason="snap", seq=1)
        ks2 = KillSwitch(path)
        points = ks2.rollback_points()
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0].point_id, point.point_id)
        self.assertEqual(ks2.current_state_hash, point.state_hash)

    def test_corrupt_state_file_fails_closed(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "kill-switch.json")
        with open(path, "w") as fh:
            fh.write("{not valid json")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            ks = KillSwitch(path)
        self.assertTrue(any("corrupt" in str(w.message) for w in caught))
        self.assertTrue(ks.is_triggered)
        self.assertEqual(ks.check(), (False, BASIS_TRIGGERED))

    def test_tampered_state_file_fails_closed(self):
        ks, tmp = make_switch()
        path = os.path.join(tmp, "kill-switch.json")
        ks.arm("window", seq=1)
        with open(path) as fh:
            raw = json.load(fh)
        raw["armed"] = False  # tamper: flip a field without fixing the digest
        with open(path, "w") as fh:
            json.dump(raw, fh)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            ks2 = KillSwitch(path)
        self.assertTrue(any("digest" in str(w.message) for w in caught))
        self.assertTrue(ks2.is_triggered)

    def test_missing_file_starts_fresh(self):
        tmp = tempfile.mkdtemp()
        ks = KillSwitch(os.path.join(tmp, "nope.json"))
        self.assertFalse(ks.is_triggered)
        self.assertEqual(ks.check(), (True, BASIS_ALLOW))


class LiabilityTests(unittest.TestCase):
    def test_every_action_emits_liability_record(self):
        ks, _ = make_switch()
        ks.arm("window", seq=1)
        ks.trigger(reason="bad", seq=2)
        log = ks.liability_log()
        self.assertEqual([r.event for r in log], [EVENT_ARMED, EVENT_TRIGGERED])
        self.assertTrue(all(isinstance(r, LiabilityRecord) for r in log))
        self.assertTrue(all(r.actor == "host" for r in log))

    def test_custom_actor_is_recorded(self):
        ks, tmp = make_switch(actor="ops-oncall")
        ks.arm("window", seq=1)
        self.assertEqual(ks.liability_log()[0].actor, "ops-oncall")

    def test_rollback_emits_liability_record(self):
        ks, _ = make_switch()
        point = ks.create_rollback_point({"v": 1}, reason="good", seq=1)
        ks.trigger(reason="bad", seq=2)
        ks.rollback(point.point_id, reason="restore", seq=3)
        events = [r.event for r in ks.liability_log()]
        self.assertEqual(events, [EVENT_TRIGGERED, EVENT_ROLLBACK])

    def test_liability_chain_verifies(self):
        ks, _ = make_switch()
        ks.arm("w", seq=1)
        ks.trigger(reason="b", seq=2)
        ok, basis = ks.verify_liability_chain()
        self.assertTrue(ok)
        self.assertEqual(basis, "ok")

    def test_liability_chain_detects_tamper(self):
        ks, _ = make_switch()
        ks.arm("w", seq=1)
        raw = ks._liability_log[0]
        raw["reason"] = "tampered reason"
        ok, basis = ks.verify_liability_chain()
        self.assertFalse(ok)
        self.assertIn("digest", basis)

    def test_liability_chain_detects_broken_link(self):
        ks, _ = make_switch()
        ks.arm("w", seq=1)
        ks.trigger(reason="b", seq=2)
        ks._liability_log[1]["prev_digest"] = "sha256:" + "0" * 64
        ok, basis = ks.verify_liability_chain()
        self.assertFalse(ok)
        self.assertIn("link", basis)

    def test_disarm_emits_liability_record(self):
        ks, _ = make_switch()
        ks.arm("w", seq=1)
        ks.disarm(reason="done", seq=2)
        self.assertEqual(ks.liability_log()[-1].event, EVENT_DISARMED)


class CheckNeverRaisesTests(unittest.TestCase):
    def test_check_never_raises(self):
        ks, _ = make_switch()
        for _ in range(3):
            allowed, basis = ks.check()
            self.assertIsInstance(allowed, bool)
            self.assertIsInstance(basis, str)
        ks.trigger(seq=1)
        allowed, basis = ks.check()
        self.assertFalse(allowed)
        self.assertEqual(basis, BASIS_TRIGGERED)


if __name__ == "__main__":
    unittest.main()
