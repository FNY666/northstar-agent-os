"""Tests for kill_switch_distributed: 2-of-3 host quorum variant."""
from __future__ import annotations

import os
import unittest

import ed25519

from kill_switch_distributed import (
    BASIS_ALLOW,
    BASIS_TRIGGERED,
    DEFAULT_QUORUM,
    KILL_SWITCH_DISTRIBUTED_VERSION,
    SCHEMA_PIN,
    VOTE_STAND_DOWN,
    VOTE_TRIGGER,
    DistributedKillSwitch,
    HostVote,
    QuorumError,
    Vote,
    cast_vote,
    verify_vote,
)


def _fleet(n=3):
    secrets = {f"host-{i}": os.urandom(32) for i in range(n)}
    pubkeys = {h: ed25519.public_key(s) for h, s in secrets.items()}
    return secrets, pubkeys


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(KILL_SWITCH_DISTRIBUTED_VERSION, "kill-switch-distributed.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.kill-switch-distributed.v1")
        self.assertEqual(DEFAULT_QUORUM, 2)


class CastVerifyTests(unittest.TestCase):
    def setUp(self):
        self.secrets, self.pubkeys = _fleet()

    def test_cast_shape_verifies(self):
        v = cast_vote("host-0", VOTE_TRIGGER, 7, self.secrets["host-0"])
        self.assertIsInstance(v, HostVote)
        self.assertEqual(v.host_id, "host-0")
        self.assertEqual(v.vote, VOTE_TRIGGER)
        self.assertEqual(v.seq, 7)
        self.assertTrue(verify_vote(v, self.pubkeys))

    def test_vote_enum_accepted(self):
        v = cast_vote("host-1", Vote.STAND_DOWN, 3, self.secrets["host-1"])
        self.assertEqual(v.vote, VOTE_STAND_DOWN)
        self.assertTrue(verify_vote(v, self.pubkeys))

    def test_wrong_key_fails(self):
        v = cast_vote("host-0", VOTE_TRIGGER, 1, self.secrets["host-0"])
        other_pubkeys = dict(self.pubkeys)
        other_pubkeys["host-0"] = ed25519.public_key(os.urandom(32))
        self.assertFalse(verify_vote(v, other_pubkeys))

    def test_tampered_vote_fails(self):
        v = cast_vote("host-0", VOTE_TRIGGER, 1, self.secrets["host-0"])
        tampered = HostVote(host_id="host-0", vote=VOTE_STAND_DOWN, seq=1,
                            signature=v.signature)
        self.assertFalse(verify_vote(tampered, self.pubkeys))

    def test_unknown_host_fails(self):
        v = cast_vote("mallory", VOTE_TRIGGER, 1, os.urandom(32))
        self.assertFalse(verify_vote(v, self.pubkeys))

    def test_malformed_never_raises(self):
        self.assertFalse(verify_vote(None, self.pubkeys))
        self.assertFalse(verify_vote("not-a-vote", self.pubkeys))
        self.assertFalse(verify_vote(HostVote("host-0", VOTE_TRIGGER, 1, b"short"),
                                     self.pubkeys))

    def test_hostvote_frozen(self):
        v = cast_vote("host-0", VOTE_TRIGGER, 1, self.secrets["host-0"])
        with self.assertRaises(Exception):
            v.seq = 99  # type: ignore

    def test_cast_validation(self):
        with self.assertRaises(ValueError):
            cast_vote("", VOTE_TRIGGER, 1, self.secrets["host-0"])
        with self.assertRaises(ValueError):
            cast_vote("host-0", "nuke", 1, self.secrets["host-0"])
        with self.assertRaises(TypeError):
            cast_vote("host-0", VOTE_TRIGGER, True, self.secrets["host-0"])
        with self.assertRaises(ValueError):
            cast_vote("host-0", VOTE_TRIGGER, -1, self.secrets["host-0"])
        with self.assertRaises(ValueError):
            cast_vote("host-0", VOTE_TRIGGER, 1, b"short")


class QuorumRuleTests(unittest.TestCase):
    def setUp(self):
        self.secrets, self.pubkeys = _fleet()
        self.gate = DistributedKillSwitch(self.pubkeys)

    def _votes(self, *host_ids, vote=VOTE_TRIGGER, seq=1):
        return [cast_vote(h, vote, seq, self.secrets[h]) for h in host_ids]

    def test_two_valid_trigger_votes_reach_quorum(self):
        self.assertTrue(self.gate.trigger(self._votes("host-0", "host-1")))

    def test_three_trigger_votes_reach_quorum(self):
        self.assertTrue(self.gate.trigger(self._votes("host-0", "host-1", "host-2")))

    def test_single_host_cannot_trigger(self):
        # The core safety property: one vote is never enough.
        self.assertFalse(self.gate.trigger(self._votes("host-0")))

    def test_byzantine_single_malicious_host_cannot_trigger(self):
        # Mallory forges a vote with her own key (not in the host set) and
        # pairs it with one honest vote: still 1 < 2.
        honest = self._votes("host-0")
        forged = cast_vote("mallory", VOTE_TRIGGER, 1, os.urandom(32))
        self.assertFalse(self.gate.trigger(honest + [forged]))

    def test_byzantine_forged_signature_for_known_host_fails(self):
        # Mallory signs as host-1 with the wrong key: verification drops it.
        v0 = self._votes("host-0")[0]
        fake = HostVote(host_id="host-1", vote=VOTE_TRIGGER, seq=1,
                        signature=os.urandom(64))
        self.assertFalse(verify_vote(fake, self.pubkeys))
        self.assertFalse(self.gate.trigger([v0, fake]))

    def test_duplicate_votes_from_same_host_count_once(self):
        v = self._votes("host-0")[0]
        self.assertEqual(self.gate.count_trigger_votes([v, v]), 1)
        self.assertFalse(self.gate.trigger([v, v]))

    def test_two_trigger_one_stand_down_still_triggers(self):
        votes = (self._votes("host-0", "host-1")
                 + self._votes("host-2", vote=VOTE_STAND_DOWN))
        self.assertTrue(self.gate.trigger(votes))

    def test_one_trigger_two_stand_down_does_not_trigger(self):
        votes = (self._votes("host-0")
                 + self._votes("host-1", "host-2", vote=VOTE_STAND_DOWN))
        self.assertFalse(self.gate.trigger(votes))

    def test_empty_votes_never_trigger(self):
        self.assertFalse(self.gate.trigger([]))

    def test_poisoned_batch_does_not_raise(self):
        votes = self._votes("host-0", "host-1") + [None, "garbage", 42]
        self.assertTrue(self.gate.trigger(votes))


class StatefulGateTests(unittest.TestCase):
    def setUp(self):
        self.secrets, self.pubkeys = _fleet()
        self.gate = DistributedKillSwitch(self.pubkeys)

    def _votes(self, *host_ids, vote=VOTE_TRIGGER, seq=1):
        return [cast_vote(h, vote, seq, self.secrets[h]) for h in host_ids]

    def test_check_allows_before_trigger(self):
        self.assertEqual(self.gate.check(), (True, BASIS_ALLOW))
        self.assertFalse(self.gate.triggered)

    def test_record_trigger_denies_check(self):
        self.gate.record_trigger(self._votes("host-0", "host-1"), 5, "fleet kill")
        self.assertTrue(self.gate.triggered)
        self.assertEqual(self.gate.check(), (False, BASIS_TRIGGERED))

    def test_record_trigger_without_quorum_raises(self):
        with self.assertRaises(QuorumError):
            self.gate.record_trigger(self._votes("host-0"), 5, "lone wolf")
        self.assertFalse(self.gate.triggered)
        self.assertEqual(self.gate.check(), (True, BASIS_ALLOW))

    def test_record_stand_down_clears_trigger(self):
        self.gate.record_trigger(self._votes("host-0", "host-1"), 5, "kill")
        self.gate.record_stand_down(
            self._votes("host-1", "host-2", vote=VOTE_STAND_DOWN), 6, "all clear")
        self.assertFalse(self.gate.triggered)
        self.assertEqual(self.gate.check(), (True, BASIS_ALLOW))

    def test_stand_down_without_quorum_raises(self):
        self.gate.record_trigger(self._votes("host-0", "host-1"), 5, "kill")
        with self.assertRaises(QuorumError):
            self.gate.record_stand_down(
                self._votes("host-2", vote=VOTE_STAND_DOWN), 6, "lone clear")
        self.assertTrue(self.gate.triggered)

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            DistributedKillSwitch({})
        with self.assertRaises(ValueError):
            DistributedKillSwitch(self.pubkeys, quorum=4)
        with self.assertRaises(ValueError):
            DistributedKillSwitch(self.pubkeys, quorum=0)
        with self.assertRaises(TypeError):
            DistributedKillSwitch(self.pubkeys, quorum=True)
        bad = dict(self.pubkeys)
        bad["host-0"] = b"short"
        with self.assertRaises(ValueError):
            DistributedKillSwitch(bad)

    def test_custom_quorum(self):
        gate = DistributedKillSwitch(self.pubkeys, quorum=3)
        self.assertFalse(gate.trigger(self._votes("host-0", "host-1")))
        self.assertTrue(gate.trigger(self._votes("host-0", "host-1", "host-2")))

    def test_as_dict(self):
        d = self.gate.as_dict()
        self.assertEqual(d["quorum"], 2)
        self.assertEqual(d["hosts"], ("host-0", "host-1", "host-2"))
        self.assertFalse(d["triggered"])

    def test_main_smoke(self):
        from kill_switch_distributed import main
        main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
