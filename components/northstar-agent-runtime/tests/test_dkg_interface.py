"""Tests for dkg_interface: Pedersen DKG bookkeeping (simulated)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dkg_interface import (
    DKG,
    DKG_INTERFACE_SCHEMA,
    DKG_INTERFACE_VERSION,
    EVENT_COMPLAINT,
    EVENT_FINALIZED,
    EVENT_ROUND1,
    EVENT_SHARE_REJECTED,
    EVENT_SHARE_VERIFIED,
    DealerCommitment,
    DKGError,
    DKGResult,
    DuplicateCommitmentError,
    NoQualifiedDealerError,
    SharePacket,
    ShareVerification,
    dkg_audit_event,
    lagrange_recover,
    main,
    FIELD_PRIME,
    _GENERATOR_G,
    _GENERATOR_H,
    _felt_hex,
    _pedersen_commit,
    _poly_eval,
)

PARTICIPANTS = ["n0", "n1", "n2"]


def make_nodes(t=1):
    return {p: DKG(p, t, PARTICIPANTS) for p in PARTICIPANTS}


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(DKG_INTERFACE_VERSION, "dkg-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(DKG_INTERFACE_SCHEMA, "northstar.dkg-interface.v1")

    def test_generators_nonzero(self):
        self.assertNotEqual(_GENERATOR_G, 0)
        self.assertNotEqual(_GENERATOR_H, 0)
        self.assertNotEqual(_GENERATOR_G, _GENERATOR_H)


class TestConstructor(unittest.TestCase):
    def test_happy(self):
        d = DKG("n0", 1, PARTICIPANTS)
        self.assertEqual(d.participants, ("n0", "n1", "n2"))
        self.assertEqual(d.my_index, 1)
        self.assertEqual(d.threshold, 1)

    def test_indices_sorted(self):
        d = DKG("n2", 1, ["n2", "n0", "n1"])
        self.assertEqual(d.my_index, 3)

    def test_bad_t_type(self):
        with self.assertRaises(TypeError):
            DKG("n0", True, PARTICIPANTS)

    def test_negative_t(self):
        with self.assertRaises(ValueError):
            DKG("n0", -1, PARTICIPANTS)

    def test_t_too_large(self):
        with self.assertRaises(ValueError):
            DKG("n0", 3, PARTICIPANTS)

    def test_duplicate_participants(self):
        with self.assertRaises(ValueError):
            DKG("n0", 1, ["n0", "n0", "n1"])

    def test_node_not_participant(self):
        with self.assertRaises(ValueError):
            DKG("ghost", 1, PARTICIPANTS)

    def test_empty_node_id(self):
        with self.assertRaises(ValueError):
            DKG("  ", 1, PARTICIPANTS)

    def test_empty_participants(self):
        with self.assertRaises(ValueError):
            DKG("n0", 0, [])


class TestRound1(unittest.TestCase):
    def setUp(self):
        self.d = DKG("n0", 1, PARTICIPANTS)

    def test_round1_shape(self):
        commitment, packets = self.d.round1([5, 7], [11, 13], seq=1)
        self.assertIsInstance(commitment, DealerCommitment)
        self.assertEqual(len(commitment.commitments), 2)
        self.assertEqual(len(packets), 3)
        self.assertTrue(all(isinstance(p, SharePacket) for p in packets))
        self.assertEqual(
            [p.recipient_id for p in packets], ["n0", "n1", "n2"]
        )
        self.assertEqual([p.recipient_index for p in packets], [1, 2, 3])

    def test_commitment_is_pedersen(self):
        commitment, _ = self.d.round1([5, 7], [11, 13], seq=1)
        self.assertEqual(commitment.commitments[0], _pedersen_commit(5, 11))
        self.assertEqual(commitment.commitments[1], _pedersen_commit(7, 13))

    def test_share_is_poly_eval(self):
        _, packets = self.d.round1([5, 7], [11, 13], seq=1)
        self.assertEqual(packets[0].share, _poly_eval([5, 7], 1))
        self.assertEqual(packets[2].share, _poly_eval([5, 7], 3))
        self.assertEqual(packets[1].share_blinding, _poly_eval([11, 13], 2))

    def test_wrong_coeff_count(self):
        with self.assertRaises(ValueError):
            self.d.round1([5, 7, 9], [11, 13], seq=1)

    def test_wrong_blinding_count(self):
        with self.assertRaises(ValueError):
            self.d.round1([5, 7], [11], seq=1)

    def test_bool_coeff(self):
        with self.assertRaises(TypeError):
            self.d.round1([True, 7], [11, 13], seq=1)

    def test_out_of_range_coeff(self):
        with self.assertRaises(ValueError):
            self.d.round1([FIELD_PRIME, 7], [11, 13], seq=1)

    def test_negative_coeff(self):
        with self.assertRaises(ValueError):
            self.d.round1([-1, 7], [11, 13], seq=1)

    def test_negative_seq(self):
        with self.assertRaises(ValueError):
            self.d.round1([5, 7], [11, 13], seq=-1)

    def test_non_sequence_coeffs(self):
        with self.assertRaises(TypeError):
            self.d.round1("ab", [11, 13], seq=1)

    def test_commitment_digest_deterministic(self):
        c1, _ = self.d.round1([5, 7], [11, 13], seq=1)
        d2 = DKG("n0", 1, PARTICIPANTS)
        c2, _ = d2.round1([5, 7], [11, 13], seq=1)
        self.assertEqual(c1.digest, c2.digest)

    def test_as_dict_hex(self):
        commitment, packets = self.d.round1([5, 7], [11, 13], seq=1)
        d = commitment.as_dict()
        self.assertTrue(all(len(h) == 64 for h in d["commitments"]))
        pd = packets[0].as_dict()
        self.assertEqual(len(pd["share"]), 64)


class TestRound2(unittest.TestCase):
    def setUp(self):
        self.nodes = make_nodes()
        self.c0, self.pkts0 = self.nodes["n0"].round1([5, 7], [11, 13], seq=1)

    def test_verify_own_share(self):
        mine = next(p for p in self.pkts0 if p.recipient_id == "n0")
        verdict = self.nodes["n0"].round2(mine, seq=2)
        self.assertTrue(verdict.valid)
        self.assertIsInstance(verdict, ShareVerification)

    def test_verify_others_share_after_receive(self):
        self.nodes["n1"].receive_commitment(self.c0)
        mine = next(p for p in self.pkts0 if p.recipient_id == "n1")
        verdict = self.nodes["n1"].round2(mine, seq=2)
        self.assertTrue(verdict.valid)

    def test_tampered_share_invalid(self):
        self.nodes["n1"].receive_commitment(self.c0)
        mine = next(p for p in self.pkts0 if p.recipient_id == "n1")
        tampered = SharePacket(
            dealer_id=mine.dealer_id,
            recipient_id=mine.recipient_id,
            recipient_index=mine.recipient_index,
            share=(mine.share + 1) % FIELD_PRIME,
            share_blinding=mine.share_blinding,
            packet_seq=mine.packet_seq,
            digest=mine.digest,  # stale digest: values not dealer-minted
        )
        verdict = self.nodes["n1"].round2(tampered, seq=2)
        self.assertFalse(verdict.valid)
        self.assertIn("digest", verdict.reason)

    def test_share_failing_equation_invalid(self):
        # Re-mint a packet with consistent digest but a wrong share value.
        self.nodes["n1"].receive_commitment(self.c0)
        mine = next(p for p in self.pkts0 if p.recipient_id == "n1")
        bad_share = (mine.share + 1) % FIELD_PRIME
        body = {
            "dealer_id": mine.dealer_id,
            "recipient_id": mine.recipient_id,
            "recipient_index": mine.recipient_index,
            "share": _felt_hex(bad_share),
            "share_blinding": _felt_hex(mine.share_blinding),
            "packet_seq": mine.packet_seq,
        }
        import hashlib, json
        digest = "sha256:" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        forged = SharePacket(
            dealer_id=mine.dealer_id,
            recipient_id=mine.recipient_id,
            recipient_index=mine.recipient_index,
            share=bad_share,
            share_blinding=mine.share_blinding,
            packet_seq=mine.packet_seq,
            digest=digest,
        )
        verdict = self.nodes["n1"].round2(forged, seq=2)
        self.assertFalse(verdict.valid)
        self.assertIn("Pedersen", verdict.reason)

    def test_wrong_recipient(self):
        mine = next(p for p in self.pkts0 if p.recipient_id == "n0")
        with self.assertRaises(DKGError):
            self.nodes["n1"].round2(mine, seq=2)

    def test_no_commitment(self):
        mine = next(p for p in self.pkts0 if p.recipient_id == "n2")
        with self.assertRaises(DKGError):
            self.nodes["n2"].round2(mine, seq=2)

    def test_bad_packet_type(self):
        with self.assertRaises(TypeError):
            self.nodes["n0"].round2("nope", seq=2)

    def test_disqualified_dealer_verdict(self):
        self.nodes["n1"].receive_commitment(self.c0)
        self.nodes["n1"].complaint("n0", seq=5)
        mine = next(p for p in self.pkts0 if p.recipient_id == "n1")
        verdict = self.nodes["n1"].round2(mine, seq=6)
        self.assertFalse(verdict.valid)
        self.assertIn("disqualified", verdict.reason)


class TestCommitments(unittest.TestCase):
    def setUp(self):
        self.nodes = make_nodes()
        self.c0, _ = self.nodes["n0"].round1([5, 7], [11, 13], seq=1)

    def test_receive_ok(self):
        self.assertTrue(self.nodes["n1"].receive_commitment(self.c0))

    def test_duplicate(self):
        self.nodes["n1"].receive_commitment(self.c0)
        with self.assertRaises(DuplicateCommitmentError):
            self.nodes["n1"].receive_commitment(self.c0)

    def test_unknown_dealer(self):
        c1, _ = self.nodes["n1"].round1([3, 17], [19, 23], seq=1)
        other = DKG("n0", 1, ["n0", "n9", "n8"])
        with self.assertRaises(DKGError):
            other.receive_commitment(c1)

    def test_threshold_mismatch(self):
        wide = DKG("n0", 2, ["n0", "n1", "n2", "n3"])
        cw, _ = wide.round1([1, 2, 3], [4, 5, 6], seq=1)
        with self.assertRaises(DKGError):
            self.nodes["n1"].receive_commitment(cw)

    def test_bad_type(self):
        with self.assertRaises(TypeError):
            self.nodes["n1"].receive_commitment("nope")


class TestComplaint(unittest.TestCase):
    def test_complaint_flow(self):
        nodes = make_nodes()
        c0, _ = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        nodes["n1"].receive_commitment(c0)
        self.assertTrue(nodes["n1"].complaint("n0", seq=9))
        self.assertEqual(nodes["n1"].qualified_dealers(), ())

    def test_complaint_unknown(self):
        nodes = make_nodes()
        with self.assertRaises(DKGError):
            nodes["n1"].complaint("ghost", seq=1)

    def test_complaint_event_logged(self):
        nodes = make_nodes()
        nodes["n1"].complaint("n0", seq=9)
        kinds = [e["kind"] for e in nodes["n1"].events()]
        self.assertIn(EVENT_COMPLAINT, kinds)


class TestFinalize(unittest.TestCase):
    def _run(self, complain_n1=False):
        nodes = make_nodes()
        c0, pkts0 = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        c1, pkts1 = nodes["n1"].round1([3, 17], [19, 23], seq=2)
        by_dealer = {c0.dealer_id: (c0, pkts0), c1.dealer_id: (c1, pkts1)}
        for p, node in nodes.items():
            for dealer_id, (commitment, packets) in by_dealer.items():
                if dealer_id != p:
                    node.receive_commitment(commitment)
                mine = next(q for q in packets if q.recipient_id == p)
                verdict = node.round2(mine, seq=3)
                assert verdict.valid, verdict.reason
        if complain_n1:
            for node in nodes.values():
                node.complaint("n1", seq=4)
        return nodes, c0, c1

    def test_finalize_group_key(self):
        nodes, c0, c1 = self._run()
        expected = (c0.commitments[0] + c1.commitments[0]) % FIELD_PRIME
        for p in PARTICIPANTS:
            r = nodes[p].finalize(seq=5)
            self.assertIsInstance(r, DKGResult)
            self.assertEqual(r.group_key, expected)
            self.assertEqual(r.qualified_dealers, ("n0", "n1"))

    def test_finalize_my_share(self):
        nodes, _, _ = self._run()
        # n2 (index 3): f0(3) + f1(3) = (5+21) + (3+51) = 80.
        r = nodes["n2"].finalize(seq=5)
        self.assertEqual(r.my_share, (26 + 54) % FIELD_PRIME)

    def test_finalize_no_qualified(self):
        nodes = make_nodes()
        with self.assertRaises(NoQualifiedDealerError):
            nodes["n0"].finalize(seq=1)

    def test_complaint_excludes_dealer(self):
        nodes, c0, _ = self._run(complain_n1=True)
        r = nodes["n2"].finalize(seq=5)
        self.assertEqual(r.qualified_dealers, ("n0",))
        self.assertEqual(r.group_key, c0.commitments[0])

    def test_result_digest_shape(self):
        nodes, _, _ = self._run()
        r = nodes["n0"].finalize(seq=5)
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertEqual(len(r.digest), 7 + 64)

    def test_finalize_event_logged(self):
        nodes, _, _ = self._run()
        nodes["n0"].finalize(seq=5)
        kinds = [e["kind"] for e in nodes["n0"].events()]
        self.assertIn(EVENT_ROUND1, kinds)
        self.assertIn(EVENT_FINALIZED, kinds)

    def test_events_tuple(self):
        nodes, _, _ = self._run()
        self.assertIsInstance(nodes["n0"].events(), tuple)


class TestLagrange(unittest.TestCase):
    def test_recover_group_secret(self):
        nodes, _, _ = TestFinalize()._run()
        results = {p: nodes[p].finalize(seq=5) for p in PARTICIPANTS}
        shares = [(nodes[p].my_index, results[p].my_share) for p in ("n0", "n2")]
        # Group secret = 5 + 3 = 8.
        self.assertEqual(lagrange_recover(shares), 8)

    def test_recover_other_subset(self):
        nodes, _, _ = TestFinalize()._run()
        results = {p: nodes[p].finalize(seq=5) for p in PARTICIPANTS}
        shares = [(nodes[p].my_index, results[p].my_share) for p in ("n1", "n2")]
        self.assertEqual(lagrange_recover(shares), 8)

    def test_empty(self):
        with self.assertRaises(ValueError):
            lagrange_recover([])

    def test_duplicate_indices(self):
        with self.assertRaises(ValueError):
            lagrange_recover([(1, 5), (1, 7)])

    def test_bad_pair_shape(self):
        with self.assertRaises(TypeError):
            lagrange_recover([(1, 5, 9)])

    def test_non_sequence(self):
        with self.assertRaises(TypeError):
            lagrange_recover("nope")


class TestAudit(unittest.TestCase):
    def test_event_shape(self):
        nodes = make_nodes()
        c0, _ = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        ev = dkg_audit_event(EVENT_ROUND1, c0, seq=7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], EVENT_ROUND1)
        self.assertEqual(ev["seq"], 7)
        self.assertIn("digest", ev["body"])

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            dkg_audit_event("bogus", {}, seq=1)

    def test_bad_seq(self):
        nodes = make_nodes()
        c0, _ = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        with self.assertRaises(ValueError):
            dkg_audit_event(EVENT_ROUND1, c0, seq=-1)

    def test_rejected_event_logged(self):
        nodes = make_nodes()
        c0, pkts0 = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        nodes["n1"].receive_commitment(c0)
        mine = next(p for p in pkts0 if p.recipient_id == "n1")
        bad = SharePacket(
            dealer_id=mine.dealer_id,
            recipient_id=mine.recipient_id,
            recipient_index=mine.recipient_index,
            share=(mine.share + 2) % FIELD_PRIME,
            share_blinding=mine.share_blinding,
            packet_seq=mine.packet_seq,
            digest=mine.digest,
        )
        nodes["n1"].round2(bad, seq=2)
        kinds = [e["kind"] for e in nodes["n1"].events()]
        self.assertIn(EVENT_SHARE_REJECTED, kinds)

    def test_verified_event_logged(self):
        nodes = make_nodes()
        c0, pkts0 = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        nodes["n1"].receive_commitment(c0)
        mine = next(p for p in pkts0 if p.recipient_id == "n1")
        nodes["n1"].round2(mine, seq=2)
        kinds = [e["kind"] for e in nodes["n1"].events()]
        self.assertIn(EVENT_SHARE_VERIFIED, kinds)


class TestRecords(unittest.TestCase):
    def test_frozen_commitment(self):
        nodes = make_nodes()
        c0, _ = nodes["n0"].round1([5, 7], [11, 13], seq=1)
        with self.assertRaises(Exception):
            c0.dealer_id = "x"  # noqa: B018

    def test_verification_bad_reason(self):
        with self.assertRaises(ValueError):
            ShareVerification("n0", "n1", True, "  ")

    def test_verification_bad_valid(self):
        with self.assertRaises(TypeError):
            ShareVerification("n0", "n1", "yes", "ok")


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
