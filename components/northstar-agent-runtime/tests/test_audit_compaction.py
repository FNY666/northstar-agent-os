"""Tests for audit_compaction (targeted: 20 tests)."""
import unittest

import audit_compaction as ac
from audit_compaction import (
    AuditCompactor,
    AuditSegment,
    ChainBrokenError,
    CompactionConflictError,
    CompactionReport,
    CompactedFeed,
    SegmentError,
    SegmentRecord,
)


def _chain(seq, prev_hash, kind):
    body = {"seq": seq, "kind": kind, "prev_hash": prev_hash}
    import hashlib
    from audit_compaction import _canonical_bytes, _SEAL_FIELDS
    chain_hash = hashlib.sha256(
        bytes.fromhex(prev_hash)
        + _canonical_bytes({k: v for k, v in body.items()
                            if k not in _SEAL_FIELDS})).hexdigest()
    body["chain_hash"] = chain_hash
    return body


GENESIS = "cd" * 32


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ac.AUDIT_COMPACTION_VERSION, "audit-compaction.v1")
        self.assertEqual(ac.SCHEMA_PIN, "northstar.audit-compaction.v1")


class TestSegmentValidation(unittest.TestCase):
    def test_bad_origin_rejected(self):
        with self.assertRaises(ValueError):
            AuditSegment("")
        with self.assertRaises(TypeError):
            AuditSegment(123)

    def test_non_mapping_rejected(self):
        seg = AuditSegment("a")
        with self.assertRaises(SegmentError):
            seg.append([("seq", 0)])

    def test_missing_seq_rejected(self):
        seg = AuditSegment("a")
        with self.assertRaises(SegmentError):
            seg.append({"kind": "x"})

    def test_bad_seq_types_rejected(self):
        seg = AuditSegment("a")
        for bad in (True, -1, "0", 1.5, None):
            with self.assertRaises((TypeError, ValueError, SegmentError)):
                seg.append({"seq": bad})

    def test_non_canonicalizable_body_rejected(self):
        seg = AuditSegment("a")
        with self.assertRaises(TypeError):
            seg.append({"seq": 0, "obj": object()})


class TestDigest(unittest.TestCase):
    def test_digest_deterministic_and_key_order_invariant(self):
        seg = AuditSegment("a")
        r1 = seg.append({"seq": 0, "b": 1, "a": 2})
        r2 = seg.append({"seq": 0, "a": 2, "b": 1})
        self.assertEqual(r1.digest, r2.digest)
        self.assertTrue(r1.digest.startswith("sha256:"))

    def test_records_frozen(self):
        seg = AuditSegment("a")
        rec = seg.append({"seq": 0})
        with self.assertRaises(AttributeError):
            rec.seq = 5  # type: ignore


class TestChainVerification(unittest.TestCase):
    def test_valid_chain_verifies(self):
        seg = AuditSegment("a")
        r0 = seg.append(_chain(0, GENESIS, "boot"))
        seg.append(_chain(1, r0.body["chain_hash"], "tick"))
        status = seg.verify_chain()
        self.assertTrue(status["ok"])
        self.assertEqual(status["sealed"], 2)
        self.assertEqual(status["unsealed"], 0)

    def test_tampered_body_breaks_chain(self):
        seg = AuditSegment("a")
        r0 = seg.append(_chain(0, GENESIS, "boot"))
        tampered = _chain(1, r0.body["chain_hash"], "tick")
        tampered["kind"] = "evil"
        seg.append(tampered)
        with self.assertRaises(ChainBrokenError):
            seg.verify_chain()

    def test_broken_linkage_breaks_chain(self):
        seg = AuditSegment("a")
        r0 = seg.append(_chain(0, GENESIS, "boot"))
        other = _chain(1, "ef" * 32, "tick")  # wrong prev_hash
        seg.append(other)
        self.assertNotEqual(r0.body["chain_hash"], "ef" * 32)
        with self.assertRaises(ChainBrokenError):
            seg.verify_chain()

    def test_unsealed_records_admitted_but_counted(self):
        seg = AuditSegment("a")
        seg.append({"seq": 0, "kind": "plain"})
        status = seg.verify_chain()
        self.assertEqual(status["unsealed"], 1)


class TestCompaction(unittest.TestCase):
    def _two_segments(self):
        compactor = AuditCompactor()
        seg_a = AuditSegment("host-a")
        r0 = seg_a.append(_chain(0, GENESIS, "boot"))
        seg_a.append(_chain(1, r0.body["chain_hash"], "tick"))
        seg_b = AuditSegment("host-b")
        seg_b.append(dict(r0.body))  # byte-identical redelivery
        seg_b.append({"seq": 3, "kind": "note"})
        compactor.add_segment(seg_a)
        compactor.add_segment(seg_b)
        return compactor

    def test_merge_dedup_orders(self):
        feed = self._two_segments().compact(0)
        self.assertEqual(feed.seqs(), (0, 1, 3))
        self.assertEqual(feed.report.records_in, 4)
        self.assertEqual(feed.report.duplicates_dropped, 1)
        self.assertEqual(feed.report.records_out, 3)
        self.assertEqual(feed.report.segments, 2)

    def test_gaps_reported(self):
        feed = self._two_segments().compact(0)
        self.assertEqual(feed.report.gaps, (2,))

    def test_unsealed_counted(self):
        feed = self._two_segments().compact(0)
        self.assertEqual(feed.report.unsealed_admitted, 1)

    def test_output_byte_identical_chains_still_verify(self):
        feed = self._two_segments().compact(0)
        for rec in feed.records:
            if rec.sealed:
                from audit_compaction import _recompute_chain_hash
                self.assertEqual(_recompute_chain_hash(rec.body),
                                 rec.body["chain_hash"])

    def test_conflict_fail_closed(self):
        compactor = AuditCompactor()
        s1 = AuditSegment("x")
        s1.append({"seq": 0, "kind": "a"})
        s2 = AuditSegment("y")
        s2.append({"seq": 0, "kind": "b"})
        compactor.add_segment(s1)
        compactor.add_segment(s2)
        with self.assertRaises(CompactionConflictError) as ctx:
            compactor.compact(7)
        self.assertEqual(ctx.exception.seqs, (0,))

    def test_broken_segment_never_admitted(self):
        seg = AuditSegment("evil")
        r0 = seg.append(_chain(0, GENESIS, "ok"))
        bad = _chain(1, r0.body["chain_hash"], "ok2")
        bad["kind"] = "tampered"
        seg.append(bad)
        compactor = AuditCompactor()
        with self.assertRaises(ChainBrokenError):
            compactor.add_segment(seg)
        self.assertEqual(compactor.segments(), ())

    def test_empty_compact(self):
        feed = AuditCompactor().compact(3)
        self.assertEqual(feed.records, ())
        self.assertEqual(feed.report.records_out, 0)
        self.assertEqual(feed.report.gaps, ())
        self.assertTrue(feed.report.head_digest.startswith("sha256:"))

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            AuditCompactor().compact(True)

    def test_non_segment_rejected(self):
        with self.assertRaises(TypeError):
            AuditCompactor().add_segment("nope")


class TestReportAndEvents(unittest.TestCase):
    def test_report_frozen_and_as_dict(self):
        feed = AuditCompactor().compact(0)
        rep = feed.report
        self.assertIsInstance(rep, CompactionReport)
        with self.assertRaises(AttributeError):
            rep.records_in = 9  # type: ignore
        d = rep.as_dict()
        self.assertEqual(d["schema"], ac.SCHEMA_PIN)
        self.assertIn("input_digest", d)

    def test_compacted_feed_is_frozen_dataclass(self):
        feed = AuditCompactor().compact(0)
        self.assertIsInstance(feed, CompactedFeed)

    def test_audit_event_shapes(self):
        feed = AuditCompactor().compact(0)
        ev = ac.audit_compaction_audit_event("compacted", 5, report=feed.report)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], ac.SCHEMA_PIN)
        self.assertEqual(ev["kind"], "compacted")
        self.assertEqual(ev["audit_seq"], 5)
        self.assertIn("report", ev)
        ev2 = ac.audit_compaction_audit_event("chain-broken", 6,
                                             detail="link at seq 2")
        self.assertEqual(ev2["detail"], "link at seq 2")
        with self.assertRaises(ValueError):
            ac.audit_compaction_audit_event("nope", 0)
        with self.assertRaises(TypeError):
            ac.audit_compaction_audit_event("compacted", True)
        with self.assertRaises(TypeError):
            ac.audit_compaction_audit_event("compacted", 0, report="x")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        ac.main()


if __name__ == "__main__":
    unittest.main()
