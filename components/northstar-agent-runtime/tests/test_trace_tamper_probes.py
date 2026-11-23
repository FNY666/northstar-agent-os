"""Tests for the trace-tampering / channel-independence / integrity probe corpus.

Trace tampering is the audit-log threat shape: an operator edits, deletes,
reorders, or re-exports trace history to erase evidence. These tests pin
the corpus shape (10 attack probes across 3 families, 3 benign controls)
and the deletion / cross-channel / integrity detector semantics.
"""

import unittest

import trace_tamper_probes as ttp

EXPECTED_PROBE_NAMES = (
    # trace-deletion
    "deletion-gap-middle",
    "deletion-tail-truncate",
    "deletion-selective-incident",
    "deletion-reexport-fresh-chain",
    # channel-divergence
    "diverge-primary-edited",
    "diverge-witness-silent",
    "diverge-both-rewritten",
    # integrity-seal
    "seal-payload-edit",
    "seal-reorder",
    "seal-genesis-swap",
)

EXPECTED_BENIGN_NAMES = (
    "benign-rotation-rekey",
    "benign-compaction-tombstone",
    "benign-dual-channel-agree",
)

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)

TS = "2026-10-07T08:00:00Z"


def _record(seq, event="tool_call", payload=None, prev=""):
    return ttp.build_record(
        seq,
        event,
        payload if payload is not None else {"detail": f"record-{seq}"},
        TS,
        previous_digest=prev,
    )


def _chained_trace(n):
    """A clean n-record trace with proper chain linkage."""
    trace = ttp.AuditTrace()
    prev = ""
    for seq in range(1, n + 1):
        rec = _record(seq, prev=prev)
        trace.append(rec)
        prev = rec.digest
    return trace


class TestCorpusShape(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ttp.TRACE_TAMPER_VERSION, "trace-tamper.v1")

    def test_corpus_shape(self):
        self.assertEqual(ttp.probe_names(), EXPECTED_PROBE_NAMES)
        self.assertEqual(ttp.benign_names(), EXPECTED_BENIGN_NAMES)

    def test_at_least_two_probes_per_family(self):
        for family in ("trace-deletion", "channel-divergence", "integrity-seal"):
            self.assertGreaterEqual(
                len(ttp.probes_by_family(family)), 2, family
            )

    def test_required_keys(self):
        for name in (*EXPECTED_PROBE_NAMES, *EXPECTED_BENIGN_NAMES):
            probe = ttp.probe_by_name(name)
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, f"{name} missing {key}")

    def test_name_uniqueness(self):
        names = [*EXPECTED_PROBE_NAMES, *EXPECTED_BENIGN_NAMES]
        self.assertEqual(len(set(names)), len(names))

    def test_attacks_deny_benign_allow(self):
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(ttp.probe_by_name(name)["expected"], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(ttp.probe_by_name(name)["expected"], "allow", name)

    def test_deny_side_keyword(self):
        for name in EXPECTED_PROBE_NAMES:
            text = ttp.probe_by_name(name)["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{name} has no deny-side keyword",
            )

    def test_accessor_round_trips(self):
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(ttp.probe_by_name(name)["probe"], name)
        with self.assertRaises(KeyError):
            ttp.probe_by_name("no-such-probe")

    def test_expected_outcomes(self):
        outcomes = ttp.expected_outcomes()
        self.assertEqual(len(outcomes), len(EXPECTED_PROBE_NAMES) + len(EXPECTED_BENIGN_NAMES))
        self.assertEqual(outcomes["seal-payload-edit"], "deny")
        self.assertEqual(outcomes["benign-dual-channel-agree"], "allow")


class TestRecordSeal(unittest.TestCase):
    def test_build_and_verify(self):
        rec = _record(1)
        self.assertTrue(ttp.verify_record(rec))

    def test_tamper_detected(self):
        rec = _record(1, payload={"outcome": "denied"})
        tampered = ttp.TraceRecord(
            seq=rec.seq,
            event=rec.event,
            payload={"outcome": "approved"},  # flipped in place
            recorded_at=rec.recorded_at,
            previous_digest=rec.previous_digest,
            digest=rec.digest,
        )
        self.assertFalse(ttp.verify_record(tampered))

    def test_digest_rejects_non_dict_payload(self):
        with self.assertRaises(ValueError):
            ttp.build_record(1, "e", "not-a-dict", TS)

    def test_build_rejects_bad_seq(self):
        with self.assertRaises(ValueError):
            ttp.build_record(0, "e", {}, TS)
        with self.assertRaises(ValueError):
            ttp.build_record(True, "e", {}, TS)

    def test_frozen(self):
        rec = _record(1)
        with self.assertRaises(Exception):
            rec.seq = 99  # type: ignore[misc]

    def test_digest_deterministic_and_distinguishing(self):
        a = _record(1, payload={"x": 1})
        b = _record(1, payload={"x": 1})
        c = _record(1, payload={"x": 2})
        self.assertEqual(a.digest, b.digest)
        self.assertNotEqual(a.digest, c.digest)


class TestAppendFailClosed(unittest.TestCase):
    def test_append_contiguity(self):
        trace = ttp.AuditTrace()
        trace.append(_record(1))
        with self.assertRaises(ValueError):
            trace.append(_record(3, prev=trace.records()[-1].digest))

    def test_append_rejects_unverifiable(self):
        good = _record(1)
        bad = ttp.TraceRecord(
            seq=1, event=good.event, payload={"x": "forged"},
            recorded_at=good.recorded_at, previous_digest="",
            digest=good.digest,
        )
        trace = ttp.AuditTrace()
        with self.assertRaises(ValueError):
            trace.append(bad)

    def test_append_chain_link(self):
        trace = ttp.AuditTrace()
        first = _record(1)
        trace.append(first)
        # Wrong previous_digest: links to a digest that is not the tail.
        other = _record(1, payload={"other": True})
        second = _record(2, prev=other.digest)
        with self.assertRaises(ValueError):
            trace.append(second)

    def test_genesis_must_not_carry_previous(self):
        trace = ttp.AuditTrace()
        rec = _record(1, prev=_record(9).digest)
        with self.assertRaises(ValueError):
            trace.append(rec)


class TestDeletionDetection(unittest.TestCase):
    def test_clean_trace_no_findings(self):
        trace = _chained_trace(5)
        self.assertEqual(ttp.detect_deletion(trace.records()), [])

    def test_missing_seq_gap(self):
        trace = _chained_trace(7)
        presented = [r for r in trace.records() if r.seq not in (3, 4, 5)]
        findings = ttp.detect_deletion(presented)
        gaps = [f for f in findings if f["kind"] == "missing_seq"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["missing"], [3, 4, 5])
        # seq 6's link dangles: its predecessor (seq 5) is gone.
        breaks = [f for f in findings if f["kind"] == "chain_break"]
        self.assertTrue(any(f["seq"] == 6 for f in breaks))

    def test_prefix_truncation_link_dangles(self):
        trace = _chained_trace(5)
        presented = trace.records()[2:]  # drop seq 1-2, present 3-5
        findings = ttp.detect_deletion(presented)
        breaks = [f for f in findings if f["kind"] == "chain_break"]
        self.assertTrue(any(f["seq"] == 3 for f in breaks))

    def test_empty_list_no_findings(self):
        self.assertEqual(ttp.detect_deletion([]), [])


class TestIntegrityVerification(unittest.TestCase):
    def test_clean_trace_verifies(self):
        trace = _chained_trace(4)
        ok, findings = ttp.verify_trace_integrity(trace.records())
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_payload_edit_fails(self):
        trace = _chained_trace(3)
        recs = list(trace.records())
        edited = ttp.TraceRecord(
            seq=recs[1].seq, event=recs[1].event,
            payload={"outcome": "approved"},  # was a generic detail
            recorded_at=recs[1].recorded_at,
            previous_digest=recs[1].previous_digest,
            digest=recs[1].digest,  # attacker keeps the old seal
        )
        recs[1] = edited
        ok, findings = ttp.verify_trace_integrity(recs)
        self.assertFalse(ok)
        kinds = [f["kind"] for f in findings]
        self.assertIn("bad_digest", kinds)
        # The link still matches the kept digest string, so only the
        # seal breaks -- exactly the signal an in-place edit leaves.

    def test_resealed_edit_without_relink_fails(self):
        trace = _chained_trace(3)
        recs = list(trace.records())
        # Attacker re-seals the edited record (new digest) but does not
        # re-link the downstream record.
        resealed = ttp.build_record(
            2, "tool_call", {"outcome": "approved"}, TS,
            previous_digest=recs[0].digest,
        )
        recs[1] = resealed
        ok, findings = ttp.verify_trace_integrity(recs)
        self.assertFalse(ok)
        kinds = [f["kind"] for f in findings]
        self.assertIn("bad_link", kinds)

    def test_reorder_fails(self):
        trace = _chained_trace(3)
        recs = list(trace.records())
        recs[0], recs[1] = recs[1], recs[0]
        ok, findings = ttp.verify_trace_integrity(recs)
        self.assertFalse(ok)
        self.assertTrue(any(f["kind"] in ("bad_link", "seq_gap") for f in findings))

    def test_gap_fails(self):
        trace = _chained_trace(4)
        recs = [r for r in trace.records() if r.seq != 2]
        ok, findings = ttp.verify_trace_integrity(recs)
        self.assertFalse(ok)
        self.assertTrue(any(f["kind"] == "seq_gap" for f in findings))


class TestHeadDigest(unittest.TestCase):
    def test_head_deterministic(self):
        self.assertEqual(
            _chained_trace(3).head_digest(), _chained_trace(3).head_digest()
        )

    def test_truncation_changes_head(self):
        full = _chained_trace(5)
        short = _chained_trace(3)
        self.assertNotEqual(full.head_digest(), short.head_digest())

    def test_edit_changes_head(self):
        trace = _chained_trace(3)
        before = trace.head_digest()
        recs = list(trace.records())
        edited = ttp.TraceRecord(
            seq=recs[0].seq, event=recs[0].event, payload={"x": "changed"},
            recorded_at=recs[0].recorded_at, previous_digest="",
            digest=recs[0].digest,
        )
        # head is over record digests; a re-sealed edit pins differently
        resealed = ttp.build_record(
            edited.seq, edited.event, edited.payload, edited.recorded_at
        )
        other = ttp.AuditTrace()
        other.append(resealed)
        prev = resealed.digest
        for r in recs[1:]:
            nxt = ttp.build_record(
                r.seq, r.event, r.payload, r.recorded_at, previous_digest=prev
            )
            other.append(nxt)
            prev = nxt.digest
        self.assertNotEqual(before, other.head_digest())


class TestGenesisAnchor(unittest.TestCase):
    def test_anchor_matches_true_genesis(self):
        trace = _chained_trace(2)
        anchor = ttp.genesis_anchor(trace.records()[0])
        self.assertTrue(anchor.startswith("sha256:"))

    def test_swapped_genesis_recomputes_differently(self):
        trace = _chained_trace(1)
        genuine = ttp.genesis_anchor(trace.records()[0])
        forged_first = ttp.build_record(
            1, "genesis", {"policy_revision": "forged"}, TS
        )
        self.assertNotEqual(genuine, ttp.genesis_anchor(forged_first))

    def test_anchor_requires_seq_one(self):
        trace = _chained_trace(2)
        with self.assertRaises(ValueError):
            ttp.genesis_anchor(trace.records()[1])


class TestDualChannelAudit(unittest.TestCase):
    def _mirrored(self, n):
        dual = ttp.DualChannelAudit()
        prev = ""
        for seq in range(1, n + 1):
            rec = _record(seq, prev=prev)
            dual.mirror(rec)
            prev = rec.digest
        return dual

    def test_agreement_no_findings(self):
        dual = self._mirrored(4)
        self.assertEqual(dual.cross_check(), [])

    def test_divergence_detected(self):
        dual = self._mirrored(3)
        # Operator edits the primary's seq-2 record and recomputes its chain.
        primary_recs = list(dual.primary.records())
        edited = ttp.build_record(
            2, "tool_call", {"outcome": "approved"}, TS,
            previous_digest=primary_recs[0].digest,
        )
        relinked = ttp.build_record(
            3, primary_recs[2].event, primary_recs[2].payload,
            primary_recs[2].recorded_at, previous_digest=edited.digest,
        )
        dual.primary = ttp.AuditTrace()
        dual.primary.append(primary_recs[0])
        dual.primary.append(edited)
        dual.primary.append(relinked)
        findings = dual.cross_check()
        kinds = {(f["kind"], f["seq"]) for f in findings}
        self.assertIn(("divergence", 2), kinds)
        self.assertIn(("divergence", 3), kinds)

    def test_witness_silence_detected(self):
        dual = self._mirrored(3)
        # Mirror blocked: primary advances, witness does not.
        last = dual.primary.records()[-1]
        extra = _record(4, prev=last.digest)
        dual.primary.append(extra)
        findings = dual.cross_check()
        self.assertTrue(
            any(f["kind"] == "primary_only" and f["seq"] == 4 for f in findings)
        )

    def test_primary_deletion_detected(self):
        dual = self._mirrored(3)
        # Operator deletes seq 2-3 from the primary; the witness kept copies.
        short_primary = ttp.AuditTrace()
        short_primary.append(dual.primary.records()[0])
        findings = ttp.DualChannelAudit(
            primary=short_primary, witness=dual.witness
        ).cross_check()
        kinds = {(f["kind"], f["seq"]) for f in findings}
        self.assertIn(("witness_only", 2), kinds)
        self.assertIn(("witness_only", 3), kinds)


if __name__ == "__main__":
    unittest.main()
