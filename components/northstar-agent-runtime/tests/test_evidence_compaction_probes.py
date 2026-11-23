"""Tests for evidence_compaction_probes.py."""

import unittest

import evidence_compaction_probes as ecp

_DENY_KEYWORDS = ("deny", "denies", "flag", "flags", "quarantine", "reject")


class CorpusShapeTests(unittest.TestCase):
    def test_attack_and_benign_counts(self):
        self.assertEqual(len(ecp.EVIDENCE_COMPACTION_PROBES), 10)
        self.assertEqual(len(ecp.EVIDENCE_COMPACTION_BENIGN), 3)

    def test_required_keys(self):
        for probe in (*ecp.EVIDENCE_COMPACTION_PROBES,
                      *ecp.EVIDENCE_COMPACTION_BENIGN):
            for key in ("probe", "family", "attack", "gate_interaction",
                        "expected", "reason"):
                self.assertIn(key, probe, probe["probe"])

    def test_unique_names(self):
        names = [p["probe"] for p in (*ecp.EVIDENCE_COMPACTION_PROBES,
                                      *ecp.EVIDENCE_COMPACTION_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_attack_expected_deny_benign_allow(self):
        for probe in ecp.EVIDENCE_COMPACTION_PROBES:
            self.assertEqual(probe["expected"], "deny")
        for probe in ecp.EVIDENCE_COMPACTION_BENIGN:
            self.assertEqual(probe["expected"], "allow")

    def test_attack_gate_interactions_carry_deny_keywords(self):
        for probe in ecp.EVIDENCE_COMPACTION_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in _DENY_KEYWORDS),
                f"no deny-side keyword in {probe['probe']}",
            )

    def test_families(self):
        families = {p["family"] for p in ecp.EVIDENCE_COMPACTION_PROBES}
        self.assertEqual(
            families,
            {"compaction-loss", "payload-evidence", "compaction-integrity"},
        )


class AccessorTests(unittest.TestCase):
    def test_probe_by_name(self):
        probe = ecp.probe_by_name("loss-digest-stripped")
        self.assertEqual(probe["family"], "compaction-loss")

    def test_probe_by_name_missing(self):
        with self.assertRaises(KeyError):
            ecp.probe_by_name("no-such-probe")

    def test_expected_outcomes(self):
        outcomes = ecp.expected_outcomes()
        self.assertEqual(outcomes["loss-payload-kept-evidence-dropped"], "deny")
        self.assertEqual(outcomes["benign-compact-with-digests"], "allow")

    def test_probes_by_family(self):
        self.assertEqual(len(ecp.probes_by_family("payload-evidence")), 3)
        self.assertEqual(ecp.probes_by_family("nope"), ())


def _manifest() -> str:
    return ecp._digest({"source": "trace-T"})


def _evidence(seq: int = 0, manifest: str | None = None) -> ecp.EvidenceItem:
    return ecp.build_item(
        "evidence", f"deny record {seq}",
        source_digest=manifest if manifest is not None else _manifest(),
        seq=seq,
    )


def _payload(seq: int = 1) -> ecp.EvidenceItem:
    return ecp.build_item("payload", f"bulk output {seq}", seq=seq)


class ItemTests(unittest.TestCase):
    def test_build_and_verify_round_trip(self):
        item = _evidence()
        self.assertTrue(ecp.verify_item(item))

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            ecp.build_item("claim", "x")

    def test_empty_content_rejected(self):
        with self.assertRaises(ValueError):
            ecp.build_item("evidence", "")

    def test_bad_source_digest_rejected(self):
        with self.assertRaises(ValueError):
            ecp.build_item("evidence", "x", source_digest="nope")

    def test_tampered_content_fails_verify(self):
        item = _evidence()
        tampered = ecp.EvidenceItem(
            kind=item.kind, content="rewritten", digest=item.digest,
            source_digest=item.source_digest, seq=item.seq,
        )
        self.assertFalse(ecp.verify_item(tampered))


class CompactTests(unittest.TestCase):
    def test_clean_compact(self):
        bundle = ecp.compact([_evidence(0)], [_payload(1)], _manifest())
        ok, findings = ecp.verify_bundle_integrity(bundle, (_evidence(0).digest,))
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_bad_manifest_rejected(self):
        with self.assertRaises(ValueError):
            ecp.compact([_evidence(0)], [], "not-a-digest")

    def test_evidence_kind_in_payload_list_rejected(self):
        with self.assertRaises(ValueError):
            ecp.compact([], [_evidence(0)], _manifest())

    def test_payload_kind_in_evidence_list_rejected(self):
        with self.assertRaises(ValueError):
            ecp.compact([_payload(0)], [], _manifest())

    def test_evidence_without_source_chain_rejected(self):
        orphan = ecp.build_item("evidence", "orphan deny", seq=0)
        with self.assertRaises(ValueError):
            ecp.compact([orphan], [], _manifest())

    def test_out_of_order_rejected(self):
        with self.assertRaises(ValueError):
            ecp.compact([_evidence(1), _evidence(0)], [], _manifest())


class IntegrityTests(unittest.TestCase):
    def test_evidence_dropped_detected(self):
        bundle = ecp.compact([_evidence(0)], [_payload(1)], _manifest())
        ok, findings = ecp.verify_bundle_integrity(
            bundle, (_evidence(0).digest, _evidence(9).digest)
        )
        self.assertFalse(ok)
        kinds = {f["kind"] for f in findings}
        self.assertIn("evidence_dropped", kinds)

    def test_bad_digest_detected(self):
        item = _evidence(0)
        bad = ecp.EvidenceItem(
            kind=item.kind, content="rewritten", digest=item.digest,
            source_digest=item.source_digest, seq=item.seq,
        )
        bundle = ecp.CompactionBundle(
            items=(bad,), source_manifest=_manifest(),
            bundle_digest="",
        )
        seal = ecp._bundle_digest(bundle.items, bundle.source_manifest, ())
        bundle = ecp.CompactionBundle(
            items=(bad,), source_manifest=_manifest(), bundle_digest=seal
        )
        ok, findings = ecp.verify_bundle_integrity(bundle)
        self.assertFalse(ok)
        self.assertIn("bad_digest", {f["kind"] for f in findings})

    def test_unlabeled_item_detected(self):
        item = _evidence(0)
        weird = ecp.EvidenceItem(
            kind="mystery", content=item.content, digest=item.digest,
            source_digest=item.source_digest, seq=item.seq,
        )
        raw = ecp.CompactionBundle(
            items=(weird,), source_manifest=_manifest(), bundle_digest=""
        )
        seal = ecp._bundle_digest(raw.items, raw.source_manifest, ())
        raw = ecp.CompactionBundle(
            items=(weird,), source_manifest=_manifest(), bundle_digest=seal
        )
        ok, findings = ecp.verify_bundle_integrity(raw)
        self.assertFalse(ok)
        self.assertIn("unlabeled_item", {f["kind"] for f in findings})

    def test_evidence_after_payload_flagged(self):
        bundle = ecp.compact([_evidence(0)], [_payload(1)], _manifest())
        shuffled = ecp.CompactionBundle(
            items=(bundle.items[1], bundle.items[0]),
            source_manifest=bundle.source_manifest,
            dropped_payload=bundle.dropped_payload,
            bundle_digest="",
        )
        seal = ecp._bundle_digest(
            shuffled.items, shuffled.source_manifest, shuffled.dropped_payload
        )
        shuffled = ecp.CompactionBundle(
            items=shuffled.items, source_manifest=shuffled.source_manifest,
            dropped_payload=shuffled.dropped_payload, bundle_digest=seal,
        )
        ok, findings = ecp.verify_bundle_integrity(shuffled)
        self.assertFalse(ok)
        kinds = {f["kind"] for f in findings}
        self.assertIn("evidence_in_payload", kinds)

    def test_bundle_seal_mismatch_detected(self):
        bundle = ecp.compact([_evidence(0)], [], _manifest())
        tampered = ecp.CompactionBundle(
            items=bundle.items, source_manifest=bundle.source_manifest,
            bundle_digest="sha256:" + "0" * 64,
        )
        ok, findings = ecp.verify_bundle_integrity(tampered)
        self.assertFalse(ok)
        self.assertIn("bundle_digest_mismatch", {f["kind"] for f in findings})

    def test_missing_manifest_flagged(self):
        item = _evidence(0)
        raw = ecp.CompactionBundle(items=(item,), source_manifest="")
        ok, findings = ecp.verify_bundle_integrity(raw)
        self.assertFalse(ok)
        self.assertIn("no_source_manifest", {f["kind"] for f in findings})

    def test_never_raises_on_garbage(self):
        raw = ecp.CompactionBundle(items=(), source_manifest="")
        ok, findings = ecp.verify_bundle_integrity(raw)
        self.assertFalse(ok)
        self.assertTrue(findings)


class HeadDigestTests(unittest.TestCase):
    def test_stable_and_sensitive(self):
        b1 = ecp.compact([_evidence(0)], [], _manifest())
        b2 = ecp.compact([_evidence(0)], [], _manifest())
        b3 = ecp.compact([_evidence(0), _evidence(1)], [], _manifest())
        self.assertEqual(ecp.bundle_head_digest(b1), ecp.bundle_head_digest(b2))
        self.assertNotEqual(ecp.bundle_head_digest(b1), ecp.bundle_head_digest(b3))


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        ecp.main()


if __name__ == "__main__":
    unittest.main()
