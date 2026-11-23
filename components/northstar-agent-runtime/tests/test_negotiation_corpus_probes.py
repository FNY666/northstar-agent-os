"""Tests for negotiation_corpus_probes."""

import unittest

import negotiation_corpus_probes as ncp


def _digest(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _make_attestation(**overrides):
    base = {
        "attester_id": "peer-1",
        "subject_id": "helper-a",
        "claims": ("clean-billing-record", "no-abuse-reports"),
        "valid_from": "2026-01-01",
        "valid_to": "2026-12-31",
        "signature_digest": _digest("sig"),
    }
    base.update(overrides)
    return ncp.ReputationAttestation(**base).pinned()


class CorpusShapeTests(unittest.TestCase):
    def test_ten_attack_probes(self):
        self.assertEqual(len(ncp.attack_probe_names()), 10)

    def test_three_benign_controls(self):
        self.assertEqual(len(ncp.benign_probe_names()), 3)

    def test_probe_keys(self):
        for name in (*ncp.attack_probe_names(), *ncp.benign_probe_names()):
            probe = ncp.probe_by_name(name)
            for key in ("probe", "family", "attack", "gate_interaction",
                        "expected", "reason"):
                self.assertIn(key, probe, name)

    def test_unique_names(self):
        names = (*ncp.attack_probe_names(), *ncp.benign_probe_names())
        self.assertEqual(len(names), len(set(names)))

    def test_attack_probes_expected_deny(self):
        for name in ncp.attack_probe_names():
            self.assertEqual(ncp.probe_by_name(name)["expected"], "deny")

    def test_benign_probes_expected_allow(self):
        for name in ncp.benign_probe_names():
            self.assertEqual(ncp.probe_by_name(name)["expected"], "allow")

    def test_family_membership(self):
        for family in ncp.NEGOTIATION_FAMILIES:
            self.assertIn(family, ncp.NEGOTIATION_CORPUS_SOURCE["families"])

    def test_attack_gate_interactions_name_deny_side(self):
        for name in ncp.attack_probe_names():
            interaction = ncp.probe_by_name(name)["gate_interaction"].lower()
            self.assertTrue(
                any(k in interaction for k in ncp.DENY_SIDE_KEYWORDS),
                name,
            )

    def test_family_counts(self):
        self.assertEqual(
            len(ncp.probes_in_family(ncp.FAMILY_ATTESTATION_FORGERY)), 4
        )
        self.assertEqual(
            len(ncp.probes_in_family(ncp.FAMILY_REGISTRY_POISONING)), 3
        )
        self.assertEqual(
            len(ncp.probes_in_family(ncp.FAMILY_COUNTER_OFFER_LAUNDERING)), 3
        )

    def test_probe_by_name_unknown_raises(self):
        with self.assertRaises(KeyError):
            ncp.probe_by_name("no-such-probe")

    def test_main_runs(self):
        ncp.main()


class AttestationTests(unittest.TestCase):
    def test_round_trip(self):
        att = _make_attestation()
        self.assertTrue(att.verify())

    def test_tampered_claims_fail(self):
        att = _make_attestation()
        forged = ncp.ReputationAttestation(
            attester_id=att.attester_id,
            subject_id=att.subject_id,
            claims=("forged-claim",),
            valid_from=att.valid_from,
            valid_to=att.valid_to,
            signature_digest=att.signature_digest,
            digest=att.digest,
        )
        self.assertFalse(forged.verify())

    def test_clean_attestation_no_findings(self):
        att = _make_attestation()
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="helper-a", as_of="2026-06-01"
        )
        self.assertEqual(findings, ())

    def test_unsigned_attestation_finding(self):
        att = _make_attestation(signature_digest="not-a-digest")
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="helper-a", as_of="2026-06-01"
        )
        self.assertTrue(
            any(f.code == ncp.DENY_UNSIGNED_ATTESTATION for f in findings)
        )

    def test_self_attestation_finding(self):
        att = _make_attestation(attester_id="broker-7", subject_id="broker-7")
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="broker-7", as_of="2026-06-01"
        )
        self.assertTrue(
            any(f.code == ncp.DENY_SELF_ATTESTATION for f in findings)
        )

    def test_subject_mismatch_finding(self):
        att = _make_attestation(subject_id="helper-a")
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="helper-b", as_of="2026-06-01"
        )
        self.assertTrue(
            any(f.code == ncp.DENY_SUBJECT_MISMATCH for f in findings)
        )

    def test_stale_attestation_finding(self):
        att = _make_attestation(valid_to="2026-03-31")
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="helper-a", as_of="2026-10-01"
        )
        self.assertTrue(
            any(f.code == ncp.DENY_STALE_ATTESTATION for f in findings)
        )

    def test_attestation_at_window_edge_is_fresh(self):
        att = _make_attestation()
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="helper-a", as_of="2026-12-31"
        )
        self.assertEqual(findings, ())

    def test_findings_are_digest_pinned(self):
        att = _make_attestation(signature_digest="not-a-digest")
        findings = ncp.detect_attestation_forgery(
            att, expected_subject="helper-a", as_of="2026-06-01"
        )
        self.assertTrue(all(f.verify() for f in findings))


def _make_entry(**overrides):
    base = {
        "entry_id": "entry-1",
        "agent_id": "db-admin",
        "service_claim": "production-database-read",
        "registry_head_digest": _digest("head"),
    }
    base.update(overrides)
    return ncp.WantRegistryEntry(**base).pinned()


class RegistryTests(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(_make_entry().verify())

    def test_clean_registry_no_findings(self):
        findings = ncp.verify_registry_integrity(
            (_make_entry(),), pinned_head_digest=_digest("head")
        )
        self.assertEqual(findings, ())

    def test_poisoned_entry_finding(self):
        entry = _make_entry()
        poisoned = ncp.WantRegistryEntry(
            entry_id=entry.entry_id,
            agent_id=entry.agent_id,
            service_claim="production-database-write",
            registry_head_digest=entry.registry_head_digest,
            digest=entry.digest,
        )
        findings = ncp.verify_registry_integrity(
            (poisoned,), pinned_head_digest=_digest("head")
        )
        self.assertTrue(
            any(f.code == ncp.DENY_REGISTRY_POISONED for f in findings)
        )

    def test_swapped_registry_head_finding(self):
        entry = _make_entry(registry_head_digest=_digest("other-head"))
        findings = ncp.verify_registry_integrity(
            (entry,), pinned_head_digest=_digest("head")
        )
        self.assertTrue(
            any(f.code == ncp.DENY_REGISTRY_POISONED for f in findings)
        )

    def test_unpinned_entry_finding(self):
        entry = _make_entry()
        unpinned = ncp.WantRegistryEntry(
            entry_id=entry.entry_id,
            agent_id=entry.agent_id,
            service_claim=entry.service_claim,
            registry_head_digest=entry.registry_head_digest,
            digest="",
        )
        findings = ncp.verify_registry_integrity(
            (unpinned,), pinned_head_digest=_digest("head")
        )
        self.assertTrue(
            any(f.code == ncp.DENY_REGISTRY_UNPINNED for f in findings)
        )

    def test_findings_are_digest_pinned(self):
        findings = ncp.verify_registry_integrity(
            (), pinned_head_digest=_digest("head")
        )
        self.assertEqual(findings, ())
        entry = _make_entry()
        unpinned = ncp.WantRegistryEntry(
            entry_id=entry.entry_id,
            agent_id=entry.agent_id,
            service_claim=entry.service_claim,
            registry_head_digest=entry.registry_head_digest,
            digest="",
        )
        findings = ncp.verify_registry_integrity(
            (unpinned,), pinned_head_digest=_digest("head")
        )
        self.assertTrue(all(f.verify() for f in findings))


def _make_binding(**overrides):
    terms = _digest("terms")
    base = {
        "negotiation_id": "neg-1",
        "offer_digest": _digest("offer"),
        "counter_terms_digest": terms,
        "executed_terms_digest": terms,
    }
    base.update(overrides)
    return ncp.CounterOfferBinding(**base).pinned()


class CounterOfferTests(unittest.TestCase):
    def test_round_trip(self):
        self.assertTrue(_make_binding().verify())

    def test_honored_counter_offer_no_findings(self):
        findings = ncp.verify_counter_offer(_make_binding())
        self.assertEqual(findings, ())

    def test_switched_terms_finding(self):
        binding = _make_binding(executed_terms_digest=_digest("other-terms"))
        findings = ncp.verify_counter_offer(binding)
        self.assertTrue(
            any(f.code == ncp.DENY_COUNTER_OFFER_LAUNDERED for f in findings)
        )

    def test_malformed_binding_finding(self):
        binding = _make_binding()
        malformed = ncp.CounterOfferBinding(
            negotiation_id=binding.negotiation_id,
            offer_digest=binding.offer_digest,
            counter_terms_digest=binding.counter_terms_digest,
            executed_terms_digest=binding.executed_terms_digest,
            digest="",
        )
        findings = ncp.verify_counter_offer(malformed)
        self.assertTrue(
            any(f.code == ncp.DENY_MALFORMED_NEGOTIATION for f in findings)
        )

    def test_agreement_is_not_authorization(self):
        finding = ncp.agreement_is_not_authorization(_digest("record"))
        self.assertEqual(finding.code, ncp.DENY_CONSENSUS_AS_AUTHORIZATION)
        self.assertEqual(
            finding.family, ncp.FAMILY_COUNTER_OFFER_LAUNDERING
        )
        self.assertTrue(finding.verify())

    def test_agreement_refusal_rejects_unpinned(self):
        with self.assertRaises(ncp.NegotiationCorpusError):
            ncp.agreement_is_not_authorization("not-a-digest")


class ExpectedOutcomesTests(unittest.TestCase):
    def test_outcomes_cover_all_probes(self):
        outcomes = ncp.expected_outcomes()
        expected = set(ncp.attack_probe_names()) | set(
            ncp.benign_probe_names()
        )
        self.assertEqual(set(outcomes), expected)

    def test_version_pinned(self):
        self.assertEqual(ncp.NEGOTIATION_CORPUS_VERSION, "negotiation-corpus.v1")


if __name__ == "__main__":
    unittest.main()
