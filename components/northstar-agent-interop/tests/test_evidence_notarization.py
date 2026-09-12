"""Tests for portable evidence notarization envelopes."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from evidence_bundle import build_lineage_bundle, make_proof
from evidence_chain import EvidenceChain
from evidence_disclosure import Disclosure
from evidence_notarization import (
    EnvelopeVerdict,
    EvidenceEnvelope,
    HMACSignatureScheme,
    NotarizationError,
    build_envelope,
    verify_envelope,
)
from evidence_proof import ProofAttestation, make_proof_attestation
from key_lifecycle import KeyHistory
from route_lineage import LineageGraph, RouteLineageEvent

SECRET = b"portable-envelope-signing-key-32bytes"
OTHER_SECRET = b"another-portable-envelope-key-32b"


def evidence():
    event = RouteLineageEvent.from_dict({
        "schema_version": "northstar.route-lineage.v2",
        "sequence": 1,
        "prev_event_digest": "0" * 64,
        "event_id": "e1",
        "route_id": "r1",
        "parent_event_id": None,
        "receipt_id": "receipt-1",
        "status": "succeeded",
        "target_agent_id": "codex",
        "provider": "openai",
        "capabilities": ["workspace:read"],
        "deadline_at": 90,
        "payload_digest": "sha256:" + "a" * 64,
        "decision_fingerprint": "sha256:" + "b" * 64,
        "retryable": False,
    })
    lineage = LineageGraph()
    lineage.append(event)
    bundle = build_lineage_bundle([event])
    proof = make_proof(bundle, 0)
    chain = EvidenceChain()
    checkpoint = chain.append(bundle)
    route = {
        "route_id": "r1",
        "selected_agent_id": "codex",
        "selected_provider": "openai",
        "deadline_at": 90,
        "decision_fingerprint": "sha256:" + "b" * 64,
        "payload_digest": "sha256:" + "a" * 64,
    }
    handoff = {
        "route_id": "r1",
        "target_agent_id": "codex",
        "provider": "openai",
        "deadline_at": 90,
        "capabilities": ["workspace:read"],
        "decision_fingerprint": "sha256:" + "b" * 64,
        "payload_digest": "sha256:" + "a" * 64,
    }
    return route, lineage, bundle, chain, event, proof, handoff, checkpoint


def make_history(root):
    path = Path(root) / "key-history.jsonl"
    initial = KeyHistory(path)
    initial.introduce("k1", SECRET)
    anchor = initial.records[0].record_digest
    return KeyHistory(path, anchor=anchor), anchor


def make_one(root):
    route, lineage, bundle, chain, event, proof, handoff, checkpoint = evidence()
    history, anchor = make_history(root)
    scheme = HMACSignatureScheme({"k1": SECRET})
    envelope = build_envelope(
        route, lineage, bundle, chain, event, proof, handoff,
        index=0, key_id="k1", history=history,
        signer={"kind": "host", "id": "host-1"}, scheme=scheme,
    )
    return envelope, anchor, scheme, event, checkpoint


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="notarize-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_builds_a_portable_envelope(self):
        envelope, anchor, scheme, event, checkpoint = make_one(self.root)
        self.assertEqual(envelope.schema_version, "northstar.evidence-notarization.v1")
        self.assertEqual(envelope.key_id, "k1")
        self.assertEqual(envelope.subject["event_id"], "e1")
        self.assertEqual(envelope.disclosure["schema_version"], "northstar.inclusion-disclosure.v1")
        self.assertEqual(envelope.attestation["verdict"], "verified")
        self.assertEqual(envelope.checkpoint_head["current_root"], envelope.disclosure["root_digest"])
        self.assertTrue(envelope.signature)

    def test_wire_form_is_deterministic_and_round_trips(self):
        envelope, _, _, _, _ = make_one(self.root)
        wire = envelope.to_dict()
        restored = EvidenceEnvelope.from_dict(json.loads(json.dumps(wire, sort_keys=True)))
        self.assertEqual(restored, envelope)
        self.assertEqual(
            json.dumps(wire, sort_keys=True, separators=(",", ":")),
            json.dumps(restored.to_dict(), sort_keys=True, separators=(",", ":")),
        )

    def test_envelope_has_no_key_material(self):
        envelope, _, _, _, _ = make_one(self.root)
        encoded = json.dumps(envelope.to_dict(), sort_keys=True)
        self.assertNotIn(SECRET.decode(), encoded)
        self.assertNotIn(SECRET.hex(), encoded)
        self.assertNotIn(SECRET, Path(self.root, "key-history.jsonl").read_bytes())

    def test_producer_refuses_a_missing_checkpoint(self):
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        history, _ = make_history(self.root)
        with self.assertRaises(NotarizationError):
            build_envelope(
                route, lineage, bundle, EvidenceChain(), event, proof, handoff,
                index=0, key_id="k1", history=history,
                signer={"kind": "host", "id": "host-1"},
                scheme=HMACSignatureScheme({"k1": SECRET}),
            )

    def test_producer_refuses_unverified_evidence(self):
        route, lineage, bundle, chain, event, proof, handoff = evidence()[:7]
        history, _ = make_history(self.root)
        bad = RouteLineageEvent.from_dict({**event.to_dict(), "status": "failed"})
        with self.assertRaises(NotarizationError):
            build_envelope(
                route, lineage, bundle, chain, bad, proof, handoff,
                index=0, key_id="k1", history=history,
                signer={"kind": "host", "id": "host-1"},
                scheme=HMACSignatureScheme({"k1": SECRET}),
            )

    def test_producer_refuses_malformed_signer(self):
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        history, _ = make_history(self.root)
        for signer in ({}, {"kind": "unknown", "id": "x"}, {"kind": "host"}, {"kind": "host", "id": ""}):
            with self.assertRaises(NotarizationError):
                build_envelope(
                    route, lineage, bundle, chain, event, proof, handoff,
                    index=0, key_id="k1", history=history, signer=signer,
                    scheme=HMACSignatureScheme({"k1": SECRET}),
                )

    def test_producer_refuses_revoked_key(self):
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        history, _ = make_history(self.root)
        history.revoke("k1")
        with self.assertRaises(NotarizationError):
            build_envelope(
                route, lineage, bundle, chain, event, proof, handoff,
                index=0, key_id="k1", history=history,
                signer={"kind": "host", "id": "host-1"},
                scheme=HMACSignatureScheme({"k1": SECRET}),
            )

    def test_producer_refuses_unknown_key(self):
        route, lineage, bundle, chain, event, proof, handoff, _ = evidence()
        history, _ = make_history(self.root)
        with self.assertRaises(NotarizationError):
            build_envelope(
                route, lineage, bundle, chain, event, proof, handoff,
                index=0, key_id="ghost", history=history,
                signer={"kind": "host", "id": "host-1"},
                scheme=HMACSignatureScheme({"ghost": SECRET}),
            )


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="notarize-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.envelope, self.anchor, self.scheme, self.event, self.checkpoint = make_one(self.root)

    def test_pinned_envelope_verifies(self):
        verdict = verify_envelope(
            self.envelope, anchor=self.anchor, scheme=self.scheme,
            expected_root=self.envelope.disclosure["root_digest"],
        )
        self.assertEqual(verdict.state, "verified")
        self.assertEqual(verdict.reasons, ())
        self.assertIn("same-key", verdict.unverified)

    def test_unpinned_root_is_not_verified(self):
        verdict = verify_envelope(self.envelope, anchor=self.anchor, scheme=self.scheme)
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("root_unpinned", verdict.unverified)

    def test_unpinned_key_anchor_is_not_verified(self):
        verdict = verify_envelope(
            self.envelope, anchor=None, scheme=self.scheme,
            expected_root=self.envelope.disclosure["root_digest"],
        )
        self.assertEqual(verdict.state, "verified-unpinned")
        self.assertIn("anchor_unpinned", verdict.unverified)

    def test_wrong_secret_is_rejected(self):
        with self.assertRaises(NotarizationError):
            verify_envelope(
                self.envelope, anchor=self.anchor,
                scheme=HMACSignatureScheme({"k1": OTHER_SECRET}),
                expected_root=self.envelope.disclosure["root_digest"],
            )

    def test_wrong_expected_root_is_rejected(self):
        with self.assertRaises(NotarizationError):
            verify_envelope(
                self.envelope, anchor=self.anchor, scheme=self.scheme,
                expected_root="sha256:" + "f" * 64,
            )

    def test_subject_tampering_is_rejected(self):
        forged = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "subject": {**self.envelope.subject, "event_id": "forged"},
        })
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_disclosure_tampering_is_rejected(self):
        forged = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "disclosure": {**self.envelope.disclosure, "root_digest": "sha256:" + "f" * 64},
        })
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_attestation_tampering_is_rejected(self):
        forged = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "attestation": {**self.envelope.attestation, "route_id": "forged"},
        })
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_key_history_tampering_is_rejected(self):
        history = list(self.envelope.key_history)
        history[0] = {**history[0], "key_id": "forged"}
        forged = EvidenceEnvelope.from_dict({**self.envelope.to_dict(), "key_history": history})
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_checkpoint_tampering_is_rejected(self):
        forged = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "checkpoint_head": {**self.envelope.checkpoint_head, "current_root": "sha256:" + "f" * 64},
        })
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_signer_tampering_is_rejected(self):
        forged = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "signer": {"kind": "agent", "id": "other"},
        })
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_signature_tampering_is_rejected(self):
        forged = EvidenceEnvelope.from_dict({
            **self.envelope.to_dict(),
            "signature": "bad-signature-value",
        })
        with self.assertRaises(NotarizationError):
            verify_envelope(forged, anchor=self.anchor, scheme=self.scheme,
                            expected_root=self.envelope.disclosure["root_digest"])

    def test_wire_schema_is_strict(self):
        with self.assertRaises(NotarizationError):
            EvidenceEnvelope.from_dict({**self.envelope.to_dict(), "extra": True})
        with self.assertRaises(NotarizationError):
            EvidenceEnvelope.from_dict({})


class HMACSchemeTests(unittest.TestCase):
    def test_hmac_scheme_declares_same_key_mode(self):
        scheme = HMACSignatureScheme({"k1": SECRET})
        self.assertEqual(scheme.mode, "same-key")
        self.assertIsInstance(scheme.sign(b"payload", key_id="k1"), str)
        self.assertTrue(scheme.verify(
            b"payload", scheme.sign(b"payload", key_id="k1"), key_id="k1"
        ))

    def test_hmac_scheme_does_not_resolve_unknown_keys(self):
        scheme = HMACSignatureScheme({"k1": SECRET})
        with self.assertRaises(NotarizationError):
            scheme.sign(b"payload", key_id="ghost")


if __name__ == "__main__":
    unittest.main()
