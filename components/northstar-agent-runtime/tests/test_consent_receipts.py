"""Tests for revocable consent receipts (one-hundred-fifth batch)."""

import unittest

import ed25519

from consent_receipts import (
    AUTHORITATIVE_DECODE,
    CONSENTED_USE,
    CONSENT_USE_DENIED_EVENT,
    DATA_SCOPES,
    DECODE_CONFIDENCE_MIN,
    NON_AUTHORITATIVE_DECODE,
    STIMULATION_DENIED_EVENT,
    STIMULATION_FRESHNESS_WINDOW_S,
    UNCONSENTED_USE,
    ConsentReceiptError,
    check_consent_at_use,
    compute_receipt_digest,
    compute_revocation_digest,
    consent_audit_event,
    decode_attribution,
    gate_stimulation,
    grant_consent,
    revoke_consent,
    stimulation_audit_event,
)


SEED_A = bytes(range(32))
SEED_B = bytes(31 - i for i in range(32))
T0 = 1_700_000_000


def _grant(**over):
    kw = dict(
        subject_id="subject-001",
        subject_secret=SEED_A,
        data_scope="neural_raw",
        purpose="clinical-research",
        granted_at=T0,
        expires_at=T0 + 10_000_000,
    )
    kw.update(over)
    return grant_consent(**kw)


class GrantTests(unittest.TestCase):
    def test_grant_seals_digest_and_signature(self):
        g = _grant()
        self.assertEqual(compute_receipt_digest(g), g.receipt_digest)
        payload_ok = ed25519.verify(
            bytes.fromhex(g.subject_pubkey_hex),
            __import__("canonical_json").jcs_canonical_json(
                {
                    "schema": "northstar.consent-receipt.v1",
                    "kind": "grant",
                    "subject_id": g.subject_id,
                    "data_scope": g.data_scope,
                    "purpose": g.purpose,
                    "granted_at": g.granted_at,
                    "expires_at": g.expires_at,
                    "subject_pubkey_hex": g.subject_pubkey_hex,
                    "prev_digest": g.prev_digest,
                }
            ),
            bytes.fromhex(g.signature_hex),
        )
        self.assertTrue(payload_ok)

    def test_grant_pubkey_derives_from_secret(self):
        g = _grant()
        self.assertEqual(g.subject_pubkey_hex, ed25519.public_key(SEED_A).hex())

    def test_bad_scope_rejected(self):
        with self.assertRaises(ConsentReceiptError):
            _grant(data_scope="mind-reading")

    def test_expiry_before_grant_rejected(self):
        with self.assertRaises(ConsentReceiptError):
            _grant(granted_at=T0, expires_at=T0)

    def test_empty_purpose_rejected(self):
        with self.assertRaises(ConsentReceiptError):
            _grant(purpose="")

    def test_revocation_chains_and_seals(self):
        g = _grant()
        r = revoke_consent(
            receipt=g, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest=g.receipt_digest,
        )
        self.assertEqual(compute_revocation_digest(r), r.record_digest)
        self.assertEqual(r.prev_digest, g.receipt_digest)

    def test_revocation_by_wrong_key_rejected(self):
        g = _grant()
        with self.assertRaises(ConsentReceiptError):
            revoke_consent(
                receipt=g, subject_secret=SEED_B, revoked_at=T0 + 100,
                prev_digest=g.receipt_digest,
            )


class UseTimeTests(unittest.TestCase):
    def _log(self, grant, revocation=None):
        log = [grant]
        if revocation is not None:
            log.append(revocation)
        return log

    def test_allow_fresh_use(self):
        g = _grant()
        v = check_consent_at_use(
            receipt=g, log=self._log(g), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 500,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CONSENTED_USE)

    def test_allow_repeated_use_within_window(self):
        # Use-time checks, not collection-time: every use re-verifies.
        g = _grant()
        log = self._log(g)
        for t in (T0 + 1, T0 + 1_000, T0 + 9_999_999):
            v = check_consent_at_use(
                receipt=g, log=log, data_scope="neural_raw",
                purpose="clinical-research", use_time=t,
            )
            self.assertTrue(v.allowed, f"use at {t} should allow")

    def test_deny_revoked_before_use(self):
        g = _grant()
        r = revoke_consent(
            receipt=g, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest=g.receipt_digest,
        )
        v = check_consent_at_use(
            receipt=g, log=self._log(g, r), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 200,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, UNCONSENTED_USE)
        self.assertIn("revoked", v.reason)

    def test_allow_use_before_revocation(self):
        # Revocation is not retroactive: uses before revoked_at were lawful.
        g = _grant()
        r = revoke_consent(
            receipt=g, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest=g.receipt_digest,
        )
        v = check_consent_at_use(
            receipt=g, log=self._log(g, r), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 50,
        )
        self.assertTrue(v.allowed)

    def test_deny_expired(self):
        g = _grant()
        v = check_consent_at_use(
            receipt=g, log=self._log(g), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 10_000_001,
        )
        self.assertFalse(v.allowed)
        self.assertIn("expired", v.reason)

    def test_deny_before_grant(self):
        g = _grant()
        v = check_consent_at_use(
            receipt=g, log=self._log(g), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 - 1,
        )
        self.assertFalse(v.allowed)

    def test_deny_scope_mismatch(self):
        g = _grant()
        v = check_consent_at_use(
            receipt=g, log=self._log(g), data_scope="neural_decoded",
            purpose="clinical-research", use_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn("scope mismatch", v.reason)

    def test_deny_purpose_mismatch(self):
        g = _grant()
        v = check_consent_at_use(
            receipt=g, log=self._log(g), data_scope="neural_raw",
            purpose="product-personalization", use_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn("purpose mismatch", v.reason)

    def test_deny_tampered_receipt(self):
        g = _grant()
        tampered = g.__class__(**{
            **g.__dict__, "purpose": "product-personalization",
        })
        v = check_consent_at_use(
            receipt=tampered, log=self._log(g), data_scope="neural_raw",
            purpose="product-personalization", use_time=T0 + 10,
        )
        self.assertFalse(v.allowed)

    def test_deny_unknown_receipt(self):
        g = _grant()
        other = _grant(subject_id="subject-002", subject_secret=SEED_B)
        v = check_consent_at_use(
            receipt=other, log=self._log(g), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 10,
        )
        self.assertFalse(v.allowed)
        self.assertIn("not present", v.reason)

    def test_deny_broken_chain(self):
        g = _grant()
        r = revoke_consent(
            receipt=g, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest="ab" * 32,  # wrong link: chain broken
        )
        v = check_consent_at_use(
            receipt=g, log=[g, r], data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 50,
        )
        self.assertFalse(v.allowed)
        self.assertIn("integrity", v.reason)

    def test_new_grant_after_revocation_allows(self):
        # No "un-revoke": a fresh grant is a new receipt.
        g1 = _grant()
        r = revoke_consent(
            receipt=g1, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest=g1.receipt_digest,
        )
        g2 = _grant(granted_at=T0 + 200, prev_digest=r.record_digest)
        v = check_consent_at_use(
            receipt=g2, log=[g1, r, g2], data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 300,
        )
        self.assertTrue(v.allowed)

    def test_audit_event_shape(self):
        g = _grant()
        r = revoke_consent(
            receipt=g, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest=g.receipt_digest,
        )
        v = check_consent_at_use(
            receipt=g, log=self._log(g, r), data_scope="neural_raw",
            purpose="clinical-research", use_time=T0 + 200,
        )
        ev = consent_audit_event(v, action="train_decoder")
        self.assertEqual(ev["event"], CONSENT_USE_DENIED_EVENT)
        self.assertFalse(ev["allowed"])
        self.assertEqual(ev["classification"], UNCONSENTED_USE)


class DecodeAttributionTests(unittest.TestCase):
    def _sig(self):
        return "cd" * 32

    def test_authoritative_decode(self):
        d = decode_attribution(
            raw_signal_digest=self._sig(), decoder_id="paradromics-d1",
            decoder_version="3.2.1", confidence=0.97,
        )
        self.assertEqual(d.classification, AUTHORITATIVE_DECODE)

    def test_low_confidence_non_authoritative(self):
        d = decode_attribution(
            raw_signal_digest=self._sig(), decoder_id="paradromics-d1",
            decoder_version="3.2.1", confidence=DECODE_CONFIDENCE_MIN - 0.01,
        )
        self.assertEqual(d.classification, NON_AUTHORITATIVE_DECODE)

    def test_ambiguous_non_authoritative(self):
        d = decode_attribution(
            raw_signal_digest=self._sig(), decoder_id="paradromics-d1",
            decoder_version="3.2.1", confidence=0.99, ambiguous=True,
        )
        self.assertEqual(d.classification, NON_AUTHORITATIVE_DECODE)

    def test_confidence_out_of_range_rejected(self):
        with self.assertRaises(ConsentReceiptError):
            decode_attribution(
                raw_signal_digest=self._sig(), decoder_id="d",
                decoder_version="v", confidence=1.5,
            )

    def test_attribution_binds_decoder(self):
        d = decode_attribution(
            raw_signal_digest=self._sig(), decoder_id="neuralink-n1",
            decoder_version="2026.9", confidence=0.5,
        )
        self.assertEqual(d.decoder_id, "neuralink-n1")
        self.assertEqual(d.raw_signal_digest, self._sig())


class StimulationGateTests(unittest.TestCase):
    def _stim_setup(self, **over):
        kw = dict(
            subject_id="subject-001",
            subject_secret=SEED_A,
            data_scope="neural_stimulation",
            purpose="tremor-suppression",
            granted_at=T0,
            expires_at=T0 + 10_000_000,
        )
        kw.update(over)
        g = grant_consent(**kw)
        decode = decode_attribution(
            raw_signal_digest="ef" * 32, decoder_id="decoder-x",
            decoder_version="1.0", confidence=0.96,
        )
        return g, decode

    def test_allow_full_gate(self):
        g, decode = self._stim_setup()
        v = gate_stimulation(
            consent_receipt=g, log=[g], use_time=T0 + 3600,
            purpose="tremor-suppression", decode=decode,
            human_countersign_ok=True,
        )
        self.assertTrue(v.allowed)

    def test_deny_non_authoritative_decode(self):
        g, _ = self._stim_setup()
        shaky = decode_attribution(
            raw_signal_digest="ef" * 32, decoder_id="decoder-x",
            decoder_version="1.0", confidence=0.5,
        )
        v = gate_stimulation(
            consent_receipt=g, log=[g], use_time=T0 + 3600,
            purpose="tremor-suppression", decode=shaky,
            human_countersign_ok=True,
        )
        self.assertFalse(v.allowed)
        self.assertIn("non-authoritative", v.reason)

    def test_deny_missing_countersign(self):
        g, decode = self._stim_setup()
        v = gate_stimulation(
            consent_receipt=g, log=[g], use_time=T0 + 3600,
            purpose="tremor-suppression", decode=decode,
            human_countersign_ok=False,
        )
        self.assertFalse(v.allowed)
        self.assertIn("countersign", v.reason)

    def test_deny_stale_consent(self):
        g, decode = self._stim_setup()
        v = gate_stimulation(
            consent_receipt=g, log=[g],
            use_time=T0 + STIMULATION_FRESHNESS_WINDOW_S + 1,
            purpose="tremor-suppression", decode=decode,
            human_countersign_ok=True,
        )
        self.assertFalse(v.allowed)
        self.assertIn("stale", v.reason)

    def test_deny_revoked_consent(self):
        g, decode = self._stim_setup()
        r = revoke_consent(
            receipt=g, subject_secret=SEED_A, revoked_at=T0 + 100,
            prev_digest=g.receipt_digest,
        )
        v = gate_stimulation(
            consent_receipt=g, log=[g, r], use_time=T0 + 3600,
            purpose="tremor-suppression", decode=decode,
            human_countersign_ok=True,
        )
        self.assertFalse(v.allowed)

    def test_deny_wrong_scope_grant(self):
        g = _grant(data_scope="neural_raw")  # not stimulation scope
        decode = decode_attribution(
            raw_signal_digest="ef" * 32, decoder_id="decoder-x",
            decoder_version="1.0", confidence=0.96,
        )
        v = gate_stimulation(
            consent_receipt=g, log=[g], use_time=T0 + 3600,
            purpose="clinical-research", decode=decode,
            human_countersign_ok=True,
        )
        self.assertFalse(v.allowed)

    def test_stimulation_denial_audit_event(self):
        g, decode = self._stim_setup()
        v = gate_stimulation(
            consent_receipt=g, log=[g], use_time=T0 + 3600,
            purpose="tremor-suppression", decode=decode,
            human_countersign_ok=False,
        )
        ev = stimulation_audit_event(v, action="stimulate-motor-cortex")
        self.assertEqual(ev["event"], STIMULATION_DENIED_EVENT)
        self.assertFalse(ev["allowed"])


if __name__ == "__main__":
    unittest.main()
