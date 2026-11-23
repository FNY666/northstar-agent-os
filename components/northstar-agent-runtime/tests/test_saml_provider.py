"""Targeted tests for saml_provider (SAML SSO bookkeeping)."""

import unittest

from saml_provider import (
    AssertionRecord,
    EntityMetadata,
    RevocationRecord,
    SAMLProvider,
    SAMLError,
    SAML_PROVIDER_VERSION,
    SCHEMA_PIN,
    AssertionError,
    UnknownAssertionError,
    ValidationError,
    ValidationReport,
    saml_provider_audit_event,
)


def make_provider() -> SAMLProvider:
    return SAMLProvider("https://idp.example.org/saml", "https://idp.example.org/sso")


def make_assertion(provider=None, **kw):
    provider = provider or make_provider()
    params = dict(
        name_id="alice@example.com",
        audience="https://sp.example.org",
        not_before_seq=10,
        not_on_or_after_seq=20,
        seq=1,
        attributes={"email": "alice@example.com", "level": 3},
    )
    params.update(kw)
    return provider, provider.issue(**params)


class TestMetadata(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(SAML_PROVIDER_VERSION, "saml-provider.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.saml-provider.v1")

    def test_metadata_shape(self):
        md = make_provider().metadata()
        self.assertIsInstance(md, EntityMetadata)
        self.assertEqual(md.entity_id, "https://idp.example.org/saml")
        self.assertEqual(md.sso_service_url, "https://idp.example.org/sso")
        self.assertTrue(md.digest.startswith("sha256:"))

    def test_metadata_digest_deterministic(self):
        self.assertEqual(make_provider().metadata().digest, make_provider().metadata().digest)

    def test_metadata_as_dict(self):
        md = make_provider().metadata().as_dict()
        self.assertEqual(md["version"], SAML_PROVIDER_VERSION)
        self.assertEqual(md["schema"], SCHEMA_PIN)

    def test_bad_constructor_inputs(self):
        with self.assertRaises(AssertionError):
            SAMLProvider("", "https://idp.example.org/sso")
        with self.assertRaises(AssertionError):
            SAMLProvider("https://idp.example.org/saml", "ftp://idp.example.org/sso")


class TestAssert(unittest.TestCase):
    def test_assert_happy_path(self):
        provider, record = make_assertion()
        self.assertIsInstance(record, AssertionRecord)
        self.assertEqual(record.name_id, "alice@example.com")
        self.assertEqual(record.audience, "https://sp.example.org")
        self.assertTrue(record.digest.startswith("sha256:"))
        self.assertEqual(record.attributes, (("email", "alice@example.com"), ("level", 3)))

    def test_assertion_ids_mint_monotonically(self):
        provider = make_provider()
        r1 = provider.issue("a", "b", 0, 5, 1)
        r2 = provider.issue("a", "b", 0, 5, 2)
        self.assertNotEqual(r1.assertion_id, r2.assertion_id)
        self.assertEqual(provider.assertion_ids(), tuple(sorted([r1.assertion_id, r2.assertion_id])))

    def test_empty_validity_window_refused(self):
        provider = make_provider()
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 10, 10, 1)
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 12, 10, 1)

    def test_bad_attribute_values_refused(self):
        provider = make_provider()
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 0, 5, 1, attributes={"ok": float("nan")})
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 0, 5, 1, attributes={"ok": True})
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 0, 5, 1, attributes={"ok": 2**54})

    def test_bool_and_negative_seqs_refused(self):
        provider = make_provider()
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 0, 5, True)
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 0, 5, -1)
        with self.assertRaises(AssertionError):
            provider.issue("a", "b", 0, 5, 1)
            provider.issue("a", "b", 0, 5, 0)  # seq rewind refused


class TestValidate(unittest.TestCase):
    def test_valid_assertion(self):
        provider, record = make_assertion()
        report = provider.validate(record, "https://sp.example.org", at_seq=15, seq=2)
        self.assertIsInstance(report, ValidationReport)
        self.assertTrue(report.valid)
        self.assertEqual(report.reason, "ok")

    def test_not_yet_valid_and_expired(self):
        provider, record = make_assertion()
        early = provider.validate(record, "https://sp.example.org", at_seq=9, seq=2)
        self.assertFalse(early.valid)
        self.assertEqual(early.reason, "not-yet-valid")
        late = provider.validate(record, "https://sp.example.org", at_seq=20, seq=3)
        self.assertFalse(late.valid)
        self.assertEqual(late.reason, "expired")

    def test_audience_mismatch(self):
        provider, record = make_assertion()
        report = provider.validate(record, "https://evil.example.org", at_seq=15, seq=2)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, "audience-mismatch")

    def test_unknown_assertion_id(self):
        provider, record = make_assertion()
        forged = AssertionRecord(
            assertion_id="assert-999",
            name_id=record.name_id,
            audience=record.audience,
            issuer=record.issuer,
            not_before_seq=record.not_before_seq,
            not_on_or_after_seq=record.not_on_or_after_seq,
            attributes=record.attributes,
            digest=record.digest,
        )
        report = provider.validate(forged, "https://sp.example.org", at_seq=15, seq=2)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, "unknown-assertion")

    def test_tampered_digest(self):
        provider, record = make_assertion()
        tampered = AssertionRecord(
            assertion_id=record.assertion_id,
            name_id=record.name_id,
            audience=record.audience,
            issuer=record.issuer,
            not_before_seq=record.not_before_seq,
            not_on_or_after_seq=record.not_on_or_after_seq,
            attributes=record.attributes,
            digest="sha256:" + "0" * 64,
        )
        report = provider.validate(tampered, "https://sp.example.org", at_seq=15, seq=2)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, "digest-mismatch")

    def test_non_assertion_raises(self):
        provider = make_provider()
        with self.assertRaises(ValidationError):
            provider.validate("not-an-assertion", "https://sp.example.org", at_seq=15, seq=1)


class TestRevoke(unittest.TestCase):
    def test_revoke_then_validate_fails(self):
        provider, record = make_assertion()
        revocation = provider.revoke(record.assertion_id, seq=2)
        self.assertIsInstance(revocation, RevocationRecord)
        self.assertTrue(provider.is_revoked(record.assertion_id))
        report = provider.validate(record, "https://sp.example.org", at_seq=15, seq=3)
        self.assertFalse(report.valid)
        self.assertEqual(report.reason, "revoked")

    def test_revoke_idempotent(self):
        provider, record = make_assertion()
        r1 = provider.revoke(record.assertion_id, seq=2)
        r2 = provider.revoke(record.assertion_id, seq=3)
        self.assertEqual(r1.digest, r2.digest)

    def test_revoke_unknown_raises(self):
        provider = make_provider()
        with self.assertRaises(UnknownAssertionError):
            provider.revoke("assert-999", seq=1)


class TestAudit(unittest.TestCase):
    def test_audit_event_shapes(self):
        event = saml_provider_audit_event("assertion-issued", 1, {"assertion_id": "assert-1"})
        self.assertEqual(event["kind"], "assertion-issued")
        self.assertEqual(event["module"], SAML_PROVIDER_VERSION)
        self.assertEqual(event["schema"], "audit.ndjson/1")

    def test_unknown_audit_kind_refused(self):
        with self.assertRaises(SAMLError):
            saml_provider_audit_event("bogus-kind", 1)

    def test_main_self_check(self):
        import saml_provider

        saml_provider.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
