"""Tests for custom_domains: 15 cases."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custom_domains import (
    CustomDomains,
    custom_domains_audit_event,
    validate_domain,
    BadDomainError,
    DuplicateMappingError,
    UnknownMappingError,
    AlreadyVerifiedError,
    NotVerifiedError,
    SeqOrderError,
    CustomDomainError,
    _SSL_VALIDITY_SEQ,
)


def make_hub(verifier=lambda d: True):
    events = []
    hub = CustomDomains(verifier, events.append)
    return hub, events


class TestCustomDomains(unittest.TestCase):
    def test_validate_domain_good(self):
        ok, _ = validate_domain("app.example.com")
        self.assertTrue(ok)

    def test_validate_domain_bad(self):
        for bad in ["", "a", "-x.com", "x..com", "UP PER.com", "x" * 300 + ".com"]:
            ok, _ = validate_domain(bad)
            self.assertFalse(ok, bad)

    def test_map_happy_path(self):
        hub, _ = make_hub()
        m = hub.map("app.example.com", "tenant-1", 1)
        self.assertEqual(m.state, "pending")
        self.assertTrue(m.verify_digest())

    def test_map_bad_domain(self):
        hub, _ = make_hub()
        with self.assertRaises(BadDomainError):
            hub.map("not a domain!", "t", 1)

    def test_map_duplicate(self):
        hub, _ = make_hub()
        hub.map("app.example.com", "t1", 1)
        with self.assertRaises(DuplicateMappingError):
            hub.map("APP.example.com", "t2", 2)  # case-insensitive dup

    def test_verify_ok(self):
        hub, events = make_hub(lambda d: d == "app.example.com")
        m = hub.map("app.example.com", "t", 1)
        v = hub.verify(m.mapping_id, 2)
        self.assertTrue(v.ok)
        self.assertTrue(v.verify_digest())
        self.assertEqual(hub.get(m.mapping_id).state, "verified")
        kinds = [e["kind"] for e in events]
        self.assertIn("verified", kinds)

    def test_verify_denied_fail_closed(self):
        hub, _ = make_hub(lambda d: False)
        m = hub.map("app.example.com", "t", 1)
        v = hub.verify(m.mapping_id, 2)
        self.assertFalse(v.ok)
        self.assertEqual(hub.get(m.mapping_id).state, "pending")

    def test_verify_raising_verifier_fail_closed(self):
        hub, _ = make_hub(lambda d: (_ for _ in ()).throw(RuntimeError("dns down")))
        m = hub.map("app.example.com", "t", 1)
        v = hub.verify(m.mapping_id, 2)
        self.assertFalse(v.ok)

    def test_verify_unknown(self):
        hub, _ = make_hub()
        with self.assertRaises(UnknownMappingError):
            hub.verify("map-999", 1)

    def test_verify_twice_refused(self):
        hub, _ = make_hub()
        m = hub.map("app.example.com", "t", 1)
        hub.verify(m.mapping_id, 2)
        with self.assertRaises(AlreadyVerifiedError):
            hub.verify(m.mapping_id, 3)

    def test_ssl_requires_verified(self):
        hub, _ = make_hub()
        m = hub.map("app.example.com", "t", 1)
        with self.assertRaises(NotVerifiedError):
            hub.ssl(m.mapping_id, 2)

    def test_ssl_happy_path(self):
        hub, _ = make_hub()
        m = hub.map("app.example.com", "t", 1)
        hub.verify(m.mapping_id, 2)
        c = hub.ssl(m.mapping_id, 3)
        self.assertTrue(c.verify_digest())
        self.assertTrue(c.valid_at(3))
        self.assertFalse(c.valid_at(3 + _SSL_VALIDITY_SEQ))

    def test_seq_must_increase(self):
        hub, _ = make_hub()
        hub.map("a.example.com", "t", 1)
        with self.assertRaises(SeqOrderError):
            hub.map("b.example.com", "t", 1)

    def test_mapping_for_view(self):
        hub, _ = make_hub()
        m = hub.map("app.example.com", "t", 1)
        self.assertEqual(hub.mapping_for("app.example.com").mapping_id, m.mapping_id)
        self.assertIsNone(hub.mapping_for("other.example.com"))

    def test_audit_event_shape(self):
        ev = custom_domains_audit_event("mapped", 5, {"domain": "x.io"})
        self.assertEqual(ev["type"], "audit.ndjson/1")
        self.assertEqual(ev["seq"], 5)
        with self.assertRaises(CustomDomainError):
            CustomDomains(lambda d: True, None)


if __name__ == "__main__":
    unittest.main()
