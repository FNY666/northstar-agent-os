"""Tests for dns_resolver.py — record ledger with TTL expiry and CNAME chains."""

import ast
import unittest
from pathlib import Path

import dns_resolver
from dns_resolver import (
    CNAMELoopError,
    ClockRegressionError,
    DNSRecord,
    DNSResolver,
    DNS_RESOLVER_VERSION,
    DuplicateRecordError,
    MAX_CNAME_HOPS,
    RecordTypeError,
    SCHEMA_PIN,
    SUPPORTED_RTYPES,
    UnknownNameError,
    UnknownRtypeError,
    dns_resolver_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(DNS_RESOLVER_VERSION, "dns-resolver.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.dns-resolver.v1")


class TestAddRecord(unittest.TestCase):
    def setUp(self):
        self.r = DNSResolver()

    def test_add_happy_path(self):
        cached = self.r.add_record("example.com", "A", "93.184.216.34",
                                   ttl_s=60, now_s=0, seq=0)
        self.assertTrue(cached.digest.startswith("sha256:"))
        self.assertEqual(cached.expires_at_s, 60)
        self.assertEqual(cached.record.name, "example.com")
        self.assertEqual(cached.record.rtype, "A")
        self.assertEqual(self.r.record_count(), 1)

    def test_name_normalized(self):
        cached = self.r.add_record("EXAMPLE.com.", "a", "1.2.3.4",
                                   ttl_s=30, now_s=0, seq=0)
        self.assertEqual(cached.record.name, "example.com")
        self.assertEqual(cached.record.rtype, "A")

    def test_duplicate_refused(self):
        self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=0)
        with self.assertRaises(DuplicateRecordError):
            self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=60, now_s=1, seq=1)

    def test_same_value_different_ttl_allowed(self):
        self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=0)
        self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=120, now_s=0, seq=1)
        self.assertEqual(self.r.record_count(), 2)

    def test_add_validation(self):
        with self.assertRaises(ValueError):
            self.r.add_record("", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=0)
        with self.assertRaises(UnknownRtypeError):
            self.r.add_record("example.com", "NOPE", "x", ttl_s=60, now_s=0, seq=0)
        with self.assertRaises(TypeError):
            self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=True, now_s=0, seq=0)
        with self.assertRaises(ValueError):
            self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=0, now_s=0, seq=0)
        with self.assertRaises(ValueError):
            self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=60, now_s=-1, seq=0)
        with self.assertRaises(ValueError):
            self.r.add_record("not a name!!", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=0)

    def test_digest_deterministic(self):
        c1 = DNSResolver()
        c2 = DNSResolver()
        a = c1.add_record("example.com", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=0)
        b = c2.add_record("example.com", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=0)
        self.assertEqual(a.digest, b.digest)


class TestResolve(unittest.TestCase):
    def setUp(self):
        self.r = DNSResolver()
        self.r.add_record("example.com", "A", "93.184.216.34", ttl_s=60, now_s=0, seq=0)

    def test_resolve_happy_path(self):
        res = self.r.resolve("example.com", "A", now_s=10, seq=1)
        self.assertEqual(len(res.records), 1)
        self.assertEqual(res.records[0].value, "93.184.216.34")
        self.assertEqual(res.cname_chain, ())
        self.assertEqual(res.min_ttl_remaining_s, 50)

    def test_multiple_answers(self):
        self.r.add_record("example.com", "A", "93.184.216.35", ttl_s=60, now_s=0, seq=1)
        res = self.r.resolve("example.com", "A", now_s=0, seq=2)
        self.assertEqual(len(res.records), 2)
        self.assertEqual(res.min_ttl_remaining_s, 60)

    def test_unknown_name(self):
        with self.assertRaises(UnknownNameError):
            self.r.resolve("missing.example.com", "A", now_s=0, seq=1)

    def test_wrong_rtype(self):
        # known name, no AAAA records, no CNAME either
        self.r.add_record("plain.example.com", "A", "1.2.3.4", ttl_s=60, now_s=0, seq=1)
        with self.assertRaises(RecordTypeError):
            self.r.resolve("plain.example.com", "AAAA", now_s=0, seq=2)

    def test_expired_not_returned(self):
        res = self.r.resolve("example.com", "A", now_s=59, seq=1)
        self.assertEqual(res.min_ttl_remaining_s, 1)
        with self.assertRaises(UnknownNameError):
            self.r.resolve("example.com", "A", now_s=60, seq=2)

    def test_cname_follow(self):
        self.r.add_record("alias.example.com", "CNAME", "example.com",
                          ttl_s=60, now_s=0, seq=1)
        res = self.r.resolve("alias.example.com", "A", now_s=5, seq=2)
        self.assertEqual(res.cname_chain, ("example.com",))
        self.assertEqual(res.records[0].value, "93.184.216.34")

    def test_cname_loop_refused(self):
        self.r.add_record("a.example.com", "CNAME", "b.example.com", ttl_s=60, now_s=0, seq=1)
        self.r.add_record("b.example.com", "CNAME", "a.example.com", ttl_s=60, now_s=0, seq=2)
        with self.assertRaises(CNAMELoopError):
            self.r.resolve("a.example.com", "A", now_s=0, seq=3)

    def test_cname_hop_limit(self):
        prev = "h0.example.com"
        for i in range(1, MAX_CNAME_HOPS + 3):
            nxt = f"h{i}.example.com"
            self.r.add_record(prev, "CNAME", nxt, ttl_s=600, now_s=0, seq=i)
            prev = nxt
        with self.assertRaises(CNAMELoopError):
            self.r.resolve("h0.example.com", "A", now_s=0, seq=99)

    def test_cname_to_missing_target(self):
        self.r.add_record("dangling.example.com", "CNAME", "ghost.example.com",
                          ttl_s=60, now_s=0, seq=1)
        with self.assertRaises(RecordTypeError):
            self.r.resolve("dangling.example.com", "A", now_s=0, seq=2)

    def test_clock_regression_refused(self):
        self.r.resolve("example.com", "A", now_s=10, seq=1)
        with self.assertRaises(ClockRegressionError):
            self.r.resolve("example.com", "A", now_s=5, seq=2)

    def test_result_frozen_and_dict(self):
        res = self.r.resolve("example.com", "A", now_s=0, seq=1)
        with self.assertRaises(Exception):
            res.query_seq = 999  # frozen dataclass
        d = res.as_dict()
        self.assertEqual(d["records"][0]["value"], "93.184.216.34")
        self.assertEqual(d["schema"], SCHEMA_PIN)


class TestTTL(unittest.TestCase):
    def setUp(self):
        self.r = DNSResolver()
        self.r.add_record("example.com", "A", "1.2.3.4", ttl_s=100, now_s=0, seq=0)
        self.r.add_record("example.com", "A", "1.2.3.5", ttl_s=50, now_s=0, seq=1)

    def test_ttl_report(self):
        rep = self.r.ttl("example.com", "A", now_s=20)
        self.assertEqual(rep.min_remaining_s, 30)
        self.assertEqual(rep.live_count, 2)
        self.assertEqual(rep.now_s, 20)

    def test_ttl_no_live_records(self):
        with self.assertRaises(RecordTypeError):
            self.r.ttl("example.com", "A", now_s=100)


class TestExpiryAndRemoval(unittest.TestCase):
    def setUp(self):
        self.r = DNSResolver()
        self.r.add_record("a.example.com", "A", "1.1.1.1", ttl_s=10, now_s=0, seq=0)
        self.r.add_record("b.example.com", "A", "2.2.2.2", ttl_s=100, now_s=0, seq=1)

    def test_expire_sweeps(self):
        rep = self.r.expire(now_s=11, seq=2)
        self.assertEqual(rep.dropped, 1)
        self.assertEqual(rep.remaining, 1)
        self.assertEqual(self.r.names(), ("b.example.com",))

    def test_remove(self):
        n = self.r.remove("a.example.com", "A", seq=2)
        self.assertEqual(n, 1)
        with self.assertRaises(UnknownNameError):
            self.r.resolve("a.example.com", "A", now_s=0, seq=3)
        self.assertEqual(self.r.remove("nope.example.com", "A", seq=4), 0)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = dns_resolver_audit_event("resolved", seq=3, detail="example.com A")
        self.assertEqual(ev["kind"], "dns-resolver.resolved")
        self.assertEqual(ev["module_version"], DNS_RESOLVER_VERSION)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["format"], "audit.ndjson/1")

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            dns_resolver_audit_event("bogus", seq=0)

    def test_audit_bad_seq(self):
        with self.assertRaises(TypeError):
            dns_resolver_audit_event("resolved", seq=True)


class TestStdlibOnly(unittest.TestCase):
    def test_no_third_party_imports(self):
        path = Path(dns_resolver.__file__)
        tree = ast.parse(path.read_text())
        allowed = {
            "hashlib", "hmac", "re", "threading", "dataclasses", "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        dns_resolver.main()


if __name__ == "__main__":
    unittest.main()
