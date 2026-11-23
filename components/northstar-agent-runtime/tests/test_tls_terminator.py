"""Tests for tls_terminator.py (simulated edge TLS termination)."""

import unittest

from tls_terminator import (
    SCHEMA_PIN,
    TLS_TERMINATOR_VERSION,
    CertificateError,
    ClientHello,
    ExpiredCertificateError,
    NoCipherOverlapError,
    NoVersionOverlapError,
    TicketError,
    TLSTerminator,
    TLSTerminatorError,
    UnknownServerNameError,
    check_client_hello,
    main,
    tls_terminator_audit_event,
)

SECRET = b"0123456789abcdef"  # 16 bytes, test-only


def make_term(**kwargs):
    return TLSTerminator(ticket_secret=SECRET, **kwargs)


def make_cert(term, **kwargs):
    args = {
        "domains": ("example.com", "*.example.com"),
        "serial": "00:11:22",
        "not_before_seq": 0,
        "not_after_seq": 10_000,
        "seq": 1,
    }
    args.update(kwargs)
    return term.add_cert(**args)


def make_hello(**kwargs):
    args = {
        "versions": ("TLS1.2", "TLS1.3"),
        "offered_ciphers": ("TLS_AES_128_GCM_SHA256",),
    }
    args.update(kwargs)
    return check_client_hello(**args)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TLS_TERMINATOR_VERSION, "tls-terminator.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.tls-terminator.v1")

    def test_constructor_secret_validation(self):
        with self.assertRaises(TLSTerminatorError):
            TLSTerminator(ticket_secret=b"short")
        with self.assertRaises(TLSTerminatorError):
            TLSTerminator(ticket_secret="not-bytes")

    def test_constructor_duplicate_alpn(self):
        with self.assertRaises(TLSTerminatorError):
            make_term(alpn_protocols=("h2", "h2"))


class TestCertificates(unittest.TestCase):
    def test_add_cert_happy_path(self):
        term = make_term()
        cert = make_cert(term)
        self.assertTrue(cert.digest.startswith("sha256:"))
        self.assertEqual(len(term.certificates()), 1)
        record = cert.as_dict()
        self.assertEqual(record["schema"], SCHEMA_PIN)
        self.assertEqual(record["version"], TLS_TERMINATOR_VERSION)

    def test_add_cert_digest_deterministic(self):
        t1, t2 = make_term(), make_term()
        c1 = make_cert(t1)
        c2 = make_cert(t2)
        self.assertEqual(c1.digest, c2.digest)

    def test_add_cert_empty_domains(self):
        with self.assertRaises(CertificateError):
            make_cert(make_term(), domains=())

    def test_add_cert_bad_wildcard(self):
        with self.assertRaises(CertificateError):
            make_cert(make_term(), domains=("**.example.com",))
        with self.assertRaises(CertificateError):
            make_cert(make_term(), domains=("www.*.example.com",))

    def test_add_cert_duplicate_domains(self):
        with self.assertRaises(CertificateError):
            make_cert(make_term(), domains=("example.com", "example.com"))

    def test_add_cert_bad_validity(self):
        with self.assertRaises(CertificateError):
            make_cert(make_term(), not_before_seq=100, not_after_seq=100)

    def test_add_cert_bad_seq(self):
        with self.assertRaises(TLSTerminatorError):
            make_cert(make_term(), seq=True)
        with self.assertRaises(TLSTerminatorError):
            make_cert(make_term(), seq=-1)

    def test_sni_exact_match(self):
        term = make_term()
        cert = make_cert(term)
        self.assertIs(term.cert_for("example.com", 5), cert)

    def test_sni_wildcard_match(self):
        term = make_term()
        cert = make_cert(term)
        self.assertIs(term.cert_for("www.example.com", 5), cert)

    def test_sni_wildcard_one_label_deep(self):
        term = make_term()
        make_cert(term)
        with self.assertRaises(UnknownServerNameError):
            term.cert_for("deep.www.example.com", 5)

    def test_sni_exact_beats_wildcard(self):
        term = make_term()
        generic = make_cert(term)
        specific = term.add_cert(
            domains=("www.example.com",),
            serial="99",
            not_before_seq=0,
            not_after_seq=10_000,
            seq=2,
        )
        self.assertIs(term.cert_for("www.example.com", 5), specific)
        self.assertIs(term.cert_for("mail.example.com", 5), generic)

    def test_sni_unknown(self):
        term = make_term()
        make_cert(term)
        with self.assertRaises(UnknownServerNameError):
            term.cert_for("other.com", 5)

    def test_cert_expiry_boundary(self):
        term = make_term()
        make_cert(term)
        with self.assertRaises(ExpiredCertificateError):
            term.cert_for("example.com", 10_000)  # not_after is exclusive
        # just inside the window works
        term.cert_for("example.com", 9_999)

    def test_cert_not_yet_valid(self):
        term = make_term()
        make_cert(term, not_before_seq=100)
        with self.assertRaises(ExpiredCertificateError):
            term.cert_for("example.com", 50)

    def test_cert_for_bad_seq(self):
        term = make_term()
        make_cert(term)
        with self.assertRaises(TLSTerminatorError):
            term.cert_for("example.com", -1)


class TestNegotiation(unittest.TestCase):
    def setUp(self):
        self.term = make_term()
        make_cert(self.term)

    def test_handshake_happy_path(self):
        hello = make_hello(alpn_protocols=("http/1.1", "h2"))
        result = self.term.handshake("www.example.com", hello, seq=10)
        self.assertEqual(result.tls_version, "TLS1.3")  # highest overlap wins
        self.assertEqual(result.sni, "www.example.com")
        self.assertFalse(result.resumed)
        self.assertTrue(result.session_ticket.startswith("tkt-"))
        self.assertTrue(result.handshake_digest.startswith("sha256:"))
        record = result.as_dict()
        self.assertEqual(record["schema"], SCHEMA_PIN)

    def test_server_cipher_preference_wins(self):
        # Client offers AES_128 first; server prefers CHACHA in its own order.
        hello = make_hello(
            offered_ciphers=("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256")
        )
        result = self.term.handshake("example.com", hello, seq=10)
        self.assertEqual(result.cipher, "TLS_CHACHA20_POLY1305_SHA256")

    def test_tls12_fallback(self):
        hello = make_hello(
            versions=("TLS1.2",),
            offered_ciphers=("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",),
        )
        result = self.term.handshake("example.com", hello, seq=10)
        self.assertEqual(result.tls_version, "TLS1.2")
        self.assertEqual(result.cipher, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")

    def test_alpn_server_preference(self):
        hello = make_hello(alpn_protocols=("http/1.1", "h2"))
        result = self.term.handshake("example.com", hello, seq=10)
        self.assertEqual(result.alpn_protocol, "h2")

    def test_alpn_no_overlap_returns_none(self):
        self.assertIsNone(self.term.alpn(("spdy/3",)))
        hello = make_hello(alpn_protocols=("spdy/3",))
        result = self.term.handshake("example.com", hello, seq=10)
        self.assertIsNone(result.alpn_protocol)

    def test_alpn_validation(self):
        with self.assertRaises(TLSTerminatorError):
            self.term.alpn("h2")

    def test_no_version_overlap(self):
        hello = make_hello(
            versions=("TLS1.1",), offered_ciphers=("TLS_AES_128_GCM_SHA256",)
        )
        with self.assertRaises(NoVersionOverlapError):
            self.term.handshake("example.com", hello, seq=10)

    def test_no_cipher_overlap(self):
        hello = make_hello(versions=("TLS1.3",), offered_ciphers=("DES-CBC3-SHA",))
        with self.assertRaises(NoCipherOverlapError):
            self.term.handshake("example.com", hello, seq=10)

    def test_unknown_sni(self):
        hello = make_hello()
        with self.assertRaises(UnknownServerNameError):
            self.term.handshake("nope.example.net", hello, seq=10)

    def test_bad_client_hello_type(self):
        with self.assertRaises(TLSTerminatorError):
            self.term.handshake("example.com", "not-a-hello", seq=10)

    def test_bad_seq(self):
        hello = make_hello()
        with self.assertRaises(TLSTerminatorError):
            self.term.handshake("example.com", hello, seq=-1)


class TestClientHello(unittest.TestCase):
    def test_check_client_hello_happy(self):
        hello = make_hello()
        self.assertIsInstance(hello, ClientHello)
        self.assertEqual(hello.session_ticket, None)

    def test_check_client_hello_empty_versions(self):
        with self.assertRaises(TLSTerminatorError):
            check_client_hello(versions=(), offered_ciphers=("A",))

    def test_check_client_hello_empty_ciphers(self):
        with self.assertRaises(TLSTerminatorError):
            check_client_hello(versions=("TLS1.3",), offered_ciphers=[])

    def test_check_client_hello_bad_types(self):
        with self.assertRaises(TLSTerminatorError):
            check_client_hello(versions=("TLS1.3", 3), offered_ciphers=("A",))


class TestTickets(unittest.TestCase):
    def setUp(self):
        self.term = make_term()
        make_cert(self.term)
        self.result = self.term.handshake("example.com", make_hello(), seq=10)

    def test_resume_roundtrip(self):
        resumed = self.term.resume(self.result.session_ticket, seq=20)
        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.tls_version, self.result.tls_version)
        self.assertEqual(resumed.cipher, self.result.cipher)
        self.assertEqual(resumed.cert_digest, self.result.cert_digest)
        self.assertEqual(resumed.session_ticket, self.result.session_ticket)

    def test_resume_unknown_ticket(self):
        with self.assertRaises(TicketError):
            self.term.resume("tkt-forged", seq=20)

    def test_resume_expired_ticket(self):
        with self.assertRaises(TicketError):
            self.term.resume(self.result.session_ticket, seq=10 + 10_001)

    def test_resume_ticket_ids_unique(self):
        r2 = self.term.handshake("example.com", make_hello(), seq=11)
        self.assertNotEqual(self.result.session_ticket, r2.session_ticket)

    def test_resume_bad_seq(self):
        with self.assertRaises(TLSTerminatorError):
            self.term.resume(self.result.session_ticket, seq=True)


class TestAudit(unittest.TestCase):
    def test_audit_event_shapes(self):
        for kind in (
            "cert-added",
            "handshake",
            "handshake-refused",
            "ticket-issued",
            "resumed",
            "resume-refused",
            "rejected",
        ):
            event = tls_terminator_audit_event(kind, 5, {"sni": "example.com"})
            self.assertEqual(event["schema"], SCHEMA_PIN)
            self.assertEqual(event["version"], TLS_TERMINATOR_VERSION)
            self.assertEqual(event["audit_seq"], 5)
            self.assertEqual(event["kind"], kind)

    def test_audit_unknown_kind(self):
        with self.assertRaises(TLSTerminatorError):
            tls_terminator_audit_event("explode", 1, {})

    def test_audit_bad_detail(self):
        with self.assertRaises(TLSTerminatorError):
            tls_terminator_audit_event("handshake", 1, "not-a-dict")

    def test_audit_bad_seq(self):
        with self.assertRaises(TLSTerminatorError):
            tls_terminator_audit_event("handshake", -1, {})


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
