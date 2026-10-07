"""Tests for cert_manager: cert-manager-style issuance, renewal, revocation."""

import ast
import unittest
from pathlib import Path

from cert_manager import (
    CERT_MANAGER_VERSION,
    SCHEMA_PIN,
    STATUS_ACTIVE,
    STATUS_REVOKED,
    STATUS_SUPERSEDED,
    AlreadyRevokedError,
    CertManager,
    CertManagerError,
    DuplicateCertificateError,
    IssuerError,
    RevokedCertificateError,
    SupersededCertificateError,
    UnknownCertificateError,
    cert_manager_audit_event,
    main,
)


class VersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CERT_MANAGER_VERSION, "cert-manager.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.cert-manager.v1")


class IssueTests(unittest.TestCase):
    def test_issue_happy_path(self):
        mgr = CertManager()
        cert = mgr.issue(("example.com",), "acme-production", seq=1)
        self.assertEqual(cert.cert_id, "cert-1")
        self.assertEqual(cert.serial, "serial-1")
        self.assertEqual(cert.domains, ("example.com",))
        self.assertEqual(cert.issuer, "acme-production")
        self.assertEqual(cert.not_before_seq, 1)
        self.assertEqual(cert.not_after_seq, 91)
        self.assertEqual(cert.renew_before_seqs, 30)
        self.assertTrue(cert.digest.startswith("sha256:"))
        self.assertEqual(cert.version, CERT_MANAGER_VERSION)

    def test_issue_domain_normalized_lowercase(self):
        mgr = CertManager()
        cert = mgr.issue(("Example.COM",), "ca", seq=1)
        self.assertEqual(cert.domains, ("example.com",))

    def test_issue_wildcard_allowed(self):
        mgr = CertManager()
        cert = mgr.issue(("*.example.com",), "ca", seq=1)
        self.assertEqual(cert.domains, ("*.example.com",))

    def test_issue_custom_duration(self):
        mgr = CertManager()
        cert = mgr.issue(("a.com",), "vault", seq=5, duration_seqs=100, renew_before_seqs=10)
        self.assertEqual(cert.not_after_seq, 105)
        self.assertEqual(cert.renew_before_seqs, 10)

    def test_issue_sequential_ids(self):
        mgr = CertManager()
        a = mgr.issue(("a.com",), "ca", seq=1)
        b = mgr.issue(("b.com",), "ca", seq=1)
        self.assertEqual((a.cert_id, b.cert_id), ("cert-1", "cert-2"))
        self.assertEqual((a.serial, b.serial), ("serial-1", "serial-2"))

    def test_issue_duplicate_live_refused(self):
        mgr = CertManager()
        mgr.issue(("example.com",), "ca", seq=1)
        with self.assertRaises(DuplicateCertificateError):
            mgr.issue(("example.com",), "acme-staging", seq=2)

    def test_issue_duplicate_different_order_refused(self):
        mgr = CertManager()
        mgr.issue(("a.com", "b.com"), "ca", seq=1)
        with self.assertRaises(DuplicateCertificateError):
            mgr.issue(("b.com", "a.com"), "ca", seq=2)

    def test_issue_after_expiry_allowed(self):
        mgr = CertManager()
        mgr.issue(("example.com",), "ca", seq=1, duration_seqs=10, renew_before_seqs=3)
        fresh = mgr.issue(("example.com",), "ca", seq=11)
        self.assertEqual(fresh.cert_id, "cert-2")

    def test_issue_after_revoke_allowed(self):
        mgr = CertManager()
        mgr.issue(("example.com",), "ca", seq=1)
        mgr.revoke("cert-1", seq=2, reason="test")
        fresh = mgr.issue(("example.com",), "ca", seq=3)
        self.assertEqual(fresh.cert_id, "cert-2")

    def test_issue_empty_domains(self):
        mgr = CertManager()
        with self.assertRaises(CertManagerError):
            mgr.issue((), "ca", seq=1)

    def test_issue_bad_wildcard(self):
        mgr = CertManager()
        with self.assertRaises(CertManagerError):
            mgr.issue(("*.com",), "ca", seq=1)  # no dot after *.
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.*.com",), "ca", seq=1)  # not leftmost

    def test_issue_duplicate_domains_in_request(self):
        mgr = CertManager()
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.com", "A.COM"), "ca", seq=1)

    def test_issue_unknown_issuer(self):
        mgr = CertManager()
        with self.assertRaises(IssuerError):
            mgr.issue(("a.com",), "digicert", seq=1)

    def test_issue_bad_duration(self):
        mgr = CertManager()
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.com",), "ca", seq=1, duration_seqs=0)
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.com",), "ca", seq=1, duration_seqs=30, renew_before_seqs=30)
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.com",), "ca", seq=1, duration_seqs=30, renew_before_seqs=40)

    def test_issue_bad_seq(self):
        mgr = CertManager()
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.com",), "ca", seq=True)
        with self.assertRaises(CertManagerError):
            mgr.issue(("a.com",), "ca", seq=-1)

    def test_cert_as_dict_shape(self):
        mgr = CertManager()
        cert = mgr.issue(("a.com",), "ca", seq=1)
        d = cert.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], CERT_MANAGER_VERSION)
        self.assertEqual(d["cert_id"], "cert-1")
        self.assertNotIn("private_key", d)  # no key material ever


class RenewalTests(unittest.TestCase):
    def test_renew_happy_path(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "acme-production", seq=1)
        rec = mgr.renew("cert-1", seq=65)
        self.assertEqual(rec.new_cert_id, "cert-2")
        self.assertTrue(rec.was_due)
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(mgr.status("cert-1"), STATUS_SUPERSEDED)
        self.assertEqual(mgr.superseded_by("cert-1"), "cert-2")
        self.assertEqual(mgr.status("cert-2"), STATUS_ACTIVE)
        new = mgr.certificate("cert-2")
        self.assertEqual(new.domains, ("a.com",))
        self.assertEqual(new.issuer, "acme-production")
        self.assertEqual(new.not_before_seq, 65)

    def test_renew_early_allowed_not_due(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        rec = mgr.renew("cert-1", seq=2)
        self.assertFalse(rec.was_due)
        self.assertEqual(rec.new_cert_id, "cert-2")

    def test_renew_unknown(self):
        mgr = CertManager()
        with self.assertRaises(UnknownCertificateError):
            mgr.renew("cert-9", seq=1)

    def test_renew_revoked_refused(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        mgr.revoke("cert-1", seq=2)
        with self.assertRaises(RevokedCertificateError):
            mgr.renew("cert-1", seq=3)

    def test_renew_superseded_refused(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        mgr.renew("cert-1", seq=65)
        with self.assertRaises(SupersededCertificateError):
            mgr.renew("cert-1", seq=66)

    def test_due_for_renewal(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)  # not_after=91, renew time=61
        self.assertFalse(mgr.due_for_renewal("cert-1", at_seq=60))
        self.assertTrue(mgr.due_for_renewal("cert-1", at_seq=61))
        self.assertTrue(mgr.due_for_renewal("cert-1", at_seq=200))

    def test_due_for_renewal_revoked_false(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        mgr.revoke("cert-1", seq=2)
        self.assertFalse(mgr.due_for_renewal("cert-1", at_seq=200))

    def test_due_view(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)  # renew time 61
        mgr.issue(("b.com",), "ca", seq=1, duration_seqs=1000, renew_before_seqs=100)
        self.assertEqual(mgr.due(at_seq=61), ("cert-1",))

    def test_renewal_record_shape(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        rec = mgr.renew("cert-1", seq=65)
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["cert_id"], "cert-1")
        self.assertEqual(d["new_cert_id"], "cert-2")


class RevokeTests(unittest.TestCase):
    def test_revoke_happy_path(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        rev = mgr.revoke("cert-1", seq=5, reason="key-compromise")
        self.assertEqual(rev.cert_id, "cert-1")
        self.assertEqual(rev.reason, "key-compromise")
        self.assertEqual(rev.revocation_seq, 5)
        self.assertTrue(rev.digest.startswith("sha256:"))
        self.assertEqual(mgr.status("cert-1"), STATUS_REVOKED)
        self.assertEqual(mgr.active(at_seq=6), ())

    def test_revoke_unknown(self):
        mgr = CertManager()
        with self.assertRaises(UnknownCertificateError):
            mgr.revoke("cert-9", seq=1)

    def test_double_revoke_refused(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        mgr.revoke("cert-1", seq=2)
        with self.assertRaises(AlreadyRevokedError):
            mgr.revoke("cert-1", seq=3)

    def test_revocation_view(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1)
        rev = mgr.revoke("cert-1", seq=2, reason="r")
        self.assertIs(mgr.revocation("cert-1"), rev)
        mgr.issue(("b.com",), "ca", seq=3)
        self.assertIsNone(mgr.revocation("cert-2"))


class ViewTests(unittest.TestCase):
    def test_active_excludes_expired(self):
        mgr = CertManager()
        mgr.issue(("a.com",), "ca", seq=1, duration_seqs=10, renew_before_seqs=3)
        mgr.issue(("b.com",), "ca", seq=1)
        self.assertEqual(mgr.active(at_seq=5), ("cert-1", "cert-2"))
        self.assertEqual(mgr.active(at_seq=11), ("cert-2",))

    def test_certificates_sorted(self):
        mgr = CertManager()
        mgr.issue(("b.com",), "ca", seq=1)
        mgr.issue(("a.com",), "ca", seq=1)
        self.assertEqual([c.cert_id for c in mgr.certificates()], ["cert-1", "cert-2"])

    def test_status_unknown(self):
        mgr = CertManager()
        with self.assertRaises(UnknownCertificateError):
            mgr.status("cert-9")

    def test_frozen_records(self):
        import dataclasses

        mgr = CertManager()
        cert = mgr.issue(("a.com",), "ca", seq=1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cert.serial = "x"  # type: ignore[misc]


class AuditTests(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("issued", "renewed", "revoked", "rejected"):
            event = cert_manager_audit_event(kind, 3, {"cert_id": "cert-1"})
            self.assertEqual(event["kind"], kind)
            self.assertEqual(event["event"], "cert-manager")
            self.assertEqual(event["schema"], SCHEMA_PIN)
            self.assertEqual(event["audit_seq"], 3)

    def test_audit_unknown_kind(self):
        with self.assertRaises(CertManagerError):
            cert_manager_audit_event("hacked", 1, {})

    def test_audit_bad_seq(self):
        with self.assertRaises(CertManagerError):
            cert_manager_audit_event("issued", -1, {})


class HouseStyleTests(unittest.TestCase):
    def test_stdlib_only(self):
        path = Path(__file__).resolve().parent.parent / "cert_manager.py"
        tree = ast.parse(path.read_text())
        allowed = {
            "hashlib",
            "threading",
            "dataclasses",
            "typing",
            "json",
            "canonical_json",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
