"""Tests for org_manager."""

import unittest

from org_manager import (
    AlreadyVerifiedError,
    DuplicateDomainError,
    DuplicateOrgError,
    ORG_MANAGER_VERSION,
    SCHEMA_PIN,
    SSOConfig,
    SSOPreconditionError,
    SeqOrderError,
    SuspendedOrgError,
    UnknownDomainError,
    UnknownOrgError,
    OrgManager,
    org_manager_audit_event,
)

SEED = b"org-manager-test-seed-32bytes!!!!!!"


def _mgr():
    return OrgManager(seed=SEED)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(ORG_MANAGER_VERSION, "org-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.org-manager.v1")


class TestCreate(unittest.TestCase):
    def test_create_happy_path(self):
        m = _mgr()
        org = m.create("Acme Corp", 1)
        self.assertTrue(org.org_id.startswith("org_"))
        self.assertEqual(org.name, "Acme Corp")
        self.assertEqual(org.slug, "acme-corp")
        self.assertEqual(org.created_seq, 1)
        self.assertEqual(org.status, "active")
        self.assertTrue(org.digest.startswith("sha256:"))

    def test_create_explicit_slug(self):
        m = _mgr()
        org = m.create("Acme Corp", 1, slug="acme-2")
        self.assertEqual(org.slug, "acme-2")

    def test_duplicate_slug_raises(self):
        m = _mgr()
        m.create("Acme", 1, slug="acme")
        with self.assertRaises(DuplicateOrgError):
            m.create("Acme Two", 2, slug="acme")

    def test_same_name_different_slug_ok(self):
        m = _mgr()
        a = m.create("Acme", 1, slug="acme")
        b = m.create("Acme", 2, slug="acme-eu")
        self.assertNotEqual(a.org_id, b.org_id)

    def test_malformed_inputs_rejected(self):
        m = _mgr()
        with self.assertRaises(ValueError):
            m.create("", 1)
        with self.assertRaises(ValueError):
            m.create("Acme", 2, slug="BAD SLUG!")

    def test_seq_must_increase(self):
        m = _mgr()
        m.create("Acme", 5)
        with self.assertRaises(SeqOrderError):
            m.create("Beta", 5)
        with self.assertRaises(SeqOrderError):
            m.create("Beta", 3)


class TestDomain(unittest.TestCase):
    def test_domain_claim_happy_path(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        claim = m.domain(org.org_id, "acme.com", 2)
        self.assertEqual(claim.domain, "acme.com")
        self.assertFalse(claim.verified)
        self.assertIsNone(claim.verified_seq)

    def test_domain_normalized_lowercase(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        claim = m.domain(org.org_id, "Acme.COM", 2)
        self.assertEqual(claim.domain, "acme.com")

    def test_malformed_domain_rejected(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        for bad in ("not a domain", "-bad.com", "a" * 300 + ".com", ""):
            with self.assertRaises(ValueError, msg=bad):
                m.domain(org.org_id, bad, 2)

    def test_domain_globally_unique(self):
        m = _mgr()
        a = m.create("Acme", 1, slug="acme")
        b = m.create("Beta", 2, slug="beta")
        m.domain(a.org_id, "shared.com", 3)
        with self.assertRaises(DuplicateDomainError):
            m.domain(b.org_id, "shared.com", 4)

    def test_verify_domain(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        m.domain(org.org_id, "acme.com", 2)
        claim = m.verify_domain(org.org_id, "acme.com", 3)
        self.assertTrue(claim.verified)
        self.assertEqual(claim.verified_seq, 3)
        with self.assertRaises(AlreadyVerifiedError):
            m.verify_domain(org.org_id, "acme.com", 4)

    def test_verify_unknown_domain(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        with self.assertRaises(UnknownDomainError):
            m.verify_domain(org.org_id, "nope.com", 2)


class TestSSO(unittest.TestCase):
    def _verified(self, m, name="acme", domain="acme.com"):
        org = m.create(name.title(), 1, slug=name)
        m.domain(org.org_id, domain, 2)
        m.verify_domain(org.org_id, domain, 3)
        return org

    def test_sso_requires_verified_domain(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        m.domain(org.org_id, "acme.com", 2)  # claimed, not verified
        with self.assertRaises(SSOPreconditionError):
            m.sso(org.org_id, "oidc", 3, entity_id="https://idp/acme")

    def test_sso_happy_path(self):
        m = _mgr()
        org = self._verified(m)
        cfg = m.sso(org.org_id, "saml", 4,
                    entity_id="https://idp/acme",
                    acs_url="https://acme.com/acs")
        self.assertIsInstance(cfg, SSOConfig)
        self.assertEqual(cfg.provider, "saml")
        self.assertEqual(cfg.entity_id, "https://idp/acme")
        self.assertEqual(cfg.bound_seq, 4)
        self.assertTrue(cfg.digest.startswith("sha256:"))
        self.assertEqual(m.sso_of(org.org_id), cfg)

    def test_sso_rebind_replaces(self):
        m = _mgr()
        org = self._verified(m)
        m.sso(org.org_id, "oidc", 4, entity_id="https://idp/v1")
        cfg = m.sso(org.org_id, "saml", 5, entity_id="https://idp/v2")
        self.assertEqual(cfg.provider, "saml")
        self.assertEqual(m.sso_of(org.org_id).bound_seq, 5)

    def test_sso_unknown_provider(self):
        m = _mgr()
        org = self._verified(m)
        with self.assertRaises(ValueError):
            m.sso(org.org_id, "kerberos", 4, entity_id="x")

    def test_secret_never_in_as_dict(self):
        m = _mgr()
        org = self._verified(m)
        m.sso(org.org_id, "oidc", 4, entity_id="https://idp/acme",
              client_secret="super-secret-value")
        snap = m.as_dict()
        blob = str(snap)
        self.assertNotIn("super-secret-value", blob)
        self.assertTrue(
            snap["sso"][0]["secret_verifier"].startswith("masked:"))


class TestLifecycle(unittest.TestCase):
    def test_suspended_org_blocks_mutations(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        m.domain(org.org_id, "acme.com", 2)
        m.verify_domain(org.org_id, "acme.com", 3)
        m.suspend(org.org_id, 4)
        self.assertEqual(m.get(org.org_id).status, "suspended")
        with self.assertRaises(SuspendedOrgError):
            m.domain(org.org_id, "new.com", 5)
        with self.assertRaises(SuspendedOrgError):
            m.sso(org.org_id, "oidc", 5, entity_id="x")
        m.reactivate(org.org_id, 6)
        claim = m.domain(org.org_id, "new.com", 7)
        self.assertEqual(claim.domain, "new.com")

    def test_unknown_org(self):
        m = _mgr()
        with self.assertRaises(UnknownOrgError):
            m.get("org_" + "0" * 16)
        with self.assertRaises(ValueError):
            m.get("bogus")


class TestViews(unittest.TestCase):
    def test_as_dict_and_audit(self):
        m = _mgr()
        org = m.create("Acme", 1, slug="acme")
        m.domain(org.org_id, "acme.com", 2)
        snap = m.as_dict()
        self.assertEqual(snap["version"], ORG_MANAGER_VERSION)
        self.assertEqual(snap["last_seq"], 2)
        self.assertEqual(len(snap["orgs"]), 1)
        self.assertEqual(len(snap["domains"]), 1)
        self.assertEqual(
            [e["kind"] for e in snap["audit"]],
            ["org.created", "domain.claimed"])

    def test_deterministic_with_seed(self):
        a, b = _mgr(), _mgr()
        oa = a.create("Acme", 1, slug="acme")
        ob = b.create("Acme", 1, slug="acme")
        self.assertEqual(oa.org_id, ob.org_id)
        self.assertEqual(oa.digest, ob.digest)

    def test_audit_event_helper(self):
        ev = org_manager_audit_event(9, "org.created", {"org_id": "org_x"})
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["seq"], 9)


if __name__ == "__main__":
    unittest.main()
