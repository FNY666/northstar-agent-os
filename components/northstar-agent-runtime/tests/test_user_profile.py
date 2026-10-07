"""Tests for user_profile: profile records with per-field privacy levels."""

import ast
import unittest
from dataclasses import FrozenInstanceError

from user_profile import (
    SCHEMA_PIN,
    USER_PROFILE_VERSION,
    VISIBILITY_LEVELS,
    VIEWER_RELATIONS,
    DuplicateProfileError,
    SeqOrderError,
    UnknownProfileError,
    UserProfile,
    UserProfileManager,
    ValidationError,
    user_profile_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(USER_PROFILE_VERSION, "user-profile.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.user-profile.v1")
        self.assertEqual(VISIBILITY_LEVELS, ("public", "contacts", "private"))
        self.assertEqual(VIEWER_RELATIONS, ("self", "contacts", "public"))

    def test_stdlib_only(self):
        tree = ast.parse(open("user_profile.py").read())
        allowed = {
            "hashlib", "re", "threading", "dataclasses", "typing",
            "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestCreate(unittest.TestCase):
    def test_create_roundtrip_verify(self):
        m = UserProfileManager()
        rec = m.create("u1", "Ada Lovelace", 1, email="ada@example.com")
        self.assertEqual(rec.field("display_name"), "Ada Lovelace")
        self.assertEqual(rec.field("email"), "ada@example.com")
        self.assertTrue(rec.verify())
        self.assertEqual(m.profile("u1").digest, rec.digest)

    def test_create_duplicate(self):
        m = UserProfileManager()
        m.create("u1", "Ada", 1)
        with self.assertRaises(DuplicateProfileError):
            m.create("u1", "Ada Again", 2)

    def test_create_bad_seq(self):
        m = UserProfileManager()
        for bad in ("1", 1.0, True, -1):
            with self.assertRaises(ValidationError):
                m.create("u1", "Ada", bad)
        m.create("u1", "Ada", 5)
        # seq is per-profile: a fresh id may start at any non-negative seq
        m.create("u2", "Bob", 5)
        # same profile: duplicate wins before seq order is evaluated
        with self.assertRaises(DuplicateProfileError):
            m.create("u1", "Ada", 4)

    def test_create_bad_display_name(self):
        m = UserProfileManager()
        with self.assertRaises(ValidationError):
            m.create("u1", "   ", 1)
        with self.assertRaises(ValidationError):
            m.create("u1", "x" * 129, 1)

    def test_create_bad_email_and_phone(self):
        m = UserProfileManager()
        for bad_email in ("not-an-email", "a@b", "@x.com", "a b@c.com"):
            with self.assertRaises(ValidationError):
                m.create(f"u-{bad_email}", "Ada", 1, email=bad_email)
        for bad_phone in ("abc", "++1-555", "12!!34"):
            with self.assertRaises(ValidationError):
                m.create(f"p-{bad_phone}", "Ada", 1, phone=bad_phone)

    def test_create_bad_locale_timezone(self):
        m = UserProfileManager()
        with self.assertRaises(ValidationError):
            m.create("u1", "Ada", 1, locale="english")
        with self.assertRaises(ValidationError):
            m.create("u1", "Ada", 1, timezone="Mars")
        rec = m.create("u2", "Ada", 2, locale="en-US", timezone="America/New_York")
        self.assertTrue(rec.verify())


class TestUpdate(unittest.TestCase):
    def test_update_field_chain(self):
        m = UserProfileManager()
        old = m.create("u1", "Ada", 1, email="ada@example.com")
        new = m.update("u1", 2, fields={"bio": "first programmer", "email": "new@example.com"})
        self.assertEqual(new.field("bio"), "first programmer")
        self.assertEqual(new.field("email"), "new@example.com")
        self.assertEqual(new.prev_digest, old.digest)
        self.assertNotEqual(new.digest, old.digest)
        self.assertTrue(new.verify())
        with self.assertRaises(SeqOrderError):
            m.update("u1", 2, fields={"bio": "x"})

    def test_update_clears_field_with_empty(self):
        m = UserProfileManager()
        m.create("u1", "Ada", 1, bio="hello")
        rec = m.update("u1", 2, fields={"bio": ""})
        self.assertIsNone(rec.field("bio"))
        self.assertTrue(rec.verify())
        self.assertEqual(rec.level("bio"), "private")  # visibility pin dropped

    def test_update_unknown_field(self):
        m = UserProfileManager()
        m.create("u1", "Ada", 1)
        with self.assertRaises(ValidationError):
            m.update("u1", 2, fields={"ssn": "123"})
        with self.assertRaises(ValidationError):
            m.update("u1", 3, fields={"custom:Bad Key!": "v"})

    def test_update_visibility_levels(self):
        m = UserProfileManager()
        rec = m.create("u1", "Ada", 1, email="ada@example.com")
        rec = m.update("u1", 2, visibility={"email": "contacts"})
        self.assertEqual(rec.level("email"), "contacts")
        self.assertTrue(rec.verify())
        with self.assertRaises(ValidationError):
            m.update("u1", 3, visibility={"email": "everyone"})
        # rejected updates still consume their seq (audit trail stays ordered)
        with self.assertRaises(ValidationError):
            m.update("u1", 4, visibility={"phone": "public"})  # phone unset


class TestVisibility(unittest.TestCase):
    def _manager(self):
        m = UserProfileManager()
        m.create(
            "u1", "Ada", 1,
            bio="pioneer", email="ada@example.com", phone="+14155550101",
            visibility_overrides=(("email", "contacts"),),
        )
        return m

    def test_self_sees_everything(self):
        m = self._manager()
        rec = m.profile("u1")
        view = m.visibility("u1", 2, "self")
        shown = dict(view.fields)
        self.assertEqual(shown["email"], "ada@example.com")
        self.assertEqual(shown["phone"], "+14155550101")
        self.assertEqual(shown["bio"], "pioneer")
        self.assertTrue(view.verify(rec))

    def test_public_sees_only_public(self):
        m = self._manager()
        rec = m.profile("u1")
        view = m.visibility("u1", 2, "public")
        shown = dict(view.fields)
        self.assertEqual(shown["display_name"], "Ada")
        self.assertEqual(shown["bio"], "pioneer")
        self.assertNotIn("email", shown)   # contacts-only: hidden
        self.assertNotIn("phone", shown)   # private: hidden
        self.assertTrue(view.verify(rec))

    def test_contacts_sees_contacts_plus_public(self):
        m = self._manager()
        rec = m.profile("u1")
        view = m.visibility("u1", 2, "contacts")
        shown = dict(view.fields)
        self.assertEqual(shown["email"], "ada@example.com")  # contacts level
        self.assertNotIn("phone", shown)                      # private still hidden
        self.assertTrue(view.verify(rec))

    def test_unknown_relation(self):
        m = self._manager()
        with self.assertRaises(ValidationError):
            m.visibility("u1", 2, "admin")
        with self.assertRaises(UnknownProfileError):
            m.visibility("nope", 2, "self")


class TestMisc(unittest.TestCase):
    def test_audit_event_shape_no_pii(self):
        m = UserProfileManager()
        m.create("u1", "Ada", 1, email="ada@example.com")
        m.visibility("u1", 2, "public")
        trail = m.audit_trail()
        self.assertEqual([e["kind"] for e in trail], ["created", "visibility-checked"])
        self.assertTrue(all(e["module"] == "user-profile" for e in trail))
        self.assertTrue(all(e["schema"] == "audit.ndjson/1" for e in trail))
        # no field values ever leak into the audit trail
        blob = str(trail)
        self.assertNotIn("ada@example.com", blob)
        with self.assertRaises(ValidationError):
            user_profile_audit_event("leaked", 1, "u1")

    def test_tamper_detected_via_verify(self):
        m = UserProfileManager()
        rec = m.create("u1", "Ada", 1, email="ada@example.com")
        forged = UserProfile(
            profile_id=rec.profile_id,
            fields=rec.fields + (("custom:admin", "yes"),),
            visibility=rec.visibility,
            seq=rec.seq,
            prev_digest=rec.prev_digest,
            digest=rec.digest,
        )
        self.assertFalse(forged.verify())

    def test_record_frozen(self):
        m = UserProfileManager()
        rec = m.create("u1", "Ada", 1)
        with self.assertRaises(FrozenInstanceError):
            rec.seq = 99  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
