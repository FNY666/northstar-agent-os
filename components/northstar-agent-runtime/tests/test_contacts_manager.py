"""Tests for contacts_manager: CardDAV-shaped contact bookkeeping."""

import ast
import unittest

from contacts_manager import (
    CONTACTS_MANAGER_VERSION,
    SCHEMA_PIN,
    ContactsManager,
    DuplicateContactError,
    DuplicateGroupError,
    NotMemberError,
    SeqOrderError,
    UnknownContactError,
    UnknownGroupError,
    ValidationError,
    contacts_manager_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(CONTACTS_MANAGER_VERSION, "contacts-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.contacts-manager.v1")

    def test_stdlib_only(self):
        tree = ast.parse(open("contacts_manager.py").read())
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


class TestAdd(unittest.TestCase):
    def test_add_roundtrip(self):
        cm = ContactsManager()
        rec = cm.add("c1", "Ada Lovelace", 1, emails=["ada@example.com"])
        self.assertEqual(rec.name, "Ada Lovelace")
        self.assertEqual(rec.emails, ("ada@example.com",))
        self.assertTrue(rec.verify())
        self.assertEqual(cm.contact("c1").name, "Ada Lovelace")

    def test_add_duplicate(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 1)
        with self.assertRaises(DuplicateContactError):
            cm.add("c1", "Ada Again", 2)

    def test_add_bad_inputs(self):
        cm = ContactsManager()
        with self.assertRaises(ValidationError):
            cm.add("", "Ada", 1)
        with self.assertRaises(ValidationError):
            cm.add("c1", "   ", 2)
        with self.assertRaises(ValidationError):
            cm.add("c1", "Ada", 3, emails=["not-an-email"])
        with self.assertRaises(ValidationError):
            cm.add("c1", "Ada", 4, phones=["abc"])
        with self.assertRaises(ValidationError):
            cm.add("c1", "Ada", True)

    def test_add_seq_order(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 5)
        with self.assertRaises(SeqOrderError):
            cm.add("c2", "Grace", 5)
        with self.assertRaises(SeqOrderError):
            cm.add("c2", "Grace", 1)


class TestSearch(unittest.TestCase):
    def test_search_by_name(self):
        cm = ContactsManager()
        cm.add("c1", "Ada Lovelace", 1)
        cm.add("c2", "Grace Hopper", 2)
        rep = cm.search("ada", 3)
        self.assertEqual(rep.matches, ("c1",))

    def test_search_by_email_and_phone(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 1, emails=["ada@example.com"], phones=["+14155550101"])
        self.assertEqual(cm.search("example.com", 2).matches, ("c1",))
        self.assertEqual(cm.search("4155550101", 3).matches, ("c1",))

    def test_search_bad_query(self):
        cm = ContactsManager()
        with self.assertRaises(ValidationError):
            cm.search("  ", 1)


class TestGroups(unittest.TestCase):
    def test_group_members(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 1)
        cm.add("c2", "Grace", 2)
        grp = cm.group("g1", "Friends", 3, members=["c1", "c2"])
        self.assertEqual(grp.members, ("c1", "c2"))
        self.assertTrue(grp.verify())
        grp = cm.add_member("g1", "c1", 4)  # idempotent
        self.assertEqual(grp.members, ("c1", "c2"))
        grp = cm.remove_member("g1", "c2", 5)
        self.assertEqual(grp.members, ("c1",))
        with self.assertRaises(NotMemberError):
            cm.remove_member("g1", "c2", 6)

    def test_group_errors(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 1)
        with self.assertRaises(UnknownGroupError):
            cm.add_member("nope", "c1", 2)
        cm.group("g1", "G", 3)
        with self.assertRaises(UnknownContactError):
            cm.add_member("g1", "ghost", 4)
        with self.assertRaises(UnknownContactError):
            cm.group("g2", "G2", 5, members=["ghost"])
        with self.assertRaises(DuplicateGroupError):
            cm.group("g1", "G again", 6)


class TestUpdateRemove(unittest.TestCase):
    def test_update(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 1, org="Analytical Engines")
        rec = cm.update("c1", 2, name="Ada Lovelace", emails=["ada@example.com"])
        self.assertEqual(rec.name, "Ada Lovelace")
        self.assertEqual(rec.emails, ("ada@example.com",))
        self.assertEqual(rec.org, "Analytical Engines")  # preserved
        self.assertTrue(rec.verify())
        with self.assertRaises(UnknownContactError):
            cm.update("ghost", 3, name="X")

    def test_remove_cleans_groups(self):
        cm = ContactsManager()
        cm.add("c1", "Ada", 1)
        cm.group("g1", "Friends", 2, members=["c1"])
        cm.remove("c1", 3)
        self.assertEqual(cm.group_record("g1").members, ())
        with self.assertRaises(UnknownContactError):
            cm.contact("c1")
        with self.assertRaises(UnknownContactError):
            cm.remove("c1", 4)


class TestVCard(unittest.TestCase):
    def test_vcard_shape(self):
        cm = ContactsManager()
        cm.add("c1", "Ada Lovelace", 1, emails=["ada@example.com"],
               phones=["+14155550101"], org="Analytical Engines")
        doc = cm.to_vcard("c1", 2)
        self.assertIn("BEGIN:VCARD", doc.text)
        self.assertIn("VERSION:4.0", doc.text)
        self.assertIn("FN:Ada Lovelace", doc.text)
        self.assertIn("EMAIL:ada@example.com", doc.text)
        self.assertIn("END:VCARD", doc.text)
        self.assertTrue(doc.verify(doc.text))
        self.assertFalse(doc.verify(doc.text + "x"))


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("added", "updated", "removed", "searched", "rendered",
                     "grouped", "member-added", "member-removed", "rejected"):
            ev = contacts_manager_audit_event(kind, 1, "t1")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "contacts-manager")
        with self.assertRaises(ValidationError):
            contacts_manager_audit_event("nope", 1, "t1")

    def test_main(self):
        from contacts_manager import main
        main()


if __name__ == "__main__":
    unittest.main()
