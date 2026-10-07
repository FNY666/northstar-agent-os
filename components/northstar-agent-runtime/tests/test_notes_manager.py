"""Tests for notes_manager."""

import ast
import unittest

import notes_manager
from notes_manager import (
    ArchivedNoteError,
    NotesManager,
    SeqOrderError,
    UnknownNoteError,
    UnknownTagError,
    ValidationError,
    notes_manager_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(notes_manager.NOTES_MANAGER_VERSION, "notes-manager.v1")
        self.assertEqual(notes_manager.SCHEMA_PIN, "northstar.notes-manager.v1")

    def test_create_record_pins(self):
        nm = NotesManager()
        rec, _ = nm.create("T", "body", 1)
        self.assertEqual(rec.version, "notes-manager.v1")
        self.assertEqual(rec.schema, "northstar.notes-manager.v1")
        self.assertTrue(rec.title_digest.startswith("sha256:"))
        self.assertTrue(rec.body_digest.startswith("sha256:"))


class TestCreate(unittest.TestCase):
    def test_roundtrip(self):
        nm = NotesManager()
        rec, nid = nm.create("Groceries", "Buy **milk**", 1)
        self.assertEqual(nid, "note-1")
        self.assertEqual(nm.body(nid), "Buy **milk**")
        self.assertEqual(nm.note(nid), rec)
        self.assertTrue(rec.verify_body("Buy **milk**"))
        self.assertFalse(rec.verify_body("Buy **bread**"))

    def test_digest_determinism(self):
        a = NotesManager()
        b = NotesManager()
        ra, _ = a.create("T", "same body", 1)
        rb, _ = b.create("T", "same body", 1)
        self.assertEqual(ra.title_digest, rb.title_digest)
        self.assertEqual(ra.body_digest, rb.body_digest)

    def test_derived_title_from_heading(self):
        nm = NotesManager()
        rec, _ = nm.create(None, "# Real Title\n\ntext", 1)
        self.assertEqual(rec.title, "Real Title")

    def test_derived_title_from_first_line(self):
        nm = NotesManager()
        rec, _ = nm.create(None, "first line\nsecond line", 1)
        self.assertEqual(rec.title, "first line")

    def test_derived_title_blank_body(self):
        nm = NotesManager()
        rec, _ = nm.create(None, "", 1)
        self.assertEqual(rec.title, "Untitled")

    def test_bad_inputs(self):
        nm = NotesManager()
        with self.assertRaises(ValidationError):
            nm.create("", "body", 1)
        with self.assertRaises(ValidationError):
            nm.create(123, "body", 2)  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            nm.create("T", 123, 3)  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            nm.create("T", "body", True)
        with self.assertRaises(ValidationError):
            nm.create("T", "body", -1)

    def test_seq_rewind(self):
        nm = NotesManager()
        nm.create("T", "b", 1)
        with self.assertRaises(SeqOrderError):
            nm.create("T", "b", 1)
        with self.assertRaises(SeqOrderError):
            nm.create("T", "b", 0)


class TestTags(unittest.TestCase):
    def test_tag_roundtrip_and_normalization(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        tr = nm.tag(nid, 2, "Personal", "TODO-list")
        self.assertEqual(tr.tags, ("personal", "todo-list"))
        self.assertEqual(tr.tag, "todo-list")
        self.assertEqual(nm.note(nid).tags, ("personal", "todo-list"))

    def test_tag_idempotent(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        nm.tag(nid, 2, "work")
        nm.tag(nid, 3, "work")
        self.assertEqual(nm.tags(), {"work": 1})

    def test_tag_bad_shapes(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        for i, bad in enumerate(("", "  ", "has space", "-leading", "_leading", "UP PER")):
            with self.assertRaises(ValidationError, msg=bad):
                nm.tag(nid, 2 + i, bad)

    def test_tag_unknown_note(self):
        nm = NotesManager()
        with self.assertRaises(UnknownNoteError):
            nm.tag("note-999", 1, "x")

    def test_tag_requires_tags(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        with self.assertRaises(ValidationError):
            nm.tag(nid, 2)

    def test_untag_happy_path(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        nm.tag(nid, 2, "a", "b")
        tr = nm.untag(nid, 3, "a")
        self.assertEqual(tr.tags, ("b",))
        self.assertEqual(nm.tags(), {"b": 1})

    def test_untag_absent_tag_refused(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        nm.tag(nid, 2, "a")
        with self.assertRaises(UnknownTagError):
            nm.untag(nid, 3, "nope")

    def test_tags_view_and_notes_by_tag(self):
        nm = NotesManager()
        _, n1 = nm.create("T1", "b", 1)
        _, n2 = nm.create("T2", "b", 2)
        nm.tag(n1, 3, "x", "y")
        nm.tag(n2, 4, "x")
        self.assertEqual(nm.tags(), {"x": 2, "y": 1})
        self.assertEqual(nm.notes_by_tag("x"), [n1, n2])
        self.assertEqual(nm.notes_by_tag("y"), [n1])


class TestUpdate(unittest.TestCase):
    def test_update_body_and_title(self):
        nm = NotesManager()
        _, nid = nm.create("Old", "old body", 1)
        rec = nm.update(nid, 2, title="New", body="new body")
        self.assertEqual(rec.title, "New")
        self.assertTrue(rec.verify_body("new body"))
        self.assertFalse(rec.verify_body("old body"))

    def test_update_requires_change(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        with self.assertRaises(ValidationError):
            nm.update(nid, 2)

    def test_update_unknown_note(self):
        nm = NotesManager()
        with self.assertRaises(UnknownNoteError):
            nm.update("note-999", 1, title="x")


class TestArchive(unittest.TestCase):
    def test_archive_restore_purge(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        nm.tag(nid, 2, "t")
        rec = nm.archive(nid, 3)
        self.assertTrue(rec.archived)
        with self.assertRaises(ArchivedNoteError):
            nm.update(nid, 4, title="x")
        with self.assertRaises(ArchivedNoteError):
            nm.tag(nid, 5, "y")
        restored = nm.restore(nid, 6)
        self.assertFalse(restored.archived)
        self.assertEqual(nm.tags(), {"t": 1})
        nm.purge(nid, 7)
        self.assertEqual(nm.note_count(), 0)
        with self.assertRaises(UnknownNoteError):
            nm.note(nid)

    def test_archive_hides_from_search(self):
        nm = NotesManager()
        _, nid = nm.create("Milk", "buy milk", 1)
        nm.archive(nid, 2)
        self.assertEqual(nm.search("milk").hits, ())
        self.assertEqual(len(nm.search("milk", include_archived=True).hits), 1)


class TestSearch(unittest.TestCase):
    def _store(self):
        nm = NotesManager()
        _, n1 = nm.create("Python tricks", "generators and decorators", 1)
        _, n2 = nm.create("Groceries", "buy python-brand tea", 2)
        _, n3 = nm.create("Rust notes", "ownership and borrowing", 3)
        nm.tag(n1, 4, "code")
        nm.tag(n3, 5, "code")
        return nm, n1, n2, n3

    def test_search_ranking_title_weight(self):
        nm, n1, n2, _ = self._store()
        res = nm.search("python")
        self.assertEqual(res.hits[0].note_id, n1)  # title hit scores 2
        self.assertEqual(res.hits[1].note_id, n2)  # body hit scores 1
        self.assertEqual(res.hits[0].matched_fields, ("title",))
        self.assertIn("body", res.hits[1].matched_fields)

    def test_search_tag_match(self):
        nm, n1, _, n3 = self._store()
        res = nm.search("code")
        self.assertEqual([h.note_id for h in res.hits], [n1, n3])
        self.assertEqual(res.hits[0].matched_fields, ("tags",))

    def test_search_case_insensitive(self):
        nm, n1, _, _ = self._store()
        self.assertEqual(nm.search("PYTHON").hits[0].note_id, n1)

    def test_search_no_matches(self):
        nm, _, _, _ = self._store()
        self.assertEqual(nm.search("zebras").hits, ())

    def test_search_empty_query_refused(self):
        nm, _, _, _ = self._store()
        with self.assertRaises(ValidationError):
            nm.search("")
        with self.assertRaises(ValidationError):
            nm.search("   !!!   ")
        with self.assertRaises(ValidationError):
            nm.search(123)  # type: ignore[arg-type]

    def test_search_tag_filter(self):
        nm, n1, n2, n3 = self._store()
        nm.tag(n2, 6, "code")
        res = nm.search("python", tags=["code"])
        self.assertEqual([h.note_id for h in res.hits], [n1, n2])
        res2 = nm.search("ownership", tags=["missing"])
        self.assertEqual(res2.hits, ())

    def test_search_is_pure_view(self):
        nm, _, _, _ = self._store()
        before = len(nm.audit_log())
        nm.search("python")
        self.assertEqual(len(nm.audit_log()), before)

    def test_search_deterministic(self):
        nm, n1, _, n3 = self._store()
        a = [h.note_id for h in nm.search("code").hits]
        b = [h.note_id for h in nm.search("code").hits]
        self.assertEqual(a, b)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        nm = NotesManager()
        _, nid = nm.create("T", "b", 1)
        nm.tag(nid, 2, "x")
        nm.archive(nid, 3)
        kinds = [e["kind"] for e in nm.audit_log()]
        self.assertEqual(kinds, ["created", "tagged", "archived"])
        for e in nm.audit_log():
            self.assertEqual(e["module"], "notes-manager")
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["version"], "notes-manager.v1")

    def test_audit_unknown_kind(self):
        with self.assertRaises(ValidationError):
            notes_manager_audit_event("nope", 1, "note-1")


class TestStdlib(unittest.TestCase):
    def test_stdlib_only(self):
        import pathlib

        src = pathlib.Path(notes_manager.__file__).read_text()
        tree = ast.parse(src)
        allowed = {
            "__future__",
            "hashlib",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "json",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main(self):
        notes_manager.main()


if __name__ == "__main__":
    unittest.main()
