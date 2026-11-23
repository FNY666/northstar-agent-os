"""Tests for release_manager: draft / notes / publish bookkeeping."""

import ast
import threading
import unittest
from pathlib import Path

from release_manager import (
    AUDIT_SCHEMA,
    NOTE_SECTIONS,
    BadNotesError,
    BadReleaseError,
    DuplicateTagError,
    PublishedError,
    RELEASE_MANAGER_SCHEMA,
    RELEASE_MANAGER_VERSION,
    ReleaseManager,
    ReleaseManagerError,
    SeqOrderError,
    TerminalReleaseError,
    UnknownReleaseError,
    release_manager_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(RELEASE_MANAGER_VERSION, "release-manager.v1")
        self.assertEqual(RELEASE_MANAGER_SCHEMA, "northstar.release-manager.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")
        self.assertEqual(NOTE_SECTIONS,
                         ("breaking", "features", "fixes", "security", "misc"))


class TestDraft(unittest.TestCase):
    def test_draft_roundtrip(self):
        mgr = ReleaseManager()
        d = mgr.draft("v1.0.0-dev", 0, name="v1.0.0", target="main")
        self.assertEqual(d.release_id, "rel-1")
        self.assertEqual(d.tag_name, "v1.0.0-dev")
        self.assertEqual(d.name, "v1.0.0")
        self.assertEqual(d.target, "main")
        self.assertFalse(d.prerelease)
        self.assertIsNone(d.notes_pin)
        self.assertTrue(d.digest.startswith("sha256:"))

    def test_draft_defaults(self):
        mgr = ReleaseManager()
        d = mgr.draft("v2.0.0", 0)
        self.assertEqual(d.name, "v2.0.0")  # name defaults to tag
        self.assertEqual(d.target, "main")
        self.assertTrue(isinstance(d.prerelease, bool))

    def test_draft_prerelease_flag(self):
        mgr = ReleaseManager()
        d = mgr.draft("v3.0.0-rc1", 0, prerelease=True)
        self.assertTrue(d.prerelease)

    def test_duplicate_tag_refused(self):
        mgr = ReleaseManager()
        mgr.draft("v1.0.0", 0)
        with self.assertRaises(DuplicateTagError):
            mgr.draft("v1.0.0", 1)

    def test_bad_draft_inputs(self):
        mgr = ReleaseManager()
        for bad in ("", None, 123, []):
            with self.assertRaises(ReleaseManagerError, msg=repr(bad)):
                mgr.draft(bad, 0)
        with self.assertRaises(BadReleaseError):
            mgr.draft("v9.9.9", 1, prerelease="yes")

    def test_seq_monotonicity(self):
        mgr = ReleaseManager()
        mgr.draft("v1.0.0", 5)
        with self.assertRaises(SeqOrderError):
            mgr.draft("v1.0.1", 5)  # rewind refuses
        with self.assertRaises(SeqOrderError):
            mgr.draft("v1.0.1", 4)
        with self.assertRaises(ReleaseManagerError):
            mgr.draft("v1.0.1", True)  # bool is not int
        mgr.draft("v1.0.1", 6)  # fresh seq works


class TestNotes(unittest.TestCase):
    def test_notes_roundtrip(self):
        mgr = ReleaseManager()
        d = mgr.draft("v1.1.0", 0)
        n = mgr.notes(d.release_id, 1,
                      {"features": ["add ledger", "pin digests"],
                       "fixes": ["close seq rewind"]})
        self.assertEqual(n.release_id, d.release_id)
        self.assertTrue(n.digest.startswith("sha256:"))
        self.assertEqual(n.sections,
                         (("features", ("add ledger", "pin digests")),
                          ("fixes", ("close seq rewind",))))
        self.assertEqual(mgr.draft_record(d.release_id).notes_pin, n.digest)

    def test_notes_unknown_release(self):
        mgr = ReleaseManager()
        with self.assertRaises(UnknownReleaseError):
            mgr.notes("rel-99", 0, {"misc": ["x"]})

    def test_notes_bad_sections(self):
        mgr = ReleaseManager()
        d = mgr.draft("v1.2.0", 0)
        with self.assertRaises(BadNotesError):  # unknown section
            mgr.notes(d.release_id, 1, {"marketing": ["shiny"]})
        with self.assertRaises(BadNotesError):  # empty mapping
            mgr.notes(d.release_id, 2, {})
        with self.assertRaises(BadNotesError):  # not a mapping
            mgr.notes(d.release_id, 3, [("features", ["x"])])
        with self.assertRaises(BadNotesError):  # empty bullet list
            mgr.notes(d.release_id, 4, {"features": []})
        with self.assertRaises(BadNotesError):  # empty bullet
            mgr.notes(d.release_id, 5, {"features": [""]})

    def test_notes_digest_determinism(self):
        mgr = ReleaseManager()
        a = mgr.draft("v2.0.0", 0)
        b = mgr.draft("v2.0.1", 1)
        sections = {"breaking": ["new API"], "misc": ["typo"]}
        na = mgr.notes(a.release_id, 2, sections)
        nb = mgr.notes(b.release_id, 3, sections)
        self.assertNotEqual(na.digest, nb.digest)  # bound to release id
        self.assertEqual(
            mgr.notes(b.release_id, 4, sections).sections, na.sections)


class TestPublish(unittest.TestCase):
    def test_publish_happy_path(self):
        mgr = ReleaseManager()
        d = mgr.draft("v3.0.0", 0, name="release three")
        n = mgr.notes(d.release_id, 1, {"features": ["go live"]})
        r = mgr.publish(d.release_id, 2)
        self.assertEqual(r.release_id, d.release_id)
        self.assertEqual(r.tag_name, "v3.0.0")
        self.assertEqual(r.notes_pin, n.digest)
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertEqual(r.published_seq, 2)
        self.assertEqual(r.draft_seq, 0)
        self.assertEqual(mgr.release_record(d.release_id).digest, r.digest)

    def test_double_publish_terminal(self):
        mgr = ReleaseManager()
        d = mgr.draft("v3.1.0", 0)
        mgr.publish(d.release_id, 1)
        with self.assertRaises(TerminalReleaseError):
            mgr.publish(d.release_id, 2)

    def test_notes_after_publish_refused(self):
        mgr = ReleaseManager()
        d = mgr.draft("v3.2.0", 0)
        mgr.publish(d.release_id, 1)
        with self.assertRaises(PublishedError):
            mgr.notes(d.release_id, 2, {"misc": ["late"]})

    def test_publish_unknown_release(self):
        mgr = ReleaseManager()
        with self.assertRaises(UnknownReleaseError):
            mgr.publish("rel-42", 0)

    def test_failed_mutation_consumes_seq(self):
        mgr = ReleaseManager()
        d = mgr.draft("v4.0.0", 0)
        try:
            mgr.notes(d.release_id, 1, {"nope": ["x"]})
        except BadNotesError:
            pass
        with self.assertRaises(SeqOrderError):
            mgr.notes(d.release_id, 1, {"misc": ["ok"]})  # seq 1 consumed
        rec = mgr.notes(d.release_id, 2, {"misc": ["ok"]})
        self.assertTrue(rec.digest.startswith("sha256:"))


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        mgr = ReleaseManager()
        d = mgr.draft("v5.0.0", 0)
        mgr.notes(d.release_id, 1, {"misc": ["docs"]})
        mgr.publish(d.release_id, 2)
        kinds = [e["event"] for e in mgr.audit_log()]
        self.assertEqual(kinds, ["draft-created", "notes-attached", "published"])
        for e in mgr.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module_version"], "release-manager.v1")
            self.assertEqual(e["module_schema"],
                             "northstar.release-manager.v1")

    def test_audit_bans_notes_text(self):
        with self.assertRaises(ReleaseManagerError):
            release_manager_audit_event("published", 0, notes="secret text")
        with self.assertRaises(ReleaseManagerError):
            release_manager_audit_event("published", 0, body="bytes")
        with self.assertRaises(ReleaseManagerError):
            release_manager_audit_event("no-such-kind", 0)

    def test_audit_ids_and_views(self):
        mgr = ReleaseManager()
        a = mgr.draft("v6.0.0", 0)
        b = mgr.draft("v6.1.0", 1)
        mgr.publish(b.release_id, 2)
        self.assertEqual(mgr.release_ids(), (a.release_id, b.release_id))
        self.assertEqual(mgr.published_ids(), (b.release_id,))
        with self.assertRaises(UnknownReleaseError):
            mgr.release_record(a.release_id)  # draft is not published


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only_imports(self):
        path = Path(__file__).with_name("release_manager.py")
        if not path.exists():
            path = (Path(__file__).parent.parent / "release_manager.py")
        tree = ast.parse(path.read_text())
        allowed = {"threading", "dataclasses", "typing", "__future__",
                   "hashlib", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)

    def test_main_self_check(self):
        import release_manager as m
        from io import StringIO
        import contextlib
        buf = StringIO()
        with contextlib.redirect_stdout(buf):
            m.main()
        self.assertIn("release-manager OK", buf.getvalue())


class TestConcurrency(unittest.TestCase):
    def test_concurrent_drafts(self):
        mgr = ReleaseManager()
        lock = threading.Lock()
        results: dict = {}

        def worker(i: int):
            with lock:
                seq = 0
                while True:
                    try:
                        rec = mgr.draft(f"v7.{i}.{seq}", seq)
                        results[i] = rec.release_id
                        return
                    except SeqOrderError:
                        seq += 1

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(set(results.values())), 8)


if __name__ == "__main__":
    unittest.main()
