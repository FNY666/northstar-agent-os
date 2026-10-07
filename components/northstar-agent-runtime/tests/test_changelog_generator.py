"""Tests for changelog_generator."""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from changelog_generator import (
    CHANGELOG_GENERATOR_VERSION,
    SCHEMA_PIN,
    BadCommitError,
    BadVersionError,
    ChangelogError,
    ChangelogGenerator,
    DuplicateCommitError,
    LedgerFullError,
    ParsedCommit,
    RenderedChangelog,
    SeqOrderError,
    UnknownCommitError,
    VersionBump,
    changelog_generator_audit_event,
)

MODULE = Path(__file__).resolve().parent.parent / "changelog_generator.py"

_STDLIB = {
    "__future__", "re", "threading", "dataclasses", "typing",
    "hashlib", "json", "canonical_json",
}


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CHANGELOG_GENERATOR_VERSION, "changelog-generator.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.changelog-generator.v1")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        tree = ast.parse(MODULE.read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    imports.add(a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0])
        self.assertLessEqual(imports, _STDLIB, f"non-stdlib imports: {imports - _STDLIB}")


class TestParse(unittest.TestCase):
    def test_parse_roundtrip(self):
        gen = ChangelogGenerator()
        rec = gen.parse("feat(api): add pagination", 0)
        self.assertIsInstance(rec, ParsedCommit)
        self.assertEqual(rec.type, "feat")
        self.assertEqual(rec.scope, "api")
        self.assertEqual(rec.subject, "add pagination")
        self.assertFalse(rec.breaking)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.version, CHANGELOG_GENERATOR_VERSION)

    def test_parse_no_scope(self):
        gen = ChangelogGenerator()
        rec = gen.parse("fix: null pointer on empty cart", 0)
        self.assertIsNone(rec.scope)
        self.assertEqual(rec.subject, "null pointer on empty cart")

    def test_parse_bang_breaking(self):
        gen = ChangelogGenerator()
        rec = gen.parse("refactor(db)!: drop legacy schema", 0)
        self.assertTrue(rec.breaking)
        self.assertIsNone(rec.breaking_note)

    def test_parse_breaking_trailer(self):
        gen = ChangelogGenerator()
        rec = gen.parse(
            "feat: new auth\n\nBREAKING CHANGE: tokens now expire", 0)
        self.assertTrue(rec.breaking)
        self.assertEqual(rec.breaking_note, "tokens now expire")

    def test_parse_body_kept(self):
        gen = ChangelogGenerator()
        rec = gen.parse("docs: update readme\n\nCloses #1\nSee also #2", 0)
        self.assertEqual(rec.body, ("", "Closes #1", "See also #2"))

    def test_parse_commit_id(self):
        gen = ChangelogGenerator()
        rec = gen.parse("chore: deps", 0, commit_id="abc123")
        self.assertEqual(rec.commit_id, "abc123")
        self.assertEqual(gen.commit("abc123").commit_id, "abc123")

    def test_duplicate_commit_id_refused(self):
        gen = ChangelogGenerator()
        gen.parse("chore: deps", 0, commit_id="dup")
        with self.assertRaises(DuplicateCommitError):
            gen.parse("chore: more", 1, commit_id="dup")

    def test_unknown_commit_lookup(self):
        gen = ChangelogGenerator()
        with self.assertRaises(UnknownCommitError):
            gen.commit("nope")

    def test_bad_commits_refused(self):
        for bad in (
            "no colon here",
            "WIP: done",
            "feat(): empty scope",
            "feat: ",
            "feat(BAD): uppercase scope",
            "feat(: bad scope",
            ": missing type",
            "unknowntype: nope",
            "",
        ):
            gen = ChangelogGenerator()
            with self.assertRaises(BadCommitError, msg=bad):
                gen.parse(bad, 0)

    def test_failed_parse_consumes_seq(self):
        gen = ChangelogGenerator()
        with self.assertRaises(BadCommitError):
            gen.parse("not a commit", 0)
        with self.assertRaises(SeqOrderError):
            gen.parse("docs: fine", 0)  # 0 was consumed by the failure

    def test_seq_ordering(self):
        gen = ChangelogGenerator()
        gen.parse("docs: one", 0)
        with self.assertRaises(SeqOrderError):
            gen.parse("docs: two", 0)
        with self.assertRaises(SeqOrderError):
            gen.parse("docs: two", True)
        with self.assertRaises(SeqOrderError):
            gen.parse("docs: two", -1)

    def test_non_str_commit_refused(self):
        gen = ChangelogGenerator()
        with self.assertRaises(BadCommitError):
            gen.parse(None, 0)  # type: ignore[arg-type]


class TestRender(unittest.TestCase):
    def _ledger(self):
        gen = ChangelogGenerator()
        gen.parse("feat(api): add pagination", 0)
        gen.parse("fix(cart): null pointer", 1)
        gen.parse("docs: typo", 2)
        return gen

    def test_render_sections(self):
        gen = self._ledger()
        out = gen.render(3, version="1.2.0")
        self.assertIsInstance(out, RenderedChangelog)
        self.assertEqual(out.version, "1.2.0")
        self.assertTrue(out.text.startswith("## 1.2.0\n"))
        self.assertIn("### Features", out.text)
        self.assertIn("### Bug Fixes", out.text)
        self.assertIn("### Documentation", out.text)
        self.assertIn("- **api:** add pagination", out.text)
        self.assertEqual(out.sections,
                         ("Features", "Bug Fixes", "Documentation"))
        self.assertTrue(out.verify(out.text))
        self.assertFalse(out.verify(out.text + "tampered"))

    def test_render_default_unreleased(self):
        gen = self._ledger()
        out = gen.render(3)
        self.assertEqual(out.version, "Unreleased")
        self.assertTrue(out.text.startswith("## Unreleased\n"))

    def test_render_breaking_section(self):
        gen = ChangelogGenerator()
        gen.parse("refactor(db)!: drop legacy\n\nBREAKING CHANGE: tables gone", 0)
        out = gen.render(1, version="2.0.0")
        self.assertIn("### BREAKING CHANGES", out.text)
        self.assertIn("tables gone", out.text)
        self.assertIn("BREAKING CHANGES", out.sections)

    def test_render_empty_ledger(self):
        gen = ChangelogGenerator()
        out = gen.render(0, version="0.1.0")
        self.assertEqual(out.sections, ())
        self.assertEqual(out.commit_ids, ())
        self.assertTrue(out.verify(out.text))

    def test_render_bad_version_label(self):
        gen = self._ledger()
        with self.assertRaises(BadVersionError):
            gen.render(3, version="")


class TestBump(unittest.TestCase):
    def test_bump_major(self):
        gen = ChangelogGenerator()
        gen.parse("feat: x", 0)
        gen.parse("fix!: y\n\nBREAKING CHANGE: api removed", 1)
        bump = gen.bump("1.2.3", 2)
        self.assertIsInstance(bump, VersionBump)
        self.assertEqual(bump.level, "major")
        self.assertEqual(bump.next, "2.0.0")
        self.assertEqual(bump.reason, "breaking-change")
        self.assertEqual(bump.current, "1.2.3")

    def test_bump_minor(self):
        gen = ChangelogGenerator()
        gen.parse("feat: x", 0)
        gen.parse("fix: y", 1)
        bump = gen.bump("1.2.3", 2)
        self.assertEqual(bump.level, "minor")
        self.assertEqual(bump.next, "1.3.0")
        self.assertEqual(bump.reason, "feature")

    def test_bump_patch(self):
        gen = ChangelogGenerator()
        gen.parse("docs: x", 0)
        bump = gen.bump("1.2.3", 1)
        self.assertEqual(bump.level, "patch")
        self.assertEqual(bump.next, "1.2.4")
        self.assertEqual(bump.reason, "no-breaking-or-feature")

    def test_bump_empty_ledger(self):
        gen = ChangelogGenerator()
        bump = gen.bump("0.0.0", 0)
        self.assertEqual(bump.level, "patch")
        self.assertEqual(bump.next, "0.0.1")
        self.assertEqual(bump.reason, "empty-ledger")

    def test_bump_prerelease_ignored(self):
        gen = ChangelogGenerator()
        gen.parse("fix: x", 0)
        bump = gen.bump("1.2.3-rc.1", 1)
        self.assertEqual(bump.next, "1.2.4")

    def test_bump_bad_version(self):
        for i, bad in enumerate(("1.2", "v1.2.3", "1.2.3.4", "", "1.02.3", None)):
            gen = ChangelogGenerator()
            with self.assertRaises(BadVersionError, msg=repr(bad)):
                gen.bump(bad, i)  # type: ignore[arg-type]

    def test_bump_commit_ids_pinned(self):
        gen = ChangelogGenerator()
        gen.parse("feat: x", 0, commit_id="c1")
        bump = gen.bump("0.1.0", 1)
        self.assertEqual(bump.commit_ids, ("c1",))


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        gen = ChangelogGenerator()
        gen.parse("feat: x", 0, commit_id="c1")
        gen.render(1, version="0.2.0")
        gen.bump("0.1.0", 2)
        log = gen.audit_log()
        kinds = [e["event"] for e in log]
        self.assertEqual(kinds, ["parsed", "rendered", "bumped"])
        for event in log:
            self.assertEqual(event["schema"], "audit.ndjson/1")
        parsed = log[0]
        self.assertEqual(parsed["commit_id"], "c1")
        self.assertNotIn("body", parsed)
        self.assertNotIn("subject", parsed)

    def test_audit_rejected(self):
        gen = ChangelogGenerator()
        with self.assertRaises(BadCommitError):
            gen.parse("garbage", 0)
        log = gen.audit_log()
        self.assertEqual(log[0]["event"], "rejected")

    def test_audit_bad_kind(self):
        with self.assertRaises(ChangelogError):
            changelog_generator_audit_event("nope", 0)

    def test_audit_boundary_ban(self):
        with self.assertRaises(ChangelogError):
            changelog_generator_audit_event("parsed", 0, body="secret")


class TestMain(unittest.TestCase):
    def test_main(self):
        import changelog_generator
        changelog_generator.main()


if __name__ == "__main__":
    unittest.main()
