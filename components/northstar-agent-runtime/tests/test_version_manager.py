"""Tests for version_manager (unittest, matching repo harness)."""

import ast
import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RUNTIME))

import version_manager as vm_mod
from version_manager import (
    AUDIT_KINDS,
    KIND_COMPARED,
    KIND_PARSED,
    KIND_REJECTED,
    KIND_SATISFIED,
    SCHEMA_PIN,
    VERSION_MANAGER_VERSION,
    BadRangeError,
    BadVersionError,
    DuplicateVersionError,
    SeqOrderError,
    UnknownVersionError,
    VersionError,
    VersionManager,
    version_manager_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(VERSION_MANAGER_VERSION, "version-manager.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.version-manager.v1")

    def test_stdlib_only(self):
        tree = ast.parse(Path(vm_mod.__file__).read_text())
        allowed = {
            "__future__", "hashlib", "json", "re", "threading",
            "dataclasses", "typing", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestParse(unittest.TestCase):
    def setUp(self):
        self.vm = VersionManager()

    def test_roundtrip(self):
        r = self.vm.parse("1.2.3", 0)
        self.assertEqual((r.major, r.minor, r.patch), (1, 2, 3))
        self.assertEqual(r.prerelease, ())
        self.assertEqual(r.build, ())
        self.assertEqual(r.canonical, "1.2.3")
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertTrue(r.verify())

    def test_prerelease_and_build(self):
        r = self.vm.parse("1.0.0-alpha.1+build.42", 0)
        self.assertEqual(r.prerelease, ("alpha", "1"))
        self.assertEqual(r.build, ("build", "42"))
        self.assertEqual(r.canonical, "1.0.0-alpha.1+build.42")

    def test_loose_padding(self):
        r = self.vm.parse("2", 0, strict=False)
        self.assertEqual(r.canonical, "2.0.0")
        r2 = self.vm.parse("3.4", 1, strict=False)
        self.assertEqual(r2.canonical, "3.4.0")

    def test_leading_zero_refused(self):
        with self.assertRaises(BadVersionError):
            self.vm.parse("01.2.3", 0)
        with self.assertRaises(BadVersionError):
            self.vm.parse("1.2", 1)  # strict requires X.Y.Z

    def test_malformed_refused(self):
        for bad in ("", "v1.2.3", "1.2.3-", "1.2.3+", "a.b.c", "1.2.3.4"):
            with self.assertRaises((BadVersionError, VersionError), msg=bad):
                self.vm.parse(bad, 100 + abs(hash(bad)) % 50)
        self.assertRaises(VersionError, self.vm.parse, "1.2.3", -1)
        self.assertRaises(VersionError, self.vm.parse, "1.2.3", True)

    def test_duplicate_refused(self):
        self.vm.parse("1.2.3", 0)
        with self.assertRaises(DuplicateVersionError):
            self.vm.parse("1.2.3", 1)

    def test_seq_monotonic(self):
        self.vm.parse("1.0.0", 0)
        with self.assertRaises(SeqOrderError):
            self.vm.parse("1.0.1", 0)


class TestCompare(unittest.TestCase):
    def setUp(self):
        self.vm = VersionManager()
        self.ids = {}
        texts = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
                 "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                 "1.0.0-rc.1", "1.0.0", "1.0.0+build.1", "2.0.0"]
        for i, t in enumerate(texts):
            self.ids[t] = self.vm.parse(t, i).version_id

    def test_semver_precedence_chain(self):
        # The canonical semver.org ordering example.
        chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
                 "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                 "1.0.0-rc.1", "1.0.0"]
        seq = 100
        for lo, hi in zip(chain, chain[1:]):
            r = self.vm.compare(self.ids[lo], self.ids[hi], seq)
            self.assertEqual(r.result, -1, f"{lo} < {hi}")
            r2 = self.vm.compare(self.ids[hi], self.ids[lo], seq + 1)
            self.assertEqual(r2.result, 1)
            seq += 2

    def test_numeric_prerelease_compares_numerically(self):
        # beta.11 > beta.2 (numeric, not lexical).
        r = self.vm.compare(self.ids["1.0.0-beta.2"],
                            self.ids["1.0.0-beta.11"], 200)
        self.assertEqual(r.result, -1)

    def test_numeric_below_alphanumeric(self):
        # alpha.1 (numeric tail) < alpha.beta (alphanumeric tail).
        r = self.vm.compare(self.ids["1.0.0-alpha.1"],
                            self.ids["1.0.0-alpha.beta"], 200)
        self.assertEqual(r.result, -1)

    def test_equal_and_build_ignored(self):
        r = self.vm.compare(self.ids["1.0.0"], self.ids["1.0.0"], 200)
        self.assertEqual(r.result, 0)
        r2 = self.vm.compare(self.ids["1.0.0"], self.ids["1.0.0+build.1"], 201)
        self.assertEqual(r2.result, 0)

    def test_major_minor_patch(self):
        r = self.vm.compare(self.ids["1.0.0"], self.ids["2.0.0"], 200)
        self.assertEqual(r.result, -1)

    def test_unknown_id(self):
        with self.assertRaises(UnknownVersionError):
            self.vm.compare("ver-999", self.ids["1.0.0"], 300)


class TestRanges(unittest.TestCase):
    def setUp(self):
        self.vm = VersionManager()
        self.ids = {}
        texts = ["0.9.0", "1.2.3", "1.2.3-alpha.1", "1.4.0",
                 "2.0.0", "2.0.0-beta.1", "4.0.0"]
        for i, t in enumerate(texts):
            self.ids[t] = self.vm.parse(t, i).version_id
        self.seq = 100

    def sat(self, version, rng):
        self.seq += 1
        return self.vm.satisfies(self.ids[version], rng, self.seq).satisfies

    def test_caret(self):
        self.assertTrue(self.sat("1.2.3", "^1.0.0"))
        self.assertTrue(self.sat("1.4.0", "^1.2.3"))
        self.assertFalse(self.sat("2.0.0", "^1.2.3"))

    def test_tilde(self):
        self.assertTrue(self.sat("1.2.3", "~1.2.0"))
        self.assertFalse(self.sat("1.4.0", "~1.2.0"))  # ~ pins minor
        self.assertFalse(self.sat("2.0.0", "~1.2.0"))
        self.assertTrue(self.sat("1.4.0", "~1"))  # ~1 := >=1.0.0 <2.0.0

    def test_comparators(self):
        self.assertTrue(self.sat("1.2.3", ">=1.0.0 <2.0.0"))
        self.assertFalse(self.sat("2.0.0", ">=1.0.0 <2.0.0"))
        self.assertTrue(self.sat("1.2.3", "=1.2.3"))
        self.assertFalse(self.sat("1.4.0", "=1.2.3"))

    def test_wildcard(self):
        self.assertTrue(self.sat("1.2.3", "1.x"))
        self.assertTrue(self.sat("1.4.0", "1.*"))
        self.assertFalse(self.sat("2.0.0", "1.x"))
        self.assertTrue(self.sat("2.0.0", "*"))

    def test_hyphen_range(self):
        self.assertTrue(self.sat("1.2.3", "1.0.0 - 2.0.0"))
        self.assertFalse(self.sat("0.9.0", "1.0.0 - 2.0.0"))

    def test_union(self):
        self.assertTrue(self.sat("1.2.3", ">=3.0.0 || =1.2.3"))
        self.assertFalse(self.sat("1.4.0", ">=3.0.0 || =1.2.3"))

    def test_prerelease_discipline(self):
        # Pre-release only satisfies ranges mentioning a pre-release on the
        # same MAJOR.MINOR.PATCH.
        self.assertFalse(self.sat("1.2.3-alpha.1", ">=1.0.0 <2.0.0"))
        self.assertTrue(self.sat("1.2.3-alpha.1",
                                 ">=1.2.3-alpha.1 <2.0.0"))

    def test_bad_range(self):
        with self.assertRaises(BadRangeError):
            self.vm.satisfies(self.ids["1.2.3"], ">=1.0.0 <<<", self.seq + 1)
        with self.assertRaises(BadRangeError):
            self.vm.satisfies(self.ids["1.2.3"], "1.2 - 3.0", self.seq + 2)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        ev = version_manager_audit_event(KIND_PARSED, 0, version_id="ver-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module_version"], VERSION_MANAGER_VERSION)
        ev2 = version_manager_audit_event(KIND_SATISFIED, 1, satisfies=True)
        self.assertEqual(ev2["event"], KIND_SATISFIED)
        for kind in (KIND_PARSED, KIND_COMPARED, KIND_SATISFIED, KIND_REJECTED):
            self.assertIn(kind, AUDIT_KINDS)
        with self.assertRaises(VersionError):
            version_manager_audit_event("nope", 2)


class TestMain(unittest.TestCase):
    def test_main(self):
        vm_mod.main()


if __name__ == "__main__":
    unittest.main()
