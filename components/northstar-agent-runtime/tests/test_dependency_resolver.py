"""Tests for dependency_resolver: constraint solving as bookkeeping."""

import ast
import unittest
from pathlib import Path

from dependency_resolver import (
    AUDIT_SCHEMA,
    DEPENDENCY_RESOLVER_VERSION,
    SCHEMA_PIN,
    BadDependencyError,
    BadSpecError,
    BadVersionError,
    ConflictReport,
    DependencyResolver,
    DependencyResolverError,
    DuplicatePackageVersionError,
    PackageRecord,
    RequirementRecord,
    SearchLimitError,
    SeqOrderError,
    SolutionRecord,
    UnsatisfiableError,
    UnknownPackageError,
    main,
    parse_spec,
    parse_version,
    spec_matches,
    dependency_resolver_audit_event,
)


def _resolver():
    """Fresh resolver; the test owns the seq counter."""
    return DependencyResolver()


class TestVersionGrammar(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(DEPENDENCY_RESOLVER_VERSION, "dependency-resolver.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.dependency-resolver.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_parse_version(self):
        self.assertEqual(parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("10"), (10,))

    def test_parse_version_refusals(self):
        for bad in ("", "1.x", "1..2", "1.2.3a", 1.2, True, None):
            with self.assertRaises(BadVersionError):
                parse_version(bad)

    def test_spec_matches(self):
        spec = parse_spec(">=1.2,<3")
        self.assertTrue(spec_matches((2, 0), spec))
        self.assertFalse(spec_matches((1, 1), spec))
        self.assertFalse(spec_matches((3, 0), spec))
        self.assertTrue(spec_matches((2, 0), parse_spec("==2.0")))
        self.assertFalse(spec_matches((2, 1), parse_spec("==2.0")))
        self.assertTrue(spec_matches((1, 0), parse_spec("!=2.0")))
        self.assertTrue(spec_matches((1, 10), parse_spec(">1.2,<=2.0")))

    def test_spec_refusals(self):
        for bad in ("", "~1.2", "=>1.2", ">=x", "1.2", None):
            with self.assertRaises(DependencyResolverError):
                parse_spec(bad)


class TestRegistration(unittest.TestCase):
    def test_add_roundtrip(self):
        res = _resolver()
        rec = res.add("a", "1.0", 0, deps=(("b", ">=1.0"),), conflicts=("c",))
        self.assertIsInstance(rec, PackageRecord)
        self.assertEqual(rec.package, "a")
        self.assertEqual(rec.version, "1.0")
        self.assertEqual(rec.conflicts, ("c",))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version_str, DEPENDENCY_RESOLVER_VERSION)
        self.assertEqual(res.versions_of("a"), ("1.0",))

    def test_add_duplicate_version(self):
        res = _resolver()
        res.add("a", "1.0", 0)
        with self.assertRaises(DuplicatePackageVersionError):
            res.add("a", "1.0.0", 1)  # same tuple as 1.0

    def test_add_bad_inputs(self):
        res = _resolver()
        with self.assertRaises(BadVersionError):
            res.add("a", "x", 0)
        with self.assertRaises(BadDependencyError):
            res.add("a", "1.0", 1, deps=">=1.0")
        with self.assertRaises(BadSpecError):
            res.add("a", "1.0", 2, deps=(("b", "nope"),))
        with self.assertRaises(BadDependencyError):
            res.add("", "1.0", 3)
        with self.assertRaises(UnknownPackageError):
            res.versions_of("missing")

    def test_seq_order(self):
        res = _resolver()
        res.add("a", "1.0", 5)
        with self.assertRaises(SeqOrderError):
            res.add("b", "1.0", 5)
        with self.assertRaises(SeqOrderError):
            res.add("b", "1.0", True)
        res.require("a", "==1.0", 6)


class TestSolving(unittest.TestCase):
    def _basic(self):
        res = _resolver()
        res.add("web", "1.0", 0, deps=(("db", ">=1.0,<2.0"),))
        res.add("web", "2.0", 1, deps=(("db", ">=2.0"),))
        res.add("db", "1.5", 2)
        res.add("db", "2.1", 3)
        return res

    def test_solve_newest_first(self):
        res = self._basic()
        res.require("web", ">=1.0", 4)
        sol = res.solve(5)
        self.assertIsInstance(sol, SolutionRecord)
        self.assertEqual(sol.version_of("web"), "2.0")
        self.assertEqual(sol.version_of("db"), "2.1")
        self.assertTrue(sol.verify())

    def test_solve_determinism(self):
        def run():
            res = self._basic()
            res.require("web", ">=1.0", 4)
            return res.solve(5).digest

        self.assertEqual(run(), run())

    def test_solve_respects_root_constraint(self):
        res = self._basic()
        res.require("web", "==1.0", 4)
        sol = res.solve(5)
        self.assertEqual(sol.version_of("web"), "1.0")
        self.assertEqual(sol.version_of("db"), "1.5")

    def test_solve_conflicts(self):
        res = _resolver()
        res.add("a", "1.0", 0, conflicts=("b",))
        res.add("b", "1.0", 1)
        res.require("a", "==1.0", 2)
        res.require("b", "==1.0", 3)
        with self.assertRaises(UnsatisfiableError):
            res.solve(4)
        # dropping either root restores solvability
        sol = DependencyResolver()
        sol.add("a", "1.0", 0, conflicts=("b",))
        sol.add("b", "1.0", 1)
        sol.require("a", "==1.0", 2)
        got = sol.solve(3)
        self.assertEqual(got.version_of("a"), "1.0")

    def test_solve_unknown_package(self):
        res = _resolver()
        res.require("ghost", ">=1.0", 0)
        with self.assertRaises(UnsatisfiableError):
            res.solve(1)

    def test_solve_dead_dep(self):
        res = _resolver()
        res.add("a", "1.0", 0, deps=(("b", ">=9.0"),))
        res.add("b", "1.0", 1)
        res.require("a", "==1.0", 2)
        with self.assertRaises(UnsatisfiableError):
            res.solve(3)

    def test_solve_transitive_satisfies_root(self):
        res = _resolver()
        res.add("a", "1.0", 0, deps=(("b", "==1.0"),))
        res.add("b", "1.0", 1)
        res.add("b", "2.0", 2)
        res.require("a", "==1.0", 3)
        res.require("b", "<2.0", 4)
        sol = res.solve(5)
        self.assertEqual(sol.version_of("b"), "1.0")


class TestConflicts(unittest.TestCase):
    def test_no_conflict(self):
        res = _resolver()
        res.add("a", "1.0", 0)
        res.require("a", "==1.0", 1)
        rep = res.conflicts(2)
        self.assertIsInstance(rep, ConflictReport)
        self.assertFalse(rep.conflicting)
        self.assertEqual(rep.blamed_req_ids, ())
        self.assertFalse(rep.unresolvable)

    def test_blame(self):
        res = _resolver()
        res.add("a", "1.0", 0, deps=(("b", ">=2.0"),))
        res.add("b", "1.0", 1)
        res.require("a", "==1.0", 2)
        rep = res.conflicts(3)
        self.assertTrue(rep.conflicting)
        self.assertEqual(rep.blamed_req_ids, ("req-1",))
        self.assertFalse(rep.unresolvable)

    def test_conflicting_roots(self):
        res = _resolver()
        res.add("a", "1.0", 0)
        res.add("a", "2.0", 1)
        res.require("a", "==1.0", 2)
        res.require("a", "==2.0", 3)
        rep = res.conflicts(4)
        self.assertTrue(rep.conflicting)
        self.assertEqual(set(rep.blamed_req_ids), {"req-1", "req-2"})


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        res = _resolver()
        res.add("a", "1.0", 0)
        res.require("a", ">=1.0", 1)
        res.solve(2)
        res.conflicts(3)
        kinds = [e["event"] for e in res.audit_log()]
        self.assertEqual(kinds, ["package-added", "required", "solved", "conflict-reported"])
        for event in res.audit_log():
            self.assertEqual(event["schema"], "audit.ndjson/1")

    def test_audit_bad_kind(self):
        with self.assertRaises(DependencyResolverError):
            dependency_resolver_audit_event("nope", 0)

    def test_stdlib_only(self):
        src = (Path(__file__).parent.parent / "dependency_resolver.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "__future__", "hashlib", "json", "threading", "dataclasses", "typing",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed, alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)

    def test_main(self):
        main()

    def test_views(self):
        res = _resolver()
        res.add("a", "1.0", 0)
        res.require("a", "==1.0", 1)
        self.assertEqual(res.package_ids(), ("a",))
        reqs = res.requirements()
        self.assertEqual(len(reqs), 1)
        self.assertIsInstance(reqs[0], RequirementRecord)


if __name__ == "__main__":
    unittest.main()
