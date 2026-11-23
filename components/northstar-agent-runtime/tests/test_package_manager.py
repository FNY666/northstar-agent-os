"""Tests for package_manager.py (npm-style install/resolve/lock)."""

import ast
import importlib.util
import unittest
from pathlib import Path

import package_manager
from package_manager import (
    PackageManager,
    PackageManagerError,
    UnknownPackageError,
    DuplicatePackageError,
    BadVersionError,
    BadRangeError,
    NoSatisfyingVersionError,
    VersionConflictError,
    DependencyCycleError,
    AlreadyInstalledError,
    RequiredByError,
    VERSION,
    SCHEMA,
    RANGE_KINDS,
    package_manager_audit_event,
)


def _pm():
    return PackageManager()


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "package-manager.v1")
        self.assertEqual(SCHEMA, "northstar.package-manager.v1")
        self.assertEqual(RANGE_KINDS, ("exact", "caret", "tilde", "star"))

    def test_stdlib_only(self):
        tree = ast.parse(Path(package_manager.__file__).read_text())
        allowed = {"__future__", "hashlib", "json", "re", "threading",
                   "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        pm = _pm()
        rec = pm.register("leftpad", "1.2.3", 0)
        self.assertTrue(rec.package_id.startswith("pkg-"))
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version_tuple, (1, 2, 3))

    def test_duplicate_refused(self):
        pm = _pm()
        pm.register("a", "1.0.0", 0)
        with self.assertRaises(DuplicatePackageError):
            pm.register("a", "1.0.0", 1)

    def test_bad_versions(self):
        pm = _pm()
        for bad in ["1.0", "v1.0.0", "1.0.0.0", "", 1.5, None]:
            with self.assertRaises((BadVersionError, PackageManagerError)):
                pm.register("a", bad, 0)

    def test_bad_names(self):
        pm = _pm()
        for bad in ["", "UPPER", "has space", "-dash"]:
            with self.assertRaises(PackageManagerError):
                pm.register(bad, "1.0.0", 0)

    def test_bad_range(self):
        pm = _pm()
        # ">=1.0.0" is not one of the pinned range shapes: it fails as a bad
        # exact version (still a fail-closed PackageManagerError).
        with self.assertRaises(PackageManagerError):
            pm.register("a", "1.0.0", 0, dependencies=[("b", ">=1.0.0")])
        with self.assertRaises(PackageManagerError):
            pm.register("a", "1.0.0", 1, dependencies=[("b", 123)])

    def test_self_dep_refused(self):
        pm = _pm()
        with self.assertRaises(PackageManagerError):
            pm.register("a", "1.0.0", 0, dependencies=[("a", "*")])

    def test_seq_monotonic(self):
        pm = _pm()
        pm.register("a", "1.0.0", 0)
        with self.assertRaises(PackageManagerError):
            pm.register("b", "1.0.0", 0)


class TestResolve(unittest.TestCase):
    def _graph(self, pm, seq=0):
        pm.register("c", "1.0.0", seq)
        pm.register("b", "1.0.0", seq + 1, dependencies=[("c", "^1.0.0")])
        pm.register("a", "1.0.0", seq + 2, dependencies=[("b", "^1.0.0")])
        return seq + 3

    def test_resolve_tree(self):
        pm = _pm()
        s = self._graph(pm)
        rep = pm.resolve("a", "1.0.0", s)
        names = [p.name for p in rep.packages]
        self.assertEqual(names, ["a", "b", "c"])
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_max_satisfying(self):
        pm = _pm()
        pm.register("lib", "1.0.0", 0)
        pm.register("lib", "1.2.0", 1)
        pm.register("lib", "2.0.0", 2)
        pm.register("app", "1.0.0", 3, dependencies=[("lib", "^1.0.0")])
        rep = pm.resolve("app", "1.0.0", 4)
        got = {p.name: p.version for p in rep.packages}
        self.assertEqual(got["lib"], "1.2.0")

    def test_tilde_range(self):
        pm = _pm()
        pm.register("lib", "1.2.3", 0)
        pm.register("lib", "1.3.0", 1)
        pm.register("app", "1.0.0", 2, dependencies=[("lib", "~1.2.0")])
        rep = pm.resolve("app", "1.0.0", 3)
        got = {p.name: p.version for p in rep.packages}
        self.assertEqual(got["lib"], "1.2.3")

    def test_star_range(self):
        pm = _pm()
        pm.register("lib", "9.9.9", 0)
        pm.register("app", "1.0.0", 1, dependencies=[("lib", "*")])
        rep = pm.resolve("app", "1.0.0", 2)
        got = {p.name: p.version for p in rep.packages}
        self.assertEqual(got["lib"], "9.9.9")

    def test_unknown_package(self):
        pm = _pm()
        with self.assertRaises(UnknownPackageError):
            pm.resolve("nope", "*", 0)

    def test_no_satisfying(self):
        pm = _pm()
        pm.register("lib", "1.0.0", 0)
        pm.register("app", "1.0.0", 1, dependencies=[("lib", "^2.0.0")])
        with self.assertRaises(NoSatisfyingVersionError):
            pm.resolve("app", "1.0.0", 2)

    def test_conflict(self):
        pm = _pm()
        pm.register("lib", "1.0.0", 0)
        pm.register("lib", "1.1.0", 1)
        pm.register("a", "1.0.0", 2, dependencies=[("lib", "^1.0.0")])
        pm.register("b", "1.0.0", 3, dependencies=[("lib", "1.0.0")])
        pm.register("combo", "1.0.0", 4,
                    dependencies=[("a", "1.0.0"), ("b", "1.0.0")])
        with self.assertRaises(VersionConflictError):
            pm.resolve("combo", "1.0.0", 5)

    def test_cycle(self):
        pm = _pm()
        pm.register("a", "1.0.0", 0, dependencies=[("b", "1.0.0")])
        pm.register("b", "1.0.0", 1, dependencies=[("a", "1.0.0")])
        with self.assertRaises(DependencyCycleError):
            pm.resolve("a", "1.0.0", 2)


class TestInstallLock(unittest.TestCase):
    def test_install_order(self):
        pm = _pm()
        pm.register("leaf", "1.0.0", 0)
        pm.register("mid", "1.0.0", 1, dependencies=[("leaf", "^1.0.0")])
        pm.register("root", "1.0.0", 2, dependencies=[("mid", "^1.0.0")])
        receipt = pm.install("root", "1.0.0", 3)
        self.assertEqual([p.name for p in receipt.packages],
                         ["leaf", "mid", "root"])

    def test_double_install_refused(self):
        pm = _pm()
        pm.register("a", "1.0.0", 0)
        pm.install("a", "1.0.0", 1)
        with self.assertRaises(AlreadyInstalledError):
            pm.install("a", "*", 2)

    def test_uninstall(self):
        pm = _pm()
        pm.register("a", "1.0.0", 0)
        pm.install("a", "1.0.0", 1)
        pm.uninstall("a", 2)
        self.assertEqual(pm.installed_roots(), ())

    def test_uninstall_required_refused(self):
        pm = _pm()
        pm.register("leaf", "1.0.0", 0)
        pm.register("top", "1.0.0", 1, dependencies=[("leaf", "^1.0.0")])
        pm.install("leaf", "1.0.0", 2)
        pm.install("top", "1.0.0", 3)
        with self.assertRaises(RequiredByError):
            pm.uninstall("leaf", 4)

    def test_lock_verify(self):
        pm = _pm()
        pm.register("leaf", "1.0.0", 0)
        pm.register("root", "2.0.0", 1, dependencies=[("leaf", "^1.0.0")])
        pm.install("root", "2.0.0", 2)
        lock = pm.lock(3)
        self.assertTrue(lock.verify())
        self.assertEqual([e.name for e in lock.entries], ["leaf", "root"])
        tampered = lock.entries[0]
        bad = type(lock)(lock.lock_id, (tampered,), "sha256:dead", 3)
        self.assertFalse(bad.verify())


class TestAudit(unittest.TestCase):
    def test_shapes_and_rejection(self):
        ev = package_manager_audit_event("installed", 0, install_id="ins-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module_version"], VERSION)
        with self.assertRaises(PackageManagerError):
            package_manager_audit_event("bogus", 0)

    def test_main(self):
        package_manager.main()


if __name__ == "__main__":
    unittest.main()
