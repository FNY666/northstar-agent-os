"""Targeted tests for artifact_publisher (PyPI-style publish ledger, simulated)."""

import ast
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from artifact_publisher import (
    ARTIFACT_PUBLISHER_VERSION,
    SCHEMA_PIN,
    AlreadyPublishedError,
    ArtifactPublisher,
    ArtifactPublisherError,
    DuplicateBuildError,
    DuplicateDistributionError,
    SeqOrderError,
    TerminalYankError,
    UnknownBuildError,
    UnknownDistributionError,
    ValidationError,
    artifact_publisher_audit_event,
    main as mod_main,
)


def fresh():
    return ArtifactPublisher()


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(ARTIFACT_PUBLISHER_VERSION, "artifact-publisher.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.artifact-publisher.v1")


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        p = fresh()
        d = p.register("d1", "Northstar_Agent", "0.3.dev0", 0)
        self.assertEqual(d.dist_id, "d1")
        self.assertEqual(d.normalized_name, "northstar-agent")
        self.assertEqual(d.dist_version, "0.3.dev0")
        self.assertTrue(d.verify())
        self.assertEqual(d, p.get_distribution("d1"))

    def test_duplicate_id(self):
        p = fresh()
        p.register("d1", "a", "1.0", 0)
        with self.assertRaises(DuplicateDistributionError):
            p.register("d1", "b", "2.0", 1)

    def test_duplicate_name_version(self):
        p = fresh()
        p.register("d1", "a", "1.0", 0)
        # different id, same normalized (name, version)
        with self.assertRaises(DuplicateDistributionError):
            p.register("d2", "A", "1.0", 1)

    def test_bad_name(self):
        p = fresh()
        seq = 0
        for bad in ("", "-a", "a b", "a!", None, 7):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                p.register(f"d-{seq}", bad, "1.0", seq)
            seq += 1

    def test_bad_version(self):
        p = fresh()
        seq = 0
        for bad in ("", "abc", "1.0+", "01.2", None):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                p.register(f"dv-{seq}", "a", bad, seq)
            seq += 1

    def test_seq_rewind_and_bool(self):
        p = fresh()
        p.register("d1", "a", "1.0", 0)
        with self.assertRaises(SeqOrderError):
            p.register("d2", "b", "1.0", 0)  # rewind
        with self.assertRaises(SeqOrderError):
            p.register("d2", "b", "1.0", True)  # bool

    def test_unknown_distribution(self):
        p = fresh()
        with self.assertRaises(UnknownDistributionError):
            p.get_distribution("nope")


class TestBuild(unittest.TestCase):
    def test_sdist_and_wheel(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b1 = p.build("d1", 1)
        self.assertEqual(b1.build_id, "bld-1")
        self.assertEqual(b1.filename, "pkg-1.0.tar.gz")
        self.assertTrue(b1.verify())
        b2 = p.build("d1", 2, build_type="wheel")
        self.assertEqual(b2.filename, "pkg-1.0-py3-none-any.whl")
        self.assertTrue(b2.verify())

    def test_duplicate_build_type(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        p.build("d1", 1)
        with self.assertRaises(DuplicateBuildError):
            p.build("d1", 2)

    def test_unknown_dist_and_bad_type(self):
        p = fresh()
        with self.assertRaises(UnknownDistributionError):
            p.build("nope", 0)
        p.register("d1", "pkg", "1.0", 1)
        with self.assertRaises(ValidationError):
            p.build("d1", 2, build_type="egg")

    def test_builds_of_sorted(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b1 = p.build("d1", 1)
        b2 = p.build("d1", 2, build_type="wheel")
        builds = p.builds_of("d1")
        self.assertEqual([b.build_id for b in builds], [b1.build_id, b2.build_id])


class TestUpload(unittest.TestCase):
    def test_upload_happy(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b = p.build("d1", 1)
        u = p.upload(b.build_id, 2)
        self.assertEqual(u.upload_id, "upl-1")
        self.assertEqual(u.build_digest, b.digest)
        self.assertTrue(u.verify())
        self.assertEqual(p.status(b.build_id), "uploaded")
        self.assertEqual(p.upload_record(b.build_id), u)

    def test_reupload_refused(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b = p.build("d1", 1)
        p.upload(b.build_id, 2)
        with self.assertRaises(AlreadyPublishedError):
            p.upload(b.build_id, 3)

    def test_upload_unknown_build(self):
        p = fresh()
        with self.assertRaises(UnknownBuildError):
            p.upload("bld-9", 0)

    def test_failing_uploader(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b = p.build("d1", 1)
        p2 = ArtifactPublisher(uploader=lambda _b: False)
        with self.assertRaises(ArtifactPublisherError):
            p2.upload(b.build_id, 0)  # unknown in p2 anyway
        p3 = ArtifactPublisher(uploader=lambda _b: False)
        p3.register("d1", "pkg", "1.0", 0)
        b3 = p3.build("d1", 1)
        with self.assertRaises(ArtifactPublisherError):
            p3.upload(b3.build_id, 2)


class TestYank(unittest.TestCase):
    def test_yank_terminal(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b = p.build("d1", 1)
        p.upload(b.build_id, 2)
        y = p.yank(b.build_id, "CVE-2026-0001", 3)
        self.assertEqual(y.reason, "CVE-2026-0001")
        self.assertEqual(p.status(b.build_id), "yanked")
        with self.assertRaises(TerminalYankError):
            p.yank(b.build_id, "again", 4)
        with self.assertRaises(TerminalYankError):
            p.upload(b.build_id, 5)  # yanked build cannot upload

    def test_yank_unbuilt_unknown_and_bad_reason(self):
        p = fresh()
        with self.assertRaises(UnknownBuildError):
            p.yank("bld-9", "x", 0)
        p.register("d1", "pkg", "1.0", 1)
        b = p.build("d1", 2)
        with self.assertRaises(ValidationError):
            p.yank(b.build_id, "  ", 3)
        self.assertEqual(p.status(b.build_id), "built")

    def test_stats(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        b = p.build("d1", 1)
        self.assertEqual(p.stats(),
                         {"distributions": 1, "builds": 1, "uploaded": 0, "yanked": 0})
        p.upload(b.build_id, 2)
        self.assertEqual(p.stats()["uploaded"], 1)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        ev = artifact_publisher_audit_event("built", 1, build_id="bld-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "built")
        self.assertEqual(ev["module_version"], ARTIFACT_PUBLISHER_VERSION)
        self.assertEqual(ev["module_schema"], SCHEMA_PIN)
        self.assertEqual(ev["audit_seq"], 1)
        self.assertEqual(ev["build_id"], "bld-1")

    def test_unknown_kind(self):
        with self.assertRaises(ArtifactPublisherError):
            artifact_publisher_audit_event("nope", 0)

    def test_log_accumulates(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        p.build("d1", 1)
        kinds = [e["event"] for e in p.audit_log()]
        self.assertEqual(kinds, ["distribution-registered", "built"])


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_imports_only(self):
        tree = ast.parse(Path(artifact_publisher.__file__).read_text())
        allowed = {"__future__", "hashlib", "math", "re", "threading",
                   "dataclasses", "typing", "json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                root = node.module.split(".")[0]
                # canonical_json is the guarded fallback import, allowed
                self.assertIn(root, allowed | {"canonical_json"})


class TestConcurrency(unittest.TestCase):
    def test_thread_safe_seq(self):
        p = fresh()
        p.register("d1", "pkg", "1.0", 0)
        seq_lock = threading.Lock()
        seq = [1]
        ok = []

        def work():
            with seq_lock:
                s = seq[0]
                seq[0] += 1
            try:
                p.build("d1", s, build_type="sdist" if s % 2 else "wheel")
            except ArtifactPublisherError:
                pass  # duplicate build type loses the race; still safe

        threads = [threading.Thread(target=work) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertLessEqual(len(p.builds_of("d1")), 2)


class TestMain(unittest.TestCase):
    def test_main(self):
        mod_main()


import artifact_publisher  # noqa: E402


if __name__ == "__main__":
    unittest.main()
