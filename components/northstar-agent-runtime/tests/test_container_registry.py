"""Tests for container_registry: OCI-shaped image bookkeeping."""

import ast
import subprocess
import unittest
from pathlib import Path

from container_registry import (
    CONTAINER_REGISTRY_SCHEMA,
    CONTAINER_REGISTRY_VERSION,
    BlobRecord,
    ContainerRegistry,
    ContainerRegistryError,
    DanglingTagError,
    DigestMismatchError,
    DuplicateBlobError,
    ManifestRecord,
    PullResult,
    TagMove,
    UnknownReferenceError,
    UnknownRepositoryError,
    container_registry_audit_event,
)


D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
D3 = "sha256:" + "c" * 64
D4 = "sha256:" + "d" * 64
MT = "application/vnd.oci.image.manifest.v1+json"


def _registry_with_image() -> ContainerRegistry:
    reg = ContainerRegistry()
    reg.push_blob(D1, 512, "config", 0)
    reg.push_blob(D2, 1024, "layer", 1)
    manifest = reg.push("library/app", MT, D1, (D2,), 2)
    reg.tag("library/app", "latest", manifest.digest, 3)
    return reg


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CONTAINER_REGISTRY_VERSION, "container-registry.v1")

    def test_schema_pin(self):
        self.assertEqual(
            CONTAINER_REGISTRY_SCHEMA, "northstar.container-registry.v1"
        )


class TestBlobs(unittest.TestCase):
    def test_push_blob_roundtrip(self):
        reg = ContainerRegistry()
        record = reg.push_blob(D1, 100, "layer", 0)
        self.assertEqual(record.digest, D1)
        self.assertEqual(record.size_bytes, 100)
        self.assertEqual(reg.blob(D1), record)

    def test_push_blob_idempotent(self):
        reg = ContainerRegistry()
        a = reg.push_blob(D1, 100, "layer", 0)
        b = reg.push_blob(D1, 100, "layer", 1)
        self.assertEqual(a, b)

    def test_push_blob_conflict(self):
        reg = ContainerRegistry()
        reg.push_blob(D1, 100, "layer", 0)
        with self.assertRaises(DuplicateBlobError):
            reg.push_blob(D1, 200, "layer", 1)

    def test_push_blob_bad_inputs(self):
        reg = ContainerRegistry()
        with self.assertRaises(ContainerRegistryError):
            reg.push_blob("not-a-digest", 1, "layer", 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push_blob(D1, -1, "layer", 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push_blob(D1, True, "layer", 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push_blob(D1, 1, "", 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push_blob(D1, 1, "layer", -1)


class TestManifests(unittest.TestCase):
    def test_push_computes_digest(self):
        reg = ContainerRegistry()
        manifest = reg.push("library/app", MT, D1, (D2, D3), 0)
        expected = ContainerRegistry.manifest_digest(MT, D1, (D2, D3))
        self.assertEqual(manifest.digest, expected)

    def test_push_idempotent(self):
        reg = ContainerRegistry()
        a = reg.push("library/app", MT, D1, (D2,), 0)
        b = reg.push("library/app", MT, D1, (D2,), 5)
        self.assertEqual(a.digest, b.digest)

    def test_push_bad_inputs(self):
        reg = ContainerRegistry()
        with self.assertRaises(ContainerRegistryError):
            reg.push("LIBRARY/APP", MT, D1, (D2,), 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push("library/app", MT, "bad", (D2,), 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push("library/app", MT, D1, ("bad",), 0)
        with self.assertRaises(ContainerRegistryError):
            reg.push("library/app", MT, D1, (D2,), True)

    def test_manifests_view(self):
        reg = _registry_with_image()
        records = reg.manifests("library/app")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].repository, "library/app")
        self.assertEqual(reg.manifests("library/other"), ())


class TestTags(unittest.TestCase):
    def test_tag_and_pull_by_tag(self):
        reg = _registry_with_image()
        result = reg.pull("library/app", "latest", 10)
        self.assertEqual(result.resolved_via, "tag")
        self.assertIsInstance(result, PullResult)

    def test_pull_by_digest(self):
        reg = _registry_with_image()
        manifest = reg.manifests("library/app")[0]
        result = reg.pull("library/app", manifest.digest, 10)
        self.assertEqual(result.resolved_via, "digest")
        self.assertEqual(result.digest, manifest.digest)

    def test_retag_records_move(self):
        reg = _registry_with_image()
        m1 = reg.manifests("library/app")[0]
        m2 = reg.push("library/app", MT, D1, (D3,), 10)
        move = reg.tag("library/app", "latest", m2.digest, 11)
        self.assertEqual(move.old_digest, m1.digest)
        self.assertEqual(move.new_digest, m2.digest)
        self.assertEqual(reg.tag_history()[-1], move)

    def test_tag_unknown_digest_refused(self):
        reg = ContainerRegistry()
        reg.push("library/app", MT, D1, (D2,), 0)
        with self.assertRaises(UnknownReferenceError):
            reg.tag("library/app", "latest", D3, 1)

    def test_tag_bad_tag_shape(self):
        reg = ContainerRegistry()
        with self.assertRaises(ContainerRegistryError):
            reg.tag("library/app", "bad tag!", D1, 0)

    def test_untag(self):
        reg = _registry_with_image()
        move = reg.untag("library/app", "latest", 10)
        self.assertEqual(move.new_digest, None)
        self.assertEqual(reg.tags("library/app"), ())
        with self.assertRaises(UnknownReferenceError):
            reg.pull("library/app", "latest", 11)

    def test_untag_unknown(self):
        reg = ContainerRegistry()
        with self.assertRaises(UnknownReferenceError):
            reg.untag("library/app", "nope", 0)

    def test_pull_unknown_reference(self):
        reg = _registry_with_image()
        with self.assertRaises(UnknownReferenceError):
            reg.pull("library/app", "nope", 0)
        with self.assertRaises(UnknownReferenceError):
            reg.pull("library/app", D4, 0)

    def test_tags_view_sorted(self):
        reg = _registry_with_image()
        manifest = reg.manifests("library/app")[0]
        reg.tag("library/app", "v1", manifest.digest, 10)
        self.assertEqual(reg.tags("library/app"), ("latest", "v1"))


class TestGarbageViews(unittest.TestCase):
    def test_unreferenced_blobs(self):
        reg = ContainerRegistry()
        reg.push_blob(D1, 1, "config", 0)
        reg.push_blob(D4, 1, "orphan", 1)
        reg.push("library/app", MT, D1, (), 2)
        orphans = reg.unreferenced_blobs()
        self.assertEqual([b.digest for b in orphans], [D4])

    def test_unreferenced_manifests(self):
        reg = _registry_with_image()
        manifest = reg.manifests("library/app")[0]
        reg.untag("library/app", "latest", 10)
        orphans = reg.unreferenced_manifests()
        self.assertEqual([m.digest for m in orphans], [manifest.digest])


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in (
            "blob-pushed",
            "manifest-pushed",
            "tagged",
            "untagged",
            "pulled",
            "rejected",
        ):
            event = container_registry_audit_event(
                kind, 0, repository="library/app"
            )
            self.assertEqual(event["schema"], CONTAINER_REGISTRY_SCHEMA)
            self.assertEqual(event["version"], CONTAINER_REGISTRY_VERSION)
            self.assertEqual(event["kind"], kind)

    def test_audit_bad_kind(self):
        with self.assertRaises(ContainerRegistryError):
            container_registry_audit_event("nope", 0)

    def test_audit_bad_seq(self):
        with self.assertRaises(ContainerRegistryError):
            container_registry_audit_event("pulled", -1)


class TestFrozenAndStats(unittest.TestCase):
    def test_records_frozen(self):
        reg = _registry_with_image()
        record = reg.manifests("library/app")[0]
        with self.assertRaises(Exception):
            record.digest = D4  # type: ignore[misc]

    def test_stats(self):
        reg = _registry_with_image()
        stats = reg.stats()
        self.assertEqual(stats["blobs"], 2)
        self.assertEqual(stats["manifests"], 1)
        self.assertEqual(stats["tags"], 1)
        self.assertEqual(stats["tag_moves"], 1)


class TestMain(unittest.TestCase):
    def test_main(self):
        completed = subprocess.run(
            ["python3", "container_registry.py"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("container-registry OK", completed.stdout)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        path = Path(__file__).resolve().parent.parent / "container_registry.py"
        tree = ast.parse(path.read_text())
        allowed = {
            "__future__",
            "hashlib",
            "json",
            "re",
            "threading",
            "dataclasses",
            "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
