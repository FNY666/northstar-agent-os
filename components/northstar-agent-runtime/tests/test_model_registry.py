"""Tests for model_registry.py."""

import unittest

from model_registry import (
    STAGE_ARCHIVED,
    STAGE_PRODUCTION,
    STAGE_STAGING,
    MODEL_REGISTRY_SCHEMA,
    MODEL_REGISTRY_VERSION,
    ModelRegistry,
    ModelRegistryError,
    StageTransitionError,
    UnknownModelError,
    VersionConflictError,
    model_registry_audit_event,
)


def _artifact(tag="ab"):
    return {"digest": "sha256:" + tag * 32, "uri": f"s3://models/m/{tag}"}


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MODEL_REGISTRY_VERSION, "model-registry.v1")

    def test_schema_pin(self):
        self.assertEqual(MODEL_REGISTRY_SCHEMA, "northstar.model-registry.v1")


class TestRegistration(unittest.TestCase):
    def setUp(self):
        self.reg = ModelRegistry()

    def test_register_first_version_is_one(self):
        v = self.reg.register("m", _artifact(), seq=0)
        self.assertEqual(v.version, 1)

    def test_register_auto_increments(self):
        self.reg.register("m", _artifact("ab"), seq=0)
        v = self.reg.register("m", _artifact("cd"), seq=1)
        self.assertEqual(v.version, 2)

    def test_register_explicit_version(self):
        v = self.reg.register("m", _artifact(), version=5, seq=0)
        self.assertEqual(v.version, 5)

    def test_register_explicit_version_not_newer_fails(self):
        self.reg.register("m", _artifact(), version=5, seq=0)
        with self.assertRaises(VersionConflictError):
            self.reg.register("m", _artifact("cd"), version=5, seq=1)
        with self.assertRaises(VersionConflictError):
            self.reg.register("m", _artifact("cd"), version=3, seq=1)

    def test_register_bad_name_rejected(self):
        for bad in ("", 1, True, None):
            with self.assertRaises(ModelRegistryError):
                self.reg.register(bad, _artifact(), seq=0)

    def test_register_bad_artifact_rejected(self):
        with self.assertRaises(ModelRegistryError):
            self.reg.register("m", {"digest": "md5:xyz", "uri": "u"}, seq=0)
        with self.assertRaises(ModelRegistryError):
            self.reg.register("m", {"digest": "sha256:" + "a" * 64}, seq=0)
        with self.assertRaises(ModelRegistryError):
            self.reg.register("m", "not-a-mapping", seq=0)

    def test_register_bad_metadata_rejected(self):
        with self.assertRaises(ModelRegistryError):
            self.reg.register("m", _artifact(), metadata={"k": 1}, seq=0)

    def test_register_bad_seq_rejected(self):
        with self.assertRaises(ModelRegistryError):
            self.reg.register("m", _artifact(), seq=-1)
        with self.assertRaises(ModelRegistryError):
            self.reg.register("m", _artifact(), seq=True)

    def test_metadata_sorted_and_pinned(self):
        v = self.reg.register(
            "m", _artifact(), metadata={"b": "2", "a": "1"}, seq=0
        )
        self.assertEqual(v.metadata, (("a", "1"), ("b", "2")))

    def test_get_latest(self):
        self.reg.register("m", _artifact("ab"), seq=0)
        self.reg.register("m", _artifact("cd"), seq=1)
        self.assertEqual(self.reg.get("m").version, 2)
        self.assertEqual(self.reg.get("m", 1).version, 1)

    def test_get_unknown_model_raises(self):
        with self.assertRaises(UnknownModelError):
            self.reg.get("nope")

    def test_get_unknown_version_raises(self):
        self.reg.register("m", _artifact(), seq=0)
        with self.assertRaises(UnknownModelError):
            self.reg.get("m", 99)

    def test_list_versions_and_models(self):
        self.reg.register("b", _artifact("ab"), seq=0)
        self.reg.register("a", _artifact("ab"), seq=0)
        self.reg.register("a", _artifact("cd"), seq=1)
        self.assertEqual(self.reg.models(), ("a", "b"))
        self.assertEqual(
            [v.version for v in self.reg.list_versions("a")], [1, 2]
        )


class TestStages(unittest.TestCase):
    def setUp(self):
        self.reg = ModelRegistry()
        self.reg.register("m", _artifact("ab"), seq=0)
        self.reg.register("m", _artifact("cd"), seq=1)

    def test_initial_stage_is_none(self):
        self.assertIsNone(self.reg.stage("m", 1))

    def test_promote_to_production(self):
        t = self.reg.promote("m", 1, STAGE_PRODUCTION, seq=2)
        self.assertEqual(t.to_stage, STAGE_PRODUCTION)
        self.assertIsNone(t.from_stage)
        self.assertEqual(self.reg.production("m").version, 1)

    def test_production_exclusive_demotes_old(self):
        self.reg.promote("m", 1, STAGE_PRODUCTION, seq=2)
        self.reg.promote("m", 2, STAGE_PRODUCTION, seq=3)
        self.assertEqual(self.reg.production("m").version, 2)
        self.assertEqual(self.reg.stage("m", 1), STAGE_STAGING)

    def test_archived_cannot_go_directly_to_production(self):
        self.reg.promote("m", 1, STAGE_ARCHIVED, seq=2)
        with self.assertRaises(StageTransitionError):
            self.reg.promote("m", 1, STAGE_PRODUCTION, seq=3)

    def test_archived_can_return_to_staging(self):
        self.reg.promote("m", 1, STAGE_ARCHIVED, seq=2)
        self.reg.promote("m", 1, STAGE_STAGING, seq=3)
        self.assertEqual(self.reg.stage("m", 1), STAGE_STAGING)

    def test_promote_unknown_version_raises(self):
        with self.assertRaises(UnknownModelError):
            self.reg.promote("m", 99, STAGE_PRODUCTION, seq=2)

    def test_promote_bad_stage_raises(self):
        with self.assertRaises(ModelRegistryError):
            self.reg.promote("m", 1, "Prod", seq=2)

    def test_transitions_append_only(self):
        self.reg.promote("m", 1, STAGE_STAGING, seq=2)
        self.reg.promote("m", 1, STAGE_PRODUCTION, seq=3)
        ts = self.reg.transitions()
        self.assertEqual(len(ts), 2)
        self.assertEqual(ts[0].to_stage, STAGE_STAGING)
        self.assertEqual(ts[1].from_stage, STAGE_STAGING)

    def test_production_none_when_unstaged(self):
        self.assertIsNone(self.reg.production("m"))


class TestLineage(unittest.TestCase):
    def setUp(self):
        self.reg = ModelRegistry()
        self.reg.register(
            "m",
            _artifact(),
            lineage={
                "run_id": "run-1",
                "data_sources": ["s3://data/x", "s3://data/y"],
                "parent": {"name": "base", "version": 3},
            },
            seq=0,
        )

    def test_lineage_roundtrip(self):
        lin = self.reg.lineage("m", 1)
        self.assertEqual(lin.run_id, "run-1")
        self.assertEqual(lin.data_sources, ("s3://data/x", "s3://data/y"))
        self.assertEqual(lin.parent_name, "base")
        self.assertEqual(lin.parent_version, 3)
        self.assertTrue(lin.lineage_digest.startswith("sha256:"))

    def test_lineage_digest_deterministic(self):
        a = self.reg.lineage("m", 1)
        reg2 = ModelRegistry()
        reg2.register(
            "m",
            _artifact(),
            lineage={
                "run_id": "run-1",
                "data_sources": ["s3://data/x", "s3://data/y"],
                "parent": {"name": "base", "version": 3},
            },
            seq=0,
        )
        b = reg2.lineage("m", 1)
        self.assertEqual(a.lineage_digest, b.lineage_digest)

    def test_lineage_digest_sensitive_to_source(self):
        reg2 = ModelRegistry()
        reg2.register(
            "m",
            _artifact(),
            lineage={"run_id": "run-1", "data_sources": ["s3://data/z"]},
            seq=0,
        )
        self.assertNotEqual(
            self.reg.lineage("m", 1).lineage_digest,
            reg2.lineage("m", 1).lineage_digest,
        )

    def test_lineage_missing_raises(self):
        self.reg.register("n", _artifact("cd"), seq=1)
        with self.assertRaises(UnknownModelError):
            self.reg.lineage("n", 1)

    def test_lineage_no_parent_ok(self):
        self.reg.register(
            "p", _artifact("ef"),
            lineage={"run_id": "r", "data_sources": []}, seq=2,
        )
        lin = self.reg.lineage("p", 1)
        self.assertIsNone(lin.parent_name)
        self.assertIsNone(lin.parent_version)


class TestAuditEvents(unittest.TestCase):
    def test_registered_shape(self):
        ev = model_registry_audit_event(
            "registered", 4, name="m", version=1
        )
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "model-registry.registered")
        self.assertEqual(ev["seq"], 4)
        self.assertEqual(ev["name"], "m")

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            model_registry_audit_event("nope", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ModelRegistryError):
            model_registry_audit_event("registered", -1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import model_registry as m

        m.main()


if __name__ == "__main__":
    unittest.main()
