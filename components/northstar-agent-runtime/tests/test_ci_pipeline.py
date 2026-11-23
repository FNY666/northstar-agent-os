"""Tests for ci_pipeline: GitHub-Actions-style stage/job bookkeeping."""

import unittest

from ci_pipeline import (
    CI_PIPELINE_VERSION,
    SCHEMA_PIN,
    JOB_SUCCESS,
    JOB_FAILED,
    JOB_SKIPPED,
    ArtifactError,
    CIPipeline,
    CIPipelineError,
    CycleError,
    DefinitionError,
    OutcomeError,
    UnknownJobError,
    ci_pipeline_audit_event,
)


def _jobs():
    return {
        "build": {"runs_on": "ubuntu-latest"},
        "test": {"runs_on": "ubuntu-latest", "needs": ["build"]},
        "deploy": {"runs_on": "ubuntu-latest", "needs": ["test"]},
    }


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CI_PIPELINE_VERSION, "ci-pipeline.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.ci-pipeline.v1")


class TestDefine(unittest.TestCase):
    def test_define_topological_order(self):
        pipe = CIPipeline()
        d = pipe.define("ci", _jobs(), seq=0)
        self.assertEqual(d.order, ("build", "test", "deploy"))
        self.assertTrue(d.digest.startswith("sha256:"))
        self.assertEqual(d.version, CI_PIPELINE_VERSION)

    def test_define_parallel_jobs_sorted(self):
        pipe = CIPipeline()
        d = pipe.define("p", {
            "b": {"runs_on": "x"},
            "a": {"runs_on": "x"},
        }, seq=0)
        self.assertEqual(d.order, ("a", "b"))

    def test_define_cycle_refused(self):
        pipe = CIPipeline()
        with self.assertRaises(CycleError):
            pipe.define("c", {
                "a": {"runs_on": "x", "needs": ["b"]},
                "b": {"runs_on": "x", "needs": ["a"]},
            }, seq=0)

    def test_define_self_dependency_refused(self):
        pipe = CIPipeline()
        with self.assertRaises(DefinitionError):
            pipe.define("s", {"a": {"runs_on": "x", "needs": ["a"]}},
                        seq=0)

    def test_define_unknown_dependency_refused(self):
        pipe = CIPipeline()
        with self.assertRaises(DefinitionError):
            pipe.define("u", {"a": {"runs_on": "x", "needs": ["ghost"]}},
                        seq=0)

    def test_define_duplicate_pipeline_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        with self.assertRaises(DefinitionError):
            pipe.define("ci", _jobs(), seq=1)

    def test_define_bad_inputs(self):
        pipe = CIPipeline()
        with self.assertRaises(CIPipelineError):
            pipe.define("", _jobs(), seq=0)
        with self.assertRaises(DefinitionError):
            pipe.define("e", {}, seq=0)
        with self.assertRaises(CIPipelineError):
            pipe.define("b", _jobs(), seq=True)
        with self.assertRaises(DefinitionError):
            pipe.define("r", {"a": {"runs_on": ""}}, seq=0)

    def test_definition_roundtrip(self):
        pipe = CIPipeline()
        d = pipe.define("ci", _jobs(), seq=0)
        self.assertIs(pipe.definition("ci"), d)
        with self.assertRaises(UnknownJobError):
            pipe.definition("nope")


class TestRun(unittest.TestCase):
    def test_run_all_success(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r = pipe.run("ci", {"build": True, "test": True, "deploy": True},
                     seq=1)
        self.assertEqual(r.overall, JOB_SUCCESS)
        self.assertTrue(r.digest.startswith("sha256:"))
        self.assertEqual([x.job_id for x in r.results],
                         ["build", "test", "deploy"])

    def test_run_skip_rule(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r = pipe.run("ci", {"build": True, "test": False}, seq=1)
        statuses = {x.job_id: x.status for x in r.results}
        self.assertEqual(statuses["build"], JOB_SUCCESS)
        self.assertEqual(statuses["test"], JOB_FAILED)
        self.assertEqual(statuses["deploy"], JOB_SKIPPED)
        self.assertEqual(r.overall, JOB_FAILED)

    def test_run_missing_outcome_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        with self.assertRaises(OutcomeError):
            pipe.run("ci", {"build": True}, seq=1)

    def test_run_unknown_job_outcome_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        with self.assertRaises(OutcomeError):
            pipe.run("ci", {"build": True, "ghost": True}, seq=1)

    def test_run_non_bool_outcome_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        with self.assertRaises(OutcomeError):
            pipe.run("ci", {"build": 1}, seq=1)

    def test_run_unknown_pipeline(self):
        pipe = CIPipeline()
        with self.assertRaises(UnknownJobError):
            pipe.run("nope", {}, seq=0)

    def test_run_ids_monotonic(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r1 = pipe.run("ci", {"build": True, "test": True, "deploy": True},
                      seq=1)
        r2 = pipe.run("ci", {"build": True, "test": True, "deploy": True},
                      seq=2)
        self.assertNotEqual(r1.run_id, r2.run_id)
        self.assertEqual(pipe.runs(), (r1.run_id, r2.run_id))


class TestArtifact(unittest.TestCase):
    def test_artifact_happy_path(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r = pipe.run("ci", {"build": True, "test": True, "deploy": True},
                     seq=1)
        rec = pipe.artifact(r.run_id, "build", "dist.tar.gz",
                            "sha256:" + "ab" * 32, seq=2)
        self.assertEqual(rec.name, "dist.tar.gz")
        self.assertEqual(rec.run_id, r.run_id)
        self.assertEqual(len(pipe.artifacts(r.run_id)), 1)

    def test_artifact_failed_job_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r = pipe.run("ci", {"build": True, "test": False}, seq=1)
        with self.assertRaises(ArtifactError):
            pipe.artifact(r.run_id, "test", "x.zip",
                          "sha256:" + "ab" * 32, seq=2)

    def test_artifact_bad_digest_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r = pipe.run("ci", {"build": True, "test": True, "deploy": True},
                     seq=1)
        with self.assertRaises(ArtifactError):
            pipe.artifact(r.run_id, "build", "x.zip", "md5:deadbeef",
                          seq=2)

    def test_artifact_duplicate_name_refused(self):
        pipe = CIPipeline()
        pipe.define("ci", _jobs(), seq=0)
        r = pipe.run("ci", {"build": True, "test": True, "deploy": True},
                     seq=1)
        pipe.artifact(r.run_id, "build", "x.zip", "sha256:" + "ab" * 32,
                      seq=2)
        with self.assertRaises(ArtifactError):
            pipe.artifact(r.run_id, "test", "x.zip", "sha256:" + "cd" * 32,
                          seq=3)

    def test_artifact_unknown_run_refused(self):
        pipe = CIPipeline()
        with self.assertRaises(ArtifactError):
            pipe.artifact("run-99", "build", "x.zip",
                          "sha256:" + "ab" * 32, seq=0)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("defined", "run-completed", "job-succeeded",
                     "job-failed", "job-skipped", "artifact-attached"):
            rec = ci_pipeline_audit_event(kind, seq=1, pipeline_id="ci",
                                          run_id="run-1")
            self.assertEqual(rec["schema"], "audit.ndjson/1")
            self.assertEqual(rec["event"], kind)

    def test_audit_unknown_kind(self):
        with self.assertRaises(CIPipelineError):
            ci_pipeline_audit_event("bogus", seq=0)

    def test_main(self):
        from ci_pipeline import main
        main()


if __name__ == "__main__":
    unittest.main()
