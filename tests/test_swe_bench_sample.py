"""Contract tests for the frozen SWE-bench Verified sample.

A frozen sample is only worth freezing if it stays frozen: the same
instance ids, the same grading tests, and above all the same container
image digest every time.  These tests hold the sample to that.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "benchmarks" / "swe-bench" / "verified-50.json"
IMAGE_PREFIX = "swebench/sweb.eval.x86_64"


class FrozenSweBenchSampleTests(unittest.TestCase):
    def setUp(self):
        self.sample = json.loads(SAMPLE.read_text(encoding="utf-8"))

    def test_the_sample_holds_the_fifty_tasks_the_blueprint_asks_for(self):
        self.assertEqual(self.sample["schema"], "northstar.swe-bench-sample.v1")
        self.assertEqual(self.sample["task_count"], 50)
        self.assertEqual(len(self.sample["tasks"]), 50)
        self.assertEqual(self.sample["source"], "princeton-nlp/SWE-bench_Verified")

    def test_every_task_pins_its_environment_to_an_image_digest(self):
        for task in self.sample["tasks"]:
            with self.subTest(task=task["instance_id"]):
                self.assertTrue(task["environment_image"].startswith(IMAGE_PREFIX))
                digest = task["environment_digest"]
                self.assertIsNotNone(digest)
                self.assertTrue(digest.startswith("sha256:"))
                self.assertEqual(len(digest.split(":")[1]), 64)

    def test_the_digests_are_the_ones_upstream_publishes(self):
        """A digest that is merely well-formed proves nothing.

        The point of pinning a digest is that it names one exact image.
        The frozen values live beside the sample so that a change has to be
        argued for rather than slipping in.
        """
        lock_path = SAMPLE.with_name("verified-50.digests.json")
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        recorded = {row["instance_id"]: row["environment_digest"] for row in self.sample["tasks"]}
        self.assertEqual(recorded, lock["digests"])
        self.assertEqual(lock["source_url"], self.sample["source_url"])

    def test_the_image_name_follows_the_upstream_convention(self):
        for task in self.sample["tasks"]:
            with self.subTest(task=task["instance_id"]):
                instance = task["instance_id"]
                organisation, _, short = instance.partition("__")
                expected = f"{IMAGE_PREFIX}.{organisation}_1776_{short}:latest"
                self.assertEqual(task["environment_image"], expected)

    def test_no_task_is_repeated_and_every_task_has_grading_tests(self):
        ids = [task["instance_id"] for task in self.sample["tasks"]]
        self.assertEqual(len(set(ids)), len(ids))
        for task in self.sample["tasks"]:
            with self.subTest(task=task["instance_id"]):
                self.assertGreater(len(task["fail_to_pass"]), 0)
                # PASS_TO_PASS is empty for some instances upstream; only
                # FAIL_TO_PASS is required to be present.
                self.assertIsInstance(task["pass_to_pass"], list)
                self.assertEqual(len(task["fail_to_pass_sha256"]), 64)
                # The upstream harness needs the raw test names, not just a
                # fingerprint, so the sample has to carry both.
                self.assertTrue(all(isinstance(t, str) for t in task["fail_to_pass"]))
                self.assertEqual(len(task["problem_statement_sha256"]), 64)
                self.assertEqual(len(task["base_commit"]), 40)

    def test_the_sample_spans_several_repositories(self):
        repos = self.sample["repos"]
        self.assertGreaterEqual(len(repos), 5)
        counts = {repo: 0 for repo in repos}
        for task in self.sample["tasks"]:
            counts[task["repo"]] += 1
        self.assertLessEqual(max(counts.values()), 5)
        self.assertGreaterEqual(min(counts.values()), 1)


if __name__ == "__main__":
    unittest.main()
