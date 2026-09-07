"""Bounded artifact manifest contract tests."""
from __future__ import annotations

import unittest

import support  # noqa: F401
from artifacts import Artifact, ArtifactError, ArtifactManifest


class ArtifactManifestTests(unittest.TestCase):
    def manifest(self, **changes):
        value = {
            "schema_version": "northstar.artifact-manifest.v1",
            "artifacts": [
                {
                    "artifact_id": "report-1",
                    "kind": "uri",
                    "locator": "s3://example-bucket/report.json",
                    "digest": "sha256:" + "a" * 64,
                    "bytes": 42,
                    "media_type": "application/json",
                }
            ],
        }
        value.update(changes)
        return value

    def test_manifest_round_trips_canonically_and_digests(self):
        manifest = ArtifactManifest.from_mapping(self.manifest())
        self.assertEqual(manifest.to_dict(), self.manifest())
        self.assertEqual(
            manifest.canonical_json(),
            ArtifactManifest.from_mapping(
                {"artifacts": list(reversed(self.manifest()["artifacts"])), "schema_version": manifest.schema_version}
            ).canonical_json(),
        )
        self.assertTrue(manifest.digest().startswith("sha256:"))
        self.assertEqual(manifest.artifacts[0], Artifact.from_mapping(self.manifest()["artifacts"][0]))

    def test_workspace_locators_are_relative_and_entries_are_bounded(self):
        for locator in ("/absolute.txt", "../escape.txt", "a//b.txt", "a\\b.txt"):
            with self.subTest(locator=locator):
                with self.assertRaises(ArtifactError):
                    ArtifactManifest.from_mapping(
                        self.manifest(
                            artifacts=[
                                {
                                    **self.manifest()["artifacts"][0],
                                    "kind": "file",
                                    "locator": locator,
                                }
                            ]
                        )
                    )
        duplicate = self.manifest(
            artifacts=[self.manifest()["artifacts"][0], self.manifest()["artifacts"][0]]
        )
        with self.assertRaises(ArtifactError):
            ArtifactManifest.from_mapping(duplicate)

    def test_unknown_fields_invalid_digest_and_oversized_manifest_fail_closed(self):
        with self.assertRaises(ArtifactError):
            ArtifactManifest.from_mapping({**self.manifest(), "extra": True})
        with self.assertRaises(ArtifactError):
            ArtifactManifest.from_mapping(
                self.manifest(
                    artifacts=[
                        {**self.manifest()["artifacts"][0], "digest": "sha256:" + "A" * 64}
                    ]
                )
            )
        too_many = [
            {
                **self.manifest()["artifacts"][0],
                "artifact_id": f"artifact-{index}",
            }
            for index in range(65)
        ]
        with self.assertRaises(ArtifactError):
            ArtifactManifest.from_mapping(self.manifest(artifacts=too_many))


if __name__ == "__main__":
    unittest.main()
