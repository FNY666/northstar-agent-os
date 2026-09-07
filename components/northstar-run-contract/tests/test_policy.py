"""The canonical policy-document identity: schema version + revision rules."""
import unittest

from policy import (
    MAX_REVISION_CHARS,
    POLICY_SCHEMA_VERSION,
    SUPPORTED_POLICY_SCHEMA_VERSIONS,
    require_supported_schema,
    validate_revision,
    validate_schema_version,
)


class SchemaVersionTests(unittest.TestCase):
    def test_the_canonical_version_is_northstar_policy_v1(self):
        self.assertEqual(POLICY_SCHEMA_VERSION, "northstar.policy.v1")
        self.assertEqual(SUPPORTED_POLICY_SCHEMA_VERSIONS, ("northstar.policy.v1",))

    def test_supported_version_and_absent_are_valid(self):
        self.assertEqual(validate_schema_version(POLICY_SCHEMA_VERSION), ())
        self.assertEqual(validate_schema_version(None), ())  # absent = the current default

    def test_unknown_and_wrong_typed_versions_are_rejected(self):
        (error,) = validate_schema_version("northstar.policy.v2")
        self.assertIn("unsupported", error)
        self.assertIn("northstar.policy.v2", error)
        self.assertIn("northstar.policy.v1", error)
        (error,) = validate_schema_version(1)
        self.assertIn("must be a string", error)

    def test_require_supported_schema_names_the_context(self):
        with self.assertRaises(ValueError) as caught:
            require_supported_schema("northstar.policy.v9", context="northstar-policy.toml")
        self.assertIn("northstar-policy.toml", str(caught.exception))
        require_supported_schema(POLICY_SCHEMA_VERSION, context="x")  # no raise


class RevisionTests(unittest.TestCase):
    def test_plain_revision_ids_are_valid(self):
        for value in ("2026-09-07.r1", "policy-7", "release_2026", "v2.3", "CI#42"):
            with self.subTest(value=value):
                self.assertEqual(validate_revision(value), ())

    def test_absent_revision_is_valid(self):
        self.assertEqual(validate_revision(None), ())

    def test_bad_revisions_are_rejected(self):
        cases = {
            "": "non-empty",
            "with space": "whitespace",
            "with/slash": "whitespace, /",
            "with\\backslash": "whitespace, /",
            "x" * (MAX_REVISION_CHARS + 1): "too long",
            7: "must be a string",
        }
        for value, needle in cases.items():
            with self.subTest(value=value):
                (error,) = validate_revision(value)
                self.assertIn(needle, error)


if __name__ == "__main__":
    unittest.main()
