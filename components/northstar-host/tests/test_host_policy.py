"""Policy as code for the host: load northstar-policy.toml into HostPolicy."""
import sys
import tempfile
import unittest
from pathlib import Path

HOST_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = HOST_ROOT.parent / "northstar-run-contract"
sys.path.insert(0, str(HOST_ROOT))
sys.path.insert(0, str(CONTRACT_ROOT))

from authorization import HostPolicy  # noqa: E402

from host_policy import POLICY_FILE_NAME, load_host_policy  # noqa: E402

VALID = '''\
schema_version = "northstar.policy.v1"
revision = "2026-09-07.r1"

[actors]
"actor-001" = ["research", "search"]
"actor-002" = []
'''


class HostPolicyFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, text: str) -> Path:
        path = self.directory / POLICY_FILE_NAME
        path.write_text(text, encoding="utf-8")
        return path

    def test_a_valid_document_loads_into_a_host_policy(self):
        self.write(VALID)
        policy = load_host_policy(self.directory)
        self.assertIsInstance(policy, HostPolicy)
        self.assertEqual(policy.revision, "2026-09-07.r1")
        self.assertEqual(
            policy.actor_capabilities,
            {"actor-001": frozenset({"research", "search"}), "actor-002": frozenset()},
        )

    def test_schema_version_is_optional_and_defaults_to_v1(self):
        self.write('revision = "policy-1"\n')
        policy = load_host_policy(self.directory)
        self.assertEqual(policy.revision, "policy-1")
        self.assertEqual(policy.actor_capabilities, {})  # no actors = deny-all

    def test_an_unsupported_schema_version_fails_closed(self):
        self.write('schema_version = "northstar.policy.v2"\nrevision = "policy-1"\n')
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("unsupported policy schema_version", str(caught.exception))
        self.assertIn("northstar.policy.v2", str(caught.exception))

    def test_revision_is_required_and_validated(self):
        self.write("schema_version = \"northstar.policy.v1\"\n")
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("revision is required", str(caught.exception))
        self.write('revision = "two words"\n')
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("whitespace", str(caught.exception))

    def test_missing_file_is_a_fail_closed_error(self):
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("policy file not found", str(caught.exception))

    def test_unknown_keys_are_rejected(self):
        self.write('revision = "policy-1"\nloosen = true\n')
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("unknown key", str(caught.exception))
        self.assertIn("loosen", str(caught.exception))

    def test_actors_validation_delegates_to_host_policy_rules(self):
        # Wildcard actors are refused by HostPolicy.from_mapping.
        self.write('revision = "policy-1"\n[actors]\n"*" = ["research"]\n')
        with self.assertRaises(ValueError):
            load_host_policy(self.directory)
        # A capability list given as a plain string is refused.
        self.write('revision = "policy-1"\n[actors]\n"actor-1" = "research"\n')
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("must be an array", str(caught.exception))

    def test_bad_toml_is_an_error(self):
        self.write("revision = 'unterminated\n")
        with self.assertRaises(ValueError) as caught:
            load_host_policy(self.directory)
        self.assertIn("invalid TOML", str(caught.exception))

    def test_loading_equals_constructing_the_same_policy_directly(self):
        self.write(VALID)
        loaded = load_host_policy(self.directory)
        direct = HostPolicy.from_mapping(
            "2026-09-07.r1",
            {"actor-001": ["research", "search"], "actor-002": []},
        )
        self.assertEqual(loaded.revision, direct.revision)
        self.assertEqual(loaded.actor_capabilities, direct.actor_capabilities)


if __name__ == "__main__":
    unittest.main()
