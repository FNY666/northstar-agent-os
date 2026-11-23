import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from producer_fixtures import build_scenario
from native_contract import normalize_path, validate_template, validated_inputs, make_record
from scan_supervisor import load_profile, distribution_digest, input_manifest_sha256, _stream_digest
from trusted_common import EvidenceError, sha, wire


class NativeContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.s = build_scenario(self.root / 'scenario')
        self.template = self.s.plan_body['expectation_template']
        raw = b'safe = True\n'
        self.inputs = {'src/app.py': raw}
        self.template['tools']['semgrep']['expected_inputs'] = [{'path': 'src/app.py', 'sha256': sha(raw), 'ecosystems': [], 'min_packages': 0}]

    def tearDown(self):
        self.temp.cleanup()

    def test_input_bytes_are_verified_not_inferred_from_scanner(self):
        validated_inputs(self.template, 'semgrep', self.inputs)
        with self.assertRaises(EvidenceError):
            validated_inputs(self.template, 'semgrep', {'src/app.py': b'changed'})
        with self.assertRaises(EvidenceError):
            validated_inputs(self.template, 'semgrep', {**self.inputs, 'extra.py': b''})

    def test_plan_cannot_preselect_evidence_hash(self):
        self.template['tools']['semgrep']['evidence_sha256'] = 'a' * 64
        with self.assertRaises(EvidenceError): validate_template(self.template)

    def test_native_paths_are_explicitly_rooted_and_no_traversal(self):
        self.assertEqual(normalize_path('/input/src/app.py'), 'src/app.py')
        self.assertEqual(normalize_path('./src/app.py'), 'src/app.py')
        for name in ('/etc/passwd', '../x', 'a/../x', 'a//x', 'a\\x', '/input/../x'):
            with self.subTest(name=name), self.assertRaises(EvidenceError): normalize_path(name)

    def test_base_record_does_not_claim_complete(self):
        record = self.s.records['semgrep']
        built = make_record('semgrep', self.template, record['execution'], record['isolation'], self.inputs, b'{}', b'')
        self.assertEqual(built['coverage']['status'], 'incomplete')
        self.assertEqual(built['coverage']['unresolved_inputs'], ['src/app.py'])
        self.assertEqual(built['artifacts']['stdout']['sha256'], sha(b'{}'))

    def test_changed_view_bytes_change_signed_view_digest(self):
        self.assertNotEqual(input_manifest_sha256(self.inputs), input_manifest_sha256({'src/app.py': b'other'}))


class SupervisorPreflightTests(unittest.TestCase):
    def test_closed_profile_only(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'profile.json'
            profile = {'schema':'northstar.native-scan-profile.v1','semgrep_root':'/tools/semgrep','osv_root':'/tools/osv','policy_dir':'/policy','database_dir':'/db','database_updated_at':'2026-10-17T00:00:00Z','database_ecosystems':['PyPI'],'bwrap_path':'/tools/bwrap'}
            path.write_bytes(wire(profile))
            self.assertEqual(load_profile(path),profile)
            profile['arbitrary_command'] = '/bin/sh'
            path.write_bytes(wire(profile))
            with self.assertRaises(EvidenceError): load_profile(path)

    def test_measurement_detects_change_and_minimal_osv_distribution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'osv-scanner').write_bytes(b'fake reviewed executable')
            first = distribution_digest(root,'osv-scanner')
            (root / 'osv-scanner').write_bytes(b'changed')
            self.assertNotEqual(first,distribution_digest(root,'osv-scanner'))
            (root / 'extra').write_bytes(b'extra')
            with self.assertRaises(EvidenceError): distribution_digest(root,'osv-scanner')

    def test_native_mount_cannot_include_a_private_key_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'osv-scanner'
            path.write_bytes(b'-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n')
            with self.assertRaises(EvidenceError): _stream_digest(path)

    def test_tool_measurement_rejects_hardlink_and_unexpected_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'payload').write_bytes(b'toy')
            (root / 'osv-scanner').symlink_to('payload')
            with self.assertRaises(EvidenceError): distribution_digest(root,'osv-scanner')


if __name__ == '__main__': unittest.main()
