import copy
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'native_tests'))
from test_semgrep_normalizer import base_stdout,finding,execution,isolation,template,wire
from semgrep_normalizer import normalize_semgrep
from trusted_common import EvidenceError


class ActualNativeShapeTests(unittest.TestCase):
    def setUp(self):
        self.inputs={'src/danger.py':b'eval(x)\nexec(y)\n'}
        self.context=template(self.inputs)
        self.map={'northstar.fixture.danger':'high'}

    def normalize(self,data,code=1):
        return normalize_semgrep(wire(data),template=self.context,execution=execution(code),isolation=isolation(),input_bytes=self.inputs,severity_map=self.map)

    def test_actual_native_additional_fields_are_narrowly_supported(self):
        data=base_stdout(['/input/src/danger.py'],[finding(fingerprint='requires login')])
        data.pop('engine_kind')
        data['engine_requested']='OSS'
        data['profiling_results']=[]
        result=self.normalize(data)
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['findings'][0]['severity'],'high')

    def test_same_login_placeholder_does_not_drop_two_distinct_hits(self):
        first=finding(fingerprint='requires login')
        second=copy.deepcopy(first)
        second['start']['line']=8
        second['end']['line']=8
        data=base_stdout(['/input/src/danger.py'],[first,second])
        result=self.normalize(data)
        self.assertEqual(len(result['findings']),2)
        self.assertNotEqual(result['findings'][0]['id'],result['findings'][1]['id'])

    def test_same_location_not_deduplicated_by_attacker_chosen_fingerprint(self):
        first=finding(fingerprint='requires login')
        second=copy.deepcopy(first)
        second['extra']['fingerprint']='attacker-changed'
        data=base_stdout(['/input/src/danger.py'],[first,second])
        with self.assertRaises(EvidenceError):self.normalize(data)

    def test_unknown_engine_or_extra_profiling_not_silently_accepted(self):
        data=base_stdout(['/input/src/danger.py'],[finding()])
        data['engine_requested']='PRO'
        with self.assertRaises(EvidenceError):self.normalize(data)
        data['engine_requested']='OSS'
        data['profiling_results']=[{'unapproved':'field'}]
        with self.assertRaises(EvidenceError):self.normalize(data)

    def test_native_default_zero_exit_with_finding_cannot_fake_a_success(self):
        data=base_stdout(['/input/src/danger.py'],[finding()])
        with self.assertRaises(EvidenceError):self.normalize(data,0)


if __name__=='__main__':unittest.main()
